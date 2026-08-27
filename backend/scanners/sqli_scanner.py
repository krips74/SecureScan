"""
SQL Injection Scanner — error-based, boolean-blind, time-blind, UNION-based.
Includes a SAFE MODE toggle that restricts to error + boolean only.
"""
import requests
import re
import time
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional
import logging
import os
import difflib
from utils.scan_storage import is_cancel_requested

logger = logging.getLogger(__name__)

# Database error signatures for error-based detection
DB_ERROR_SIGNATURES = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"unclosed quotation mark",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"MySqlException",
        r"SQL syntax.*?MySQL",
        r"MySqlClient\.",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"unterminated quoted string",
    ],
    "MSSQL": [
        # Keep only high-signal MSSQL error message fragments to avoid matching
        # normal page content that happens to mention "SQL Server".
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
        r"System\.Data\.SqlClient\.SqlException",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SQLSTATE\[\w+\]",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    "SQLite": [
        r"SQLite\/JDBCDriver",
        r"SQLite\.Exception",
        r"SQLITE_ERROR",
        r"unrecognized token",
        r"System\.Data\.SQLite\.SQLiteException",
        r"near \".*?\": syntax error",
    ],
}


class SQLiScanner:
    """SQL Injection scanner with safe mode support."""

    def __init__(self, payload_file: str = None, safe_mode: bool = True):
        self.safe_mode = safe_mode
        self.payloads = self._load_payloads(payload_file)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SecureScan/1.0"
        })

    def _load_payloads(self, payload_file: str = None) -> Dict[str, List[str]]:
        """Load payloads organized by technique."""
        if payload_file is None:
            payload_file = os.path.join(os.path.dirname(__file__), "sqli-payload.txt")

        payloads = {"safe": [], "time_based": [], "union_based": []}
        current_section = "safe"

        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("# TIMEBASED"):
                        current_section = "time_based"
                        continue
                    if line.startswith("# UNION"):
                        current_section = "union_based"
                        continue
                    if line.startswith("#"):
                        continue
                    payloads[current_section].append(line)
        except FileNotFoundError:
            payloads["safe"] = ["'", '"', "' OR '1'='1", "' AND 1=1--", "' AND 1=2--"]

        return payloads

    def _get_active_payloads(self, safe_mode: bool = None) -> List[str]:
        """Return payloads based on safe mode setting."""
        is_safe = safe_mode if safe_mode is not None else self.safe_mode
        active = list(self.payloads["safe"])
        if not is_safe:
            active.extend(self.payloads["time_based"])
            active.extend(self.payloads["union_based"])
        return active

    def _extract_params(self, url: str) -> Dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return {k: v[0] if v else "" for k, v in params.items()}

    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]  # Always set, adds if missing or replaces
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    def _check_error_based(self, response_text: str) -> Optional[Dict]:
        """Check for database error strings in response."""
        text_lower = response_text.lower()
        for db_type, patterns in DB_ERROR_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return {"db_type": db_type, "pattern": pattern}
        return None

    def _normalize_for_diff(self, text: str, max_len: int = 200_000) -> str:
        """Normalize HTML/text to reduce dynamic noise before diffing.

        This is intentionally lossy: we prefer avoiding false positives over
        detecting every edge case.
        """
        if not text:
            return ""

        # Drop script/style blocks which are often highly dynamic.
        text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", text)
        text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)

        # Normalize obvious entropy sources.
        text = re.sub(r"[A-Fa-f0-9]{16,}", "x", text)
        text = re.sub(r"\d+", "0", text)
        text = re.sub(r"\s+", " ", text)

        text = text.strip().lower()
        if len(text) > max_len:
            # Keep head+tail to retain some context.
            half = max_len // 2
            text = text[:half] + text[-half:]
        return text

    def _similarity(self, a: str, b: str) -> float:
        if a == b:
            return 1.0
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _looks_blocked(self, resp: Optional[requests.Response]) -> bool:
        if resp is None:
            return True
        if resp.status_code in (401, 403, 406, 409, 423, 429, 503):
            return True
        ct = (resp.headers.get("Content-Type") or "").lower()
        # Some WAFs return HTML challenge pages for non-HTML endpoints.
        if "text/html" in ct:
            body = (resp.text or "").lower()
            challenge_markers = (
                "captcha",
                "unusual traffic",
                "verify you are a human",
                "cloudflare",
                "access denied",
                "request blocked",
                "waf",
            )
            if any(m in body for m in challenge_markers):
                return True
        return False

    def _check_error_based_differential(self, baseline_text: str, injected_text: str) -> Optional[Dict]:
        """Error-based detection that requires the signature to be absent in baseline."""
        if not injected_text:
            return None
        baseline_lower = (baseline_text or "").lower()
        injected_lower = injected_text.lower()

        for db_type, patterns in DB_ERROR_SIGNATURES.items():
            for pattern in patterns:
                # If baseline already matches this pattern, treat it as noise.
                if baseline_lower and re.search(pattern, baseline_lower, re.IGNORECASE):
                    continue
                m = re.search(pattern, injected_lower, re.IGNORECASE)
                if m:
                    snippet_start = max(0, m.start() - 60)
                    snippet_end = min(len(injected_lower), m.end() + 60)
                    snippet = injected_lower[snippet_start:snippet_end]
                    return {"db_type": db_type, "pattern": pattern, "snippet": snippet}
        return None

    def _detect_boolean_differential(
        self,
        baseline_resp: requests.Response,
        true_resp: requests.Response,
        false_resp: requests.Response,
    ) -> Optional[Dict]:
        """Conservative boolean-blind detector.

        We only report if baseline is clearly closer to one branch than the other.
        This is designed to avoid false positives on highly dynamic pages.
        """
        if self._looks_blocked(baseline_resp) or self._looks_blocked(true_resp) or self._looks_blocked(false_resp):
            return None

        base_norm = self._normalize_for_diff(baseline_resp.text)
        true_norm = self._normalize_for_diff(true_resp.text)
        false_norm = self._normalize_for_diff(false_resp.text)

        sim_bt = self._similarity(base_norm, true_norm)
        sim_bf = self._similarity(base_norm, false_norm)
        sim_tf = self._similarity(true_norm, false_norm)

        # Require baseline to strongly resemble at least one branch.
        if max(sim_bt, sim_bf) < 0.85:
            return None

        # Require a meaningful separation between branches.
        if abs(sim_bt - sim_bf) < 0.04:
            return None

        # Branches should not be near-identical.
        if sim_tf > 0.97:
            return None

        len_t = len(true_resp.text or "")
        len_f = len(false_resp.text or "")
        len_delta = abs(len_t - len_f)
        if len_delta < 80 and (len_delta / max(len_t, len_f, 1)) < 0.03:
            return None

        baseline_matches = "true" if sim_bt > sim_bf else "false"
        return {
            "baseline_matches": baseline_matches,
            "sim_baseline_true": round(sim_bt, 4),
            "sim_baseline_false": round(sim_bf, 4),
            "sim_true_false": round(sim_tf, 4),
            "len_true": len_t,
            "len_false": len_f,
        }

    def _check_time_based(self, response_time: float, baseline_time: float = None, threshold: float = 4.0) -> bool:
        """Check if response time indicates time-based injection.
        
        If baseline_time is provided, uses the difference from baseline; otherwise uses absolute threshold.
        """
        if baseline_time is None:
            return response_time >= threshold
        return (response_time - baseline_time) >= threshold

    def _build_baseline_true_false_candidates(self, orig_val: str) -> List[Dict[str, str]]:
        """Return boolean-blind candidates.

        We probe both string-style and numeric-style comparisons because many labs
        (including common "blind SQLi" pages) expect numeric IDs even if the current
        URL value isn't numeric.
        """
        ov = (orig_val or "").strip()
        is_numeric = bool(re.fullmatch(r"\d+", ov))

        candidates: List[Dict[str, str]] = []

        # String-style (append quote + boolean condition)
        # Keep original value to preserve application behavior when it is a string field.
        candidates.append(
            {
                "technique": "string",
                "baseline_val": ov or "admin",
                "true_val": f"{(ov or 'admin')}' AND '1'='1'-- ",
                "false_val": f"{(ov or 'admin')}' AND '1'='2'-- ",
            }
        )

        # Numeric-style (replace value entirely)
        base_num = ov if is_numeric else "1"
        candidates.append(
            {
                "technique": "numeric",
                "baseline_val": base_num,
                "true_val": f"{base_num} AND 1=1",
                "false_val": f"{base_num} AND 1=2",
            }
        )

        return candidates

    def _get_severity(self, technique: str) -> str:
        if technique in ("error_based", "union_based"):
            return "High"
        elif technique == "time_based":
            return "High"
        elif technique == "boolean_blind":
            return "Medium"
        return "Medium"

    def scan_url(self, target_url: str, parameters: List[str] = None,
                 timeout: int = 10, safe_mode: bool = None,
                 custom_payloads: List[str] = None,
                 stop_on_first: bool = False,
                 method: str = "GET", body_template: str = None,
                 auth_session=None, scan_id: Optional[int] = None) -> Dict:
        """
        Scan a URL for SQL injection vulnerabilities.
        """
        # Auto-upgrade HTTP to HTTPS if target is on common HTTPS ports
        if target_url.startswith('http://'):
            parsed = urllib.parse.urlparse(target_url)
            if parsed.port in (443, 8443, 4280, 4443, 5001):
                target_url = target_url.replace('http://', 'https://', 1)
        
        try:
            logger.info(f"[SQLi] Scanning: {target_url}")
            session = auth_session.session if auth_session else self.session
            is_safe = safe_mode if safe_mode is not None else self.safe_mode

            vulnerabilities = []
            url_params = self._extract_params(target_url)
            params_to_test = parameters if parameters else list(url_params.keys())

            # Activity counters for transparency
            requests_made = 0
            payload_attempts = 0
            params_tested_count = 0

            def check_cancel() -> None:
                if scan_id is not None and is_cancel_requested(scan_id):
                    raise RuntimeError("Scan stopped by user")

            payloads_to_use = custom_payloads if custom_payloads else self._get_active_payloads(is_safe)
            active_payloads_count = len(payloads_to_use)
            using_custom_payloads = bool(custom_payloads)

            if not params_to_test and method == "GET":
                # Try adding a test parameter
                params_to_test = ["id"]
                if "?" not in target_url:
                    target_url += "?id=1"

            # Get baseline response
            baseline_time = None
            try:
                baseline_start = time.time()
                baseline = session.get(target_url, timeout=timeout, verify=False) if method == "GET" else session.post(target_url, timeout=timeout, verify=False)
                baseline_time = time.time() - baseline_start
                requests_made += 1
                baseline_text = baseline.text
                baseline_length = len(baseline_text)
            except Exception:
                baseline_text = ""
                baseline_length = 0
                baseline = None
                baseline_time = None

            for param in params_to_test:
                logger.info(f"[SQLi] Testing parameter: {param}")
                check_cancel()

                # Stop on first finding per parameter (continue scanning other params).
                found_for_param = False

                params_tested_count += 1

                # Conservative boolean differential check first.
                # We probe both string-style and numeric-style boolean pairs.
                try:
                    orig_val = url_params.get(param, "1")
                    bool_candidates = self._build_baseline_true_false_candidates(orig_val)

                    for cand in bool_candidates:
                        check_cancel()
                        baseline_val = cand["baseline_val"]
                        true_val = cand["true_val"]
                        false_val = cand["false_val"]

                        # Build baseline/true/false requests for this candidate.
                        if method == "GET":
                            baseline_url = self._build_payload_url(target_url, param, baseline_val)
                            true_url = self._build_payload_url(target_url, param, true_val)
                            false_url = self._build_payload_url(target_url, param, false_val)

                            # Reuse the already-fetched baseline response if it matches the original URL.
                            baseline_resp = baseline if (baseline is not None and baseline_url == target_url) else session.get(
                                baseline_url,
                                timeout=timeout,
                                verify=False,
                            )
                            if baseline_resp is not baseline:
                                requests_made += 1

                            true_resp = session.get(true_url, timeout=timeout, verify=False)
                            requests_made += 1
                            payload_attempts += 1

                            false_resp = session.get(false_url, timeout=timeout, verify=False)
                            requests_made += 1
                            payload_attempts += 1

                            poc_true = true_url
                            poc_false = false_url
                        else:
                            if body_template:
                                baseline_body = body_template.replace("{{INJECT}}", baseline_val)
                                true_body = body_template.replace("{{INJECT}}", true_val)
                                false_body = body_template.replace("{{INJECT}}", false_val)

                                baseline_resp = session.post(
                                    target_url,
                                    data=baseline_body,
                                    timeout=timeout,
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    verify=False,
                                )
                                requests_made += 1

                                true_resp = session.post(
                                    target_url,
                                    data=true_body,
                                    timeout=timeout,
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    verify=False,
                                )
                                requests_made += 1
                                payload_attempts += 1

                                false_resp = session.post(
                                    target_url,
                                    data=false_body,
                                    timeout=timeout,
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    verify=False,
                                )
                                requests_made += 1
                                payload_attempts += 1
                            else:
                                baseline_resp = session.post(target_url, data={param: baseline_val}, timeout=timeout, verify=False)
                                requests_made += 1

                                true_resp = session.post(target_url, data={param: true_val}, timeout=timeout, verify=False)
                                requests_made += 1
                                payload_attempts += 1

                                false_resp = session.post(target_url, data={param: false_val}, timeout=timeout, verify=False)
                                requests_made += 1
                                payload_attempts += 1

                            poc_true = f"POST {target_url} → {param}={true_val}"
                            poc_false = f"POST {target_url} → {param}={false_val}"

                        bool_evidence = self._detect_boolean_differential(baseline_resp, true_resp, false_resp)
                        if bool_evidence:
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "severity": self._get_severity("boolean_blind"),
                                "parameter": param,
                                "payload": true_val,
                                "evidence": (
                                    f"Boolean differential ({cand['technique']}): "
                                    f"baseline~true={bool_evidence['sim_baseline_true']} "
                                    f"baseline~false={bool_evidence['sim_baseline_false']} "
                                    f"true~false={bool_evidence['sim_true_false']} "
                                    f"len(true)={bool_evidence['len_true']} len(false)={bool_evidence['len_false']}"
                                ),
                                "poc": poc_true,
                                "poc_false": poc_false,
                                "cwe": "CWE-89",
                                "scan_type": "boolean_blind",
                            })
                            found_for_param = True
                            break
                except Exception:
                    # Boolean checks are best-effort; do not fail the scan.
                    pass

                if found_for_param:
                    if bool(stop_on_first):
                        continue
                    found_for_param = False

                for payload in payloads_to_use:
                    check_cancel()
                    try:
                        # Determine if this is a time-based payload
                        is_time_payload = any(kw in payload.upper() for kw in ["SLEEP", "WAITFOR", "PG_SLEEP", "BENCHMARK"])
                        is_union_payload = "UNION" in payload.upper()

                        # Skip unsafe payloads in safe mode
                        if is_safe and (is_time_payload or is_union_payload):
                            continue

                        if method == "GET":
                            payload_url = self._build_payload_url(target_url, param, payload)
                            start_time = time.time()
                            response = session.get(payload_url, timeout=timeout + (6 if is_time_payload else 0), verify=False)
                            elapsed = time.time() - start_time
                            requests_made += 1
                            payload_attempts += 1
                        else:
                            # POST injection
                            if body_template:
                                body = body_template.replace("{{INJECT}}", payload)
                            else:
                                body = {param: payload}
                            start_time = time.time()
                            if isinstance(body, str):
                                response = session.post(target_url, data=body, timeout=timeout + (6 if is_time_payload else 0),
                                                        headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False)
                            else:
                                response = session.post(target_url, data=body, timeout=timeout + (6 if is_time_payload else 0), verify=False)
                            elapsed = time.time() - start_time
                            payload_url = target_url
                            requests_made += 1
                            payload_attempts += 1

                        # ── Detection Checks ─────────────────────────

                        # 1. Error-based
                        error_match = self._check_error_based_differential(baseline_text, response.text)
                        if error_match:
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "severity": "High",
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"{error_match['db_type']} error detected (pattern baseline-diff)",
                                "poc": payload_url if method == "GET" else f"POST {target_url} → {param}={payload}",
                                "cwe": "CWE-89",
                                "scan_type": "error_based",
                                "db_type": error_match["db_type"],
                                "match": error_match.get("snippet"),
                            })
                            if bool(stop_on_first):
                                found_for_param = True
                                break
                            continue

                        # 2. Time-based blind
                        if is_time_payload and self._check_time_based(elapsed, baseline_time):
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "severity": "High",
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Response delayed by {elapsed:.1f}s (expected ≥4s)",
                                "poc": payload_url if method == "GET" else f"POST {target_url} → {param}={payload}",
                                "cwe": "CWE-89",
                                "scan_type": "time_based",
                            })
                            if bool(stop_on_first):
                                found_for_param = True
                                break
                            continue

                        # 3. Boolean-based blind is handled by the stricter
                        # baseline/true/false differential check above.

                    except requests.Timeout:
                        # Timeout on time-based can itself be evidence
                        if is_time_payload:
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "severity": "High",
                                "parameter": param,
                                "payload": payload,
                                "evidence": "Request timed out (likely time-based injection)",
                                "poc": payload_url if method == "GET" else f"POST {target_url} → {param}={payload}",
                                "cwe": "CWE-89",
                                "scan_type": "time_based",
                            })
                            if bool(stop_on_first):
                                found_for_param = True
                                break
                    except requests.RequestException as e:
                        logger.debug(f"[SQLi] Request failed: {e}")
                        continue

                    if found_for_param:
                        break

            return {
                "success": True,
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "safe_mode": is_safe,
                "stop_on_first": bool(stop_on_first),
                "active_payloads_count": int(active_payloads_count),
                "using_custom_payloads": bool(using_custom_payloads),
                "scan_time": "completed",
                "requests_made": requests_made,
                "payload_attempts": payload_attempts,
                "params_tested_count": params_tested_count,
            }

        except Exception as e:
            logger.error(f"[SQLi] Error scanning {target_url}: {e}")
            return {"success": False, "error": str(e), "target": target_url}

    def scan_batch(self, urls: List[str], **kwargs) -> Dict:
        results = {
            "total_scanned": len(urls),
            "timestamp": datetime.now().isoformat(),
            "scans": [],
        }
        for url in urls:
            results["scans"].append(self.scan_url(url, **kwargs))
        total = sum(s.get("total_found", 0) for s in results["scans"])
        results["total_vulnerabilities"] = total
        return results
