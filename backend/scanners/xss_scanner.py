import requests
import re
import urllib.parse
import html
import os
import time
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from utils.scan_storage import is_cancel_requested


class XSSScanner:
    """
    Python-based XSS Scanner using custom payloads
    """
    
    def __init__(self, payload_file: str = None):
        self.payloads = self._load_payloads(payload_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _load_payloads(self, payload_file: str = None) -> List[str]:
        """Load XSS payloads from file"""
        if payload_file is None:
            payload_file = os.path.join(os.path.dirname(__file__), 'xss-payload.txt')

        payload_file = payload_file.strip()
        
        payloads = []
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            # Default payloads if file not found
            payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "' onerror='alert(1)'",
                "\"><script>alert(1)</script>"
            ]
        return payloads
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        """Build URL with payload injected"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        params[param] = [payload]
        
        new_query = urllib.parse.urlencode(params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        return new_url

    def _detect_context(self, response_text: str, marker: str) -> str:
        """Best-effort context detector for a reflected marker.

        Returns one of: 'script', 'attr', 'text', 'unknown'.
        """
        try:
            idx = response_text.find(marker)
            if idx < 0:
                return "unknown"

            # Script context heuristic
            before = response_text[:idx].lower()
            last_script_open = before.rfind("<script")
            last_script_close = before.rfind("</script")
            if last_script_open != -1 and last_script_open > last_script_close:
                # Also ensure there's a closing tag after marker
                after = response_text[idx:].lower()
                if "</script" in after:
                    return "script"

            # Attribute context heuristic: marker appears inside the nearest tag chunk
            lt = response_text.rfind("<", 0, idx)
            gt = response_text.find(">", idx)
            if lt != -1 and gt != -1 and (gt - lt) < 8000:
                chunk = response_text[lt:gt]
                # very rough: inside quotes in a tag
                q1 = chunk.rfind('"', 0, idx - lt)
                q2 = chunk.find('"', idx - lt)
                if q1 != -1 and q2 != -1 and q1 < (idx - lt) < q2:
                    return "attr"
                s1 = chunk.rfind("'", 0, idx - lt)
                s2 = chunk.find("'", idx - lt)
                if s1 != -1 and s2 != -1 and s1 < (idx - lt) < s2:
                    return "attr"

            return "text"
        except Exception:
            return "unknown"

    def _probe_reflection_and_context(
        self,
        target_url: str,
        param: str,
        timeout: float,
    ) -> Tuple[Dict[str, str], int]:
        """Inject a unique marker to see whether/where the input is reflected.

        Returns: (probe_result, requests_made)
        """
        marker = f"SSXSS{uuid.uuid4().hex[:10]}"
        payload_url = self._build_payload_url(target_url, param, marker)
        try:
            response = self.session.get(
                payload_url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            if marker not in response.text:
                return ({"reflected": "false", "context": "unknown"}, 1)
            return ({"reflected": "true", "context": self._detect_context(response.text, marker)}, 1)
        except Exception:
            return ({"reflected": "false", "context": "unknown"}, 0)

    def _prioritize_payloads(self, payloads: List[str], context: str) -> List[str]:
        """Put high-signal, context-appropriate payloads first.

        This is designed to improve true-positive discovery under tight time budgets.
        """
        if not payloads:
            return payloads

        # Context-focused shortlist (keep small, diverse)
        focus: List[str] = []

        if context == "script":
            # Avoid JS string-breaker payloads here: they are prone to false positives
            # because they can appear as inert data (e.g., inside JSON strings).
            focus = [
                "</script><script>alert(1)</script>",
                "<script>alert(1)</script>",
            ]
        elif context == "attr":
            focus = [
                "\" onmouseover=alert(1) x=\"",
                "' onfocus=alert(1) autofocus '",
                "\"><svg/onload=alert(1)>",
            ]
        else:
            # text/unknown: try classic reflected-XSS payloads
            focus = [
                "<script>alert(1)</script>",
                "<svg/onload=alert(1)>",
                "\"><svg/onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
            ]

        # Preserve original order but ensure focus payloads go first.
        # IMPORTANT: Never introduce new payload strings here (especially when
        # callers pass custom payloads). Only reorder existing payloads.
        seen = set()
        out: List[str] = []

        focus_existing = [p for p in focus if p in payloads]

        for p in focus_existing:
            if p in seen:
                continue
            out.append(p)
            seen.add(p)
        for p in payloads:
            if p in seen:
                continue
            out.append(p)
            seen.add(p)
        return out
    
    def _reflection_state(self, response_text: str, payload: str) -> Dict[str, bool]:
        """Determine how (or if) the payload is reflected in the response.

        This is intentionally conservative to reduce false positives:
        - raw: payload appears without HTML escaping (more likely exploitable)
        - escaped: payload appears but is escaped/sanitized (not reported as vuln)
        """
        decoded_payload = urllib.parse.unquote(payload)

        raw_variations = [
            decoded_payload,
            payload,
        ]

        escaped_variations = [
            html.escape(decoded_payload),
            decoded_payload.replace('<', '&lt;').replace('>', '&gt;'),
            decoded_payload.replace('"', '&quot;'),
            decoded_payload.replace("'", '&#x27;'),
        ]

        raw = any(v and v in response_text for v in raw_variations)
        escaped = any(v and v in response_text for v in escaped_variations)
        return {"raw": bool(raw), "escaped": bool(escaped)}

    def _is_html_like_response(self, response) -> bool:
        """Best-effort filter to reduce false positives.

        Reflected input inside JSON/plain-text endpoints is usually NOT XSS.
        We only treat reflections as XSS candidates when the response is likely
        rendered/executed as HTML/XML.
        """
        try:
            ctype = (getattr(response, "headers", {}) or {}).get("Content-Type", "")
            ctype_l = str(ctype).lower()

            # Strong allow-list
            if "text/html" in ctype_l or "application/xhtml+xml" in ctype_l:
                return True
            if "xml" in ctype_l and "svg" in ctype_l:
                return True

            # Strong deny-list
            if "application/json" in ctype_l or "text/plain" in ctype_l:
                return False
            if "javascript" in ctype_l or "application/javascript" in ctype_l:
                return False

            # If Content-Type is missing/unknown, use light HTML heuristics.
            body = getattr(response, "text", "") or ""
            body_l = body[:4096].lower()
            if "<html" in body_l or "<!doctype" in body_l or "<body" in body_l:
                return True

            # Default to conservative: don't report.
            return False
        except Exception:
            return False
    
    def _check_xss_execution(self, response_text: str, payload: str) -> bool:
        """Check if XSS might have executed (script tags, event handlers present)"""
        # Check for various XSS indicators
        xss_indicators = [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=\s*["\']?[^"\']*alert',
            r'javascript\s*:\s*alert',
            r'<img[^>]+onerror[^>]*>',
            r'<svg[^>]+onload[^>]*>',
            r'<body[^>]+onload[^>]*>',
            r'<input[^>]+onfocus[^>]*>',
            r'<iframe[^>]+onload[^>]*>',
        ]
        
        for pattern in xss_indicators:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def _inject_marker_into_payload(self, payload: str, marker: str) -> str:
        """Create a per-scan unique payload to reduce false positives.

        We do NOT attempt to prove execution; we only need a unique string that is
        likely to be reflected verbatim when the target is vulnerable.
        """
        if not payload or not marker:
            return payload
        if marker in payload:
            return payload

        out = payload

        # Prefer to place the marker into alert()/confirm()/prompt() calls.
        # This keeps the payload shape similar but makes it unique.
        def _fn_call_repl(m: re.Match) -> str:
            return f"{m.group(1)}(\"{marker}\")"

        out = re.sub(
            r"\b(alert|confirm|prompt)\s*\(\s*1\s*\)",
            _fn_call_repl,
            out,
            flags=re.IGNORECASE,
        )
        out = re.sub(
            r"\b(alert|confirm|prompt)\s*\(\s*'XSS'\s*\)",
            _fn_call_repl,
            out,
            flags=re.IGNORECASE,
        )
        out = re.sub(
            r"\b(alert|confirm|prompt)\s*\(\s*\)",
            _fn_call_repl,
            out,
            flags=re.IGNORECASE,
        )

        # If still not unique, append a harmless JS comment inside a script tag.
        if marker not in out and "<script" in out.lower() and "</script" in out.lower():
            out = out.replace("</script>", f"/*{marker}*/</script>", 1)

        # If still not unique and it's HTML-ish, try to add a data- attribute.
        if marker not in out and out.lstrip().startswith("<") and ">" in out:
            m = re.match(r"^\s*<\s*([a-zA-Z0-9]+)([^>]*)>", out)
            if m:
                tag = m.group(1)
                rest = m.group(2) or ""
                injected_open = f"<{tag}{rest} data-ssxss=\"{marker}\">"
                out = re.sub(r"^\s*<\s*[a-zA-Z0-9]+[^>]*>", injected_open, out, count=1)

        # Final fallback: append marker as plain text (still unique).
        if marker not in out:
            out = f"{out}{marker}"

        return out
    
    def scan_url(
        self,
        target_url: str,
        parameters: List[str] = None,
        timeout: int = 10,
        custom_payloads: List[str] = None,
        max_duration: int = 15,
        max_payloads: int = 50,
        stop_on_first: bool = True,
        scan_id: Optional[int] = None,
    ) -> Dict:
        """Scan a URL for XSS vulnerabilities.

        This scanner is intentionally conservative to reduce false positives:
        it reports a finding only when the injected payload is reflected
        unescaped in the HTTP response.
        """
        # Auto-upgrade HTTP to HTTPS if target is on common HTTPS ports
        if target_url.startswith('http://'):
            parsed = urllib.parse.urlparse(target_url)
            # Check if it's likely an HTTPS service (common HTTPS ports)
            # Port 443, 8443, 4280 (custom), or if the domain suggests HTTPS
            if parsed.port in (443, 8443, 4280, 4443, 5001) or 'https' in target_url.lower():
                target_url = target_url.replace('http://', 'https://', 1)
        
        try:
            print(f"[*] Scanning URL: {target_url}")

            started = time.monotonic()
            scan_marker = f"SSXSS{uuid.uuid4().hex[:10]}"
            truncated = False
            requests_made = 0
            payload_attempts = 0
            params_tested_count = 0

            def time_remaining() -> float:
                if max_duration is None:
                    return float('inf')
                try:
                    md = float(max_duration)
                except Exception:
                    md = 15.0
                return md - (time.monotonic() - started)

            def budgeted_timeout() -> float:
                # Avoid letting any single request exceed the overall budget.
                try:
                    per_req = float(timeout)
                except Exception:
                    per_req = 10.0
                remaining = time_remaining()
                if remaining <= 0:
                    return 0.0
                # Keep at least 1s to allow fast failure/response.
                return min(per_req, max(1.0, remaining))

            def check_cancel() -> None:
                if scan_id is not None and is_cancel_requested(scan_id):
                    raise RuntimeError("Scan stopped by user")

            payloads_to_use = custom_payloads if custom_payloads else self.payloads

            max_payloads_int: Optional[int] = None
            if max_payloads is not None:
                try:
                    mp = int(max_payloads)
                except Exception:
                    mp = 50
                if mp > 0:
                    max_payloads_int = mp

            # Quick baseline fetch: if upstream is failing, scanning results would be misleading.
            try:
                check_cancel()
                base_timeout = budgeted_timeout()
                if base_timeout <= 0:
                    return {
                        "success": False,
                        "error": "Scan time budget exceeded before starting requests",
                        "target": target_url,
                    }
                requests_made += 1
                baseline_resp = self.session.get(
                    target_url,
                    timeout=base_timeout,
                    allow_redirects=True,
                    verify=False,
                )
                if baseline_resp.status_code in (502, 503, 504):
                    return {
                        "success": False,
                        "error": f"Upstream returned HTTP {baseline_resp.status_code} (gateway/service timeout). Target may be down or blocking automated requests.",
                        "target": target_url,
                        "http_status": baseline_resp.status_code,
                    }
            except requests.RequestException as e:
                return {
                    "success": False,
                    "error": f"Request failed before scanning: {e}",
                    "target": target_url,
                }

            url_params = self._extract_params(target_url)
            params_to_test = parameters if parameters else list(url_params.keys())

            vulnerabilities: List[Dict] = []
            if not params_to_test:
                params_tested_count = 1
                vulnerabilities, truncated, rm, pa = self._test_url(
                    target_url,
                    timeout,
                    payloads_to_use,
                    started,
                    max_duration,
                )
                requests_made += int(rm or 0)
                payload_attempts += int(pa or 0)
            else:
                for param in params_to_test:
                    if time_remaining() <= 0:
                        truncated = True
                        break
                    check_cancel()

                    params_tested_count += 1
                    print(f"[*] Testing parameter: {param}")

                    found_for_param = False

                    # Probe to improve payload choice under a time budget.
                    probe = {"reflected": "false", "context": "unknown"}
                    probe_timeout = budgeted_timeout()
                    if probe_timeout > 0:
                        probe, probe_rm = self._probe_reflection_and_context(target_url, param, probe_timeout)
                        requests_made += int(probe_rm or 0)

                    payloads_ordered = self._prioritize_payloads(payloads_to_use, probe.get("context", "unknown"))
                    if max_payloads_int is not None:
                        payloads_ordered = payloads_ordered[:max_payloads_int]

                    for payload in payloads_ordered:
                        if time_remaining() <= 0:
                            truncated = True
                            break
                        check_cancel()

                        # Only report high-confidence reflected XSS payloads to avoid false positives.
                        # (E.g., quote-breaker payloads can appear as inert JSON data.)
                        if '<' not in payload:
                            continue

                        unique_payload = self._inject_marker_into_payload(payload, scan_marker)
                        payload_url = self._build_payload_url(target_url, param, unique_payload)
                        req_timeout = budgeted_timeout()
                        if req_timeout <= 0:
                            truncated = True
                            break

                        requests_made += 1
                        payload_attempts += 1
                        try:
                            response = self.session.get(
                                payload_url,
                                timeout=req_timeout,
                                allow_redirects=True,
                                verify=False,
                            )
                        except requests.RequestException as e:
                            print(f"[!] Request failed: {e}")
                            continue

                        refl = self._reflection_state(response.text, unique_payload)
                        if refl.get("raw"):
                            if not self._is_html_like_response(response):
                                # Reflected in a non-HTML response (e.g., JSON) — avoid false positives.
                                continue
                            vuln = {
                                "type": "XSS",
                                "severity": self._get_severity(payload),
                                "parameter": param,
                                "payload": unique_payload,
                                "payload_template": payload,
                                "marker": scan_marker,
                                "evidence": f"Injected payload reflected (unescaped) in parameter '{param}'",
                                "poc": payload_url,
                                "cwe": "CWE-79",
                                "scan_type": "reflected_raw",
                                "confidence": "high",
                            }
                            vulnerabilities.append(vuln)
                            print(f"[V] Found vulnerability with payload: {payload[:50]}...")

                            found_for_param = True
                            if bool(stop_on_first):
                                break

                    if found_for_param and bool(stop_on_first):
                        # Keep results focused: one high-confidence PoC per parameter.
                        continue

            return {
                "success": True,
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "payload_attempts": payload_attempts,
                "requests_made": requests_made,
                "params_tested_count": params_tested_count,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "scan_time": "completed",
                "truncated": bool(truncated),
                "duration_seconds": round(time.monotonic() - started, 3),
                "payloads_tested": (max_payloads_int if max_payloads_int is not None else len(payloads_to_use)),
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target_url,
            }
    
    def scan_url_with_custom_payloads(
        self,
        target_url: str,
        parameters: List[str] = None,
        custom_payloads: List[str] = None,
        timeout: int = 10,
        max_duration: int = 15,
        max_payloads: int = 50,
        stop_on_first: bool = True,
        scan_id: Optional[int] = None,
    ) -> Dict:
        """
        Scan a URL with custom payloads

        Args:
            target_url (str): The target URL to scan
            parameters (list): Optional list of parameters to test
            custom_payloads (list): List of custom payloads to use
            timeout (int): Request timeout in seconds
            max_duration (int): Maximum scan duration in seconds
            max_payloads (int): Maximum number of payloads to test
            stop_on_first (bool): Stop after first finding per parameter
            scan_id (int): Optional scan ID for cancellation support

        Returns:
            dict: Scan results with vulnerabilities found
        """
        return self.scan_url(
            target_url,
            parameters=parameters,
            timeout=timeout,
            custom_payloads=custom_payloads,
            max_duration=max_duration,
            max_payloads=max_payloads,
            stop_on_first=stop_on_first,
            scan_id=scan_id,
        )
    
    def _test_url(
        self,
        url: str,
        timeout: int,
        payloads: List[str] = None,
        started: float = None,
        max_duration: int = 15,
    ) -> Tuple[List[Dict], bool, int, int]:
        """Test URL by injecting a payload into a synthetic query parameter."""
        vulnerabilities: List[Dict] = []
        truncated = False
        requests_made = 0
        payload_attempts = 0
        payloads_to_use = payloads if payloads else self.payloads

        if started is None:
            started = time.monotonic()

        def time_remaining() -> float:
            if max_duration is None:
                return float('inf')
            try:
                md = float(max_duration)
            except Exception:
                md = 15.0
            return md - (time.monotonic() - started)

        def budgeted_timeout() -> float:
            try:
                per_req = float(timeout)
            except Exception:
                per_req = 10.0
            remaining = time_remaining()
            if remaining <= 0:
                return 0.0
            return min(per_req, max(1.0, remaining))

        for payload in payloads_to_use:
            if time_remaining() <= 0:
                truncated = True
                break

            if '?' in url:
                test_url = f"{url}&xss_test={urllib.parse.quote(payload)}"
            else:
                test_url = f"{url}?xss_test={urllib.parse.quote(payload)}"

            req_timeout = budgeted_timeout()
            if req_timeout <= 0:
                truncated = True
                break

            requests_made += 1
            payload_attempts += 1
            try:
                response = self.session.get(test_url, timeout=req_timeout, verify=False)
            except requests.RequestException:
                continue

            refl = self._reflection_state(response.text, payload)
            if refl.get("raw"):
                vulnerabilities.append(
                    {
                        "type": "XSS",
                        "severity": self._get_severity(payload),
                        "parameter": "xss_test",
                        "payload": payload,
                        "evidence": "Injected payload reflected (unescaped) in parameter 'xss_test'",
                        "poc": test_url,
                        "cwe": "CWE-79",
                        "scan_type": "reflected_raw",
                    }
                )
                break

        return vulnerabilities, truncated, requests_made, payload_attempts
    
    def _get_severity(self, payload: str) -> str:
        """Determine severity based on payload type"""
        payload_lower = payload.lower()
        
        if 'alert' in payload_lower and ('script' in payload_lower or 'onerror' in payload_lower):
            return "High"
        elif 'alert' in payload_lower:
            return "Medium"
        else:
            return "Low"
    
    def scan_multiple_urls(self, urls: List[str], timeout_per_url: int = 30) -> Dict:
        """
        Scan multiple URLs for XSS vulnerabilities
        
        Args:
            urls (list): List of URLs to scan
            timeout_per_url (int): Timeout per URL in seconds
            
        Returns:
            dict: Combined results from all scans
        """
        results = {
            "total_scanned": len(urls),
            "timestamp": datetime.now().isoformat(),
            "scans": []
        }
        
        for url in urls:
            scan_result = self.scan_url(url, timeout=timeout_per_url)
            results["scans"].append(scan_result)
        
        # Calculate statistics
        total_vulns = sum(scan.get("total_found", 0) for scan in results["scans"])
        results["total_vulnerabilities"] = total_vulns
        successful_scans = [scan for scan in results["scans"] if scan.get("success", False)]
        results["success_rate"] = (len(successful_scans) / len(urls)) * 100 if urls else 0
        
        return results


# Quick test function
if __name__ == "__main__":
    scanner = XSSScanner()
    
    # Test URL
    test_url = "http://testphp.vulnweb.com/search.php?test=query"
    
    print("Testing XSS Scanner...")
    result = scanner.scan_url(test_url)
    import json
    print(json.dumps(result, indent=2))
