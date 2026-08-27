"""
Open Redirect Scanner — detects unvalidated redirect/forward vulnerabilities.
"""
import requests
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
import logging
import os
import re
from utils.scan_storage import is_cancel_requested

logger = logging.getLogger(__name__)

# Common parameter names that often control redirects.
# These are only *hints*; they must never be used alone to classify a vulnerability.
REDIRECT_PARAMS = [
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnto",
    "return_to",
    "next",
    "next_url",
    "continue",
]


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECT_HOPS = 10


def _norm_host(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("www."):
        h = h[4:]
    return h


def _looks_like_example_domain(host: str) -> bool:
    h = _norm_host(host)
    if not h:
        return False
    # RFC 2606 / common placeholders
    if h in {"example.com", "example.org", "example.net", "test.com", "localhost"}:
        return True
    if h.endswith(".example"):
        return True
    return False


def _decode_multi(value: str, rounds: int = 2) -> str:
    out = value or ""
    for _ in range(max(0, int(rounds))):
        new = urllib.parse.unquote(out)
        if new == out:
            break
        out = new
    return out


def _normalize_location(current_url: str, location_header: str) -> Optional[str]:
    if not location_header:
        return None
    loc = str(location_header).strip()
    if not loc:
        return None
    # Normalize encoded schemes / slashes before joining.
    loc_decoded = _decode_multi(loc, rounds=2)
    # urljoin handles relative and protocol-relative URLs.
    try:
        absolute = urllib.parse.urljoin(current_url, loc_decoded)
        return absolute
    except Exception:
        return loc_decoded


class OpenRedirectScanner:
    """Detects open redirect vulnerabilities by injecting redirect payloads."""

    def __init__(self, payload_file: str = None):
        self.payloads = self._load_payloads(payload_file)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SecureScan/1.0"
        })
        # Use a reserved TLD for probes; we only need to detect the Location header.
        self._probe_host = "attacker.invalid"

    def _load_payloads(self, payload_file: str = None) -> List[str]:
        if payload_file is None:
            payload_file = os.path.join(os.path.dirname(__file__), "redirect-payload.txt")
        payloads = []
        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
        except FileNotFoundError:
            payloads = []

        # Always include a small, deterministic probe set that does not rely
        # on real domains.
        payloads.extend(
            [
                "https://attacker.invalid/",
                "//attacker.invalid/",
                "https%3A%2F%2Fattacker.invalid%2F",
            ]
        )

        # Deduplicate while preserving order
        seen = set()
        out = []
        for p in payloads:
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
        return out
        return payloads

    def _extract_params(self, url: str) -> Dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return {k: v[0] if v else "" for k, v in params.items()}

    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    def _request_once(self, url: str, timeout: int, session: requests.Session) -> Tuple[int, Optional[str]]:
        """Send a real HTTP request and return (status_code, Location_header)."""
        resp = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
        status = int(getattr(resp, "status_code", 0) or 0)
        location = None
        try:
            location = resp.headers.get("Location")
        except Exception:
            location = None
        return status, location

    def _follow_redirect_chain(self, start_url: str, timeout: int, session: requests.Session) -> Dict[str, Any]:
        """Follow redirects until final destination or external hop.

        Records each hop. Stops when:
        - status is not a redirect
        - redirect has no Location
        - hop count exceeds limit
        - redirect leaves the original host (external) — we do not fetch external targets
        """
        chain: List[Dict[str, Any]] = []
        current = start_url
        origin_host = _norm_host(urllib.parse.urlparse(start_url).netloc)

        for _ in range(_MAX_REDIRECT_HOPS):
            try:
                status, location_hdr = self._request_once(current, timeout=timeout, session=session)
            except Exception as e:
                chain.append({"url": current, "status_code": None, "location": None, "error": str(e)})
                return {
                    "status_code": None,
                    "location_header": None,
                    "final_url": current,
                    "redirect_chain": chain,
                }

            next_url = _normalize_location(current, location_hdr) if (status in _REDIRECT_STATUSES) else None
            chain.append({"url": current, "status_code": status, "location": location_hdr, "resolved_location": next_url})

            if status not in _REDIRECT_STATUSES or not next_url:
                return {
                    "status_code": status,
                    "location_header": location_hdr,
                    "final_url": current,
                    "redirect_chain": chain,
                }

            next_host = _norm_host(urllib.parse.urlparse(next_url).netloc)
            if next_host and origin_host and next_host != origin_host:
                # External hop becomes the "final" for our analysis.
                return {
                    "status_code": status,
                    "location_header": location_hdr,
                    "final_url": next_url,
                    "redirect_chain": chain,
                }

            current = next_url

        return {
            "status_code": chain[-1].get("status_code") if chain else None,
            "location_header": chain[-1].get("location") if chain else None,
            "final_url": current,
            "redirect_chain": chain,
        }

    def _is_external_to_origin(self, origin_url: str, final_url: str) -> bool:
        try:
            origin_host = _norm_host(urllib.parse.urlparse(origin_url).netloc)
            final_host = _norm_host(urllib.parse.urlparse(final_url).netloc)
        except Exception:
            return False
        return bool(final_host and origin_host and final_host != origin_host)

    def _is_user_controlled_external(self, location_url: str, injected_payload: str) -> bool:
        """Confirm that the external redirect destination is controlled by injected user input."""
        if not location_url or not injected_payload:
            return False

        loc = _decode_multi(location_url, rounds=2)
        inj = _decode_multi(injected_payload, rounds=2)

        try:
            loc_parsed = urllib.parse.urlparse(loc)
            inj_parsed = urllib.parse.urlparse(inj)
        except Exception:
            return False

        loc_host = _norm_host(loc_parsed.netloc)
        inj_host = _norm_host(inj_parsed.netloc)

        if not loc_host or not inj_host:
            # protocol-relative payloads may parse with empty scheme but have netloc
            if inj.startswith("//"):
                try:
                    inj_host = _norm_host(urllib.parse.urlparse("https:" + inj).netloc)
                except Exception:
                    inj_host = ""
            if not loc_host or not inj_host:
                return False

        if loc_host != inj_host:
            return False

        # Avoid false positives on placeholder domains.
        if _looks_like_example_domain(loc_host):
            return False

        return True

    def scan_url(self, target_url: str, parameters: List[str] = None,
                 timeout: int = 10, auth_session=None, scan_id: Optional[int] = None) -> Dict:
        # Auto-upgrade HTTP to HTTPS if target is on common HTTPS ports
        if target_url.startswith('http://'):
            parsed = urllib.parse.urlparse(target_url)
            if parsed.port in (443, 8443, 4280, 4443, 5001):
                target_url = target_url.replace('http://', 'https://', 1)
        
        try:
            logger.info(f"[Redirect] Scanning: {target_url}")
            session = auth_session.session if auth_session else self.session
            vulnerabilities: List[Dict[str, Any]] = []

            origin_host = _norm_host(urllib.parse.urlparse(target_url).netloc)

            url_params = self._extract_params(target_url)
            params_to_test = parameters if parameters else list(url_params.keys())

            # Also try common redirect parameter names (hints only)
            if not params_to_test:
                params_to_test = REDIRECT_PARAMS[:5]

            # Build a small set of payload probes.
            # Use `.invalid` so we can confirm the Location header without relying on DNS.
            probe_payloads = [
                f"https://{self._probe_host}/",
                f"//{self._probe_host}/",
                f"https%3A%2F%2F{self._probe_host}%2F",
            ]

            best: Optional[Dict[str, Any]] = None
            best_sev_rank = -1

            def _severity_rank(sev: str) -> int:
                return {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get((sev or "").upper(), 0)

            def _record_result(res_obj: Dict[str, Any]):
                nonlocal best, best_sev_rank
                r = _severity_rank(res_obj.get("severity"))
                if r > best_sev_rank:
                    best = res_obj
                    best_sev_rank = r

            def check_cancel() -> None:
                if scan_id is not None and is_cancel_requested(scan_id):
                    raise RuntimeError("Scan stopped by user")

            # Baseline request (for context only)
            baseline = self._follow_redirect_chain(target_url, timeout=timeout, session=session)

            for param in params_to_test:
                check_cancel()
                # If the URL did not include a query string, build one.
                if "?" not in target_url:
                    test_base = target_url + "?" + urllib.parse.urlencode({param: "/"})
                else:
                    test_base = target_url

                for payload in probe_payloads:
                    payload_url = self._build_payload_url(test_base, param, payload)
                    evidence = self._follow_redirect_chain(payload_url, timeout=timeout, session=session)

                    status_code = evidence.get("status_code")
                    location_header = evidence.get("location_header")
                    final_url = evidence.get("final_url")
                    chain = evidence.get("redirect_chain") or []

                    # Only analyze real HTTP redirects.
                    if status_code not in _REDIRECT_STATUSES or not location_header:
                        continue

                    final_host = _norm_host(urllib.parse.urlparse(final_url or "").netloc)

                    # Prevent false positives: placeholder/example domains.
                    if final_host and _looks_like_example_domain(final_host):
                        continue

                    is_external = self._is_external_to_origin(target_url, final_url or "")
                    if not is_external:
                        # Internal redirect only.
                        _record_result(
                            {
                                "vulnerability": "Open Redirect",
                                "severity": "LOW",
                                "is_vulnerable": False,
                                "exploitability": "NONE",
                                "evidence": {
                                    "status_code": status_code,
                                    "location_header": location_header,
                                    "final_url": final_url,
                                    "redirect_chain": chain,
                                },
                                "recommendation": "No action required for internal redirects. Ensure redirect targets remain restricted to trusted paths/origins.",
                                "tested_parameter": param,
                                "tested_payload": payload,
                            }
                        )
                        continue

                    controlled = self._is_user_controlled_external(str(final_url or ""), payload)
                    if controlled:
                        result_obj = {
                            "vulnerability": "Open Redirect",
                            "severity": "HIGH",
                            "is_vulnerable": True,
                            "exploitability": "CONFIRMED",
                            "evidence": {
                                "status_code": status_code,
                                "location_header": location_header,
                                "final_url": final_url,
                                "redirect_chain": chain,
                            },
                            "recommendation": "Validate redirect targets using an allowlist of trusted domains/paths. Do not allow arbitrary external URLs from user-controlled parameters.",
                            "tested_parameter": param,
                            "tested_payload": payload,
                        }
                        _record_result(result_obj)
                        # Confirmed vulnerability; stop early to reduce noise.
                        break
                    else:
                        # External redirect occurred but does not appear controlled by the injected input.
                        # This is not a confirmed open redirect; keep for manual review only.
                        _record_result(
                            {
                                "vulnerability": "Open Redirect",
                                "severity": "MEDIUM",
                                "is_vulnerable": False,
                                "exploitability": "POSSIBLE",
                                "evidence": {
                                    "status_code": status_code,
                                    "location_header": location_header,
                                    "final_url": final_url,
                                    "redirect_chain": chain,
                                },
                                "recommendation": "Review redirect logic to ensure the destination is validated/allowlisted and not derived from untrusted input.",
                                "tested_parameter": param,
                                "tested_payload": payload,
                            }
                        )

                # If confirmed high found, stop scanning other params.
                if best and best.get("severity") == "HIGH" and best.get("is_vulnerable") is True:
                    break

            if best is None:
                best = {
                    "vulnerability": "Open Redirect",
                    "severity": "INFO",
                    "is_vulnerable": False,
                    "exploitability": "NONE",
                    "evidence": {
                        "status_code": baseline.get("status_code"),
                        "location_header": baseline.get("location_header"),
                        "final_url": baseline.get("final_url"),
                        "redirect_chain": baseline.get("redirect_chain") or [],
                    },
                    "recommendation": "No redirect behavior detected that indicates an open redirect.",
                }

            # Backward-compatible vulnerabilities list (only add on confirmed or manual-review findings)
            if best.get("exploitability") in ("CONFIRMED", "POSSIBLE"):
                sev_title = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}.get(best.get("severity"), "Medium")
                vulnerabilities.append(
                    {
                        "type": "Open Redirect",
                        "severity": sev_title,
                        "parameter": best.get("tested_parameter"),
                        "payload": best.get("tested_payload", ""),
                        "evidence": f"HTTP {best['evidence'].get('status_code')} Location: {best['evidence'].get('location_header')} Final: {best['evidence'].get('final_url')}",
                        "poc": best.get("evidence", {}).get("redirect_chain", [{}])[0].get("url") if best.get("evidence") else None,
                        "cwe": "CWE-601",
                        "scan_type": "redirect",
                        "redirect_target": best.get("evidence", {}).get("final_url"),
                    }
                )

            total_found = len(vulnerabilities)

            return {
                "success": True,
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                # Required structured output (primary)
                "result": {
                    "vulnerability": "Open Redirect",
                    "severity": best.get("severity"),
                    "is_vulnerable": bool(best.get("is_vulnerable")),
                    "evidence": best.get("evidence"),
                    "exploitability": best.get("exploitability"),
                    "recommendation": best.get("recommendation"),
                },
                # Schema-compatible aliases (so clients can read without nested `result`).
                "vulnerability": "Open Redirect",
                "severity": best.get("severity"),
                "is_vulnerable": bool(best.get("is_vulnerable")),
                "evidence": best.get("evidence"),
                "exploitability": best.get("exploitability"),
                "recommendation": best.get("recommendation"),
                "baseline": baseline,
                "vulnerabilities": vulnerabilities,
                "total_found": total_found,
                "scan_time": "completed",
            }

        except Exception as e:
            logger.error(f"[Redirect] Error: {e}")
            return {"success": False, "error": str(e), "target": target_url}

    def scan_batch(self, urls: List[str], **kwargs) -> Dict:
        results = {"total_scanned": len(urls), "timestamp": datetime.now().isoformat(), "scans": []}
        for url in urls:
            results["scans"].append(self.scan_url(url, **kwargs))
        results["total_vulnerabilities"] = sum(s.get("total_found", 0) for s in results["scans"])
        return results
