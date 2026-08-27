from __future__ import annotations

import time
from uuid import uuid4
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from utils.scan_storage import is_cancel_requested


@dataclass(frozen=True)
class _TestCase:
    name: str
    parameter: str
    url: str


class DomXssScanner:
    """DOM-based XSS detector using a real browser context.

    This is intentionally "safe": it injects a non-executing DOM marker payload
    and checks if it becomes a real DOM element (indicating unsafe HTML insertion).
    """

    def __init__(self, headless: bool = True):
        self.headless = bool(headless)

    def scan_url(
        self,
        target_url: str,
        timeout: int = 12,
        max_cases: int = 12,
        stop_on_first: bool = True,
        scan_id: Optional[int] = None,
    ) -> Dict:
        started = time.monotonic()

        # IMPORTANT: Use a per-scan random marker id to avoid false positives
        # on pages that already contain a fixed id.
        marker_id = f"ss_dom_xss_{uuid4().hex[:10]}"
        marker_payload = f"<svg id=\"{marker_id}\"></svg>"

        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception as e:
            return {
                "success": False,
                "error": "DOM XSS check requires Playwright. Install with `pip install playwright` and run `python -m playwright install chromium`.",
                "details": str(e),
                "target": target_url,
            }

        cases = self._build_cases(target_url, marker_payload)
        if max_cases is not None:
            try:
                max_int = int(max_cases)
            except Exception:
                max_int = 12
            if max_int > 0:
                cases = cases[:max_int]

        vulnerabilities: List[Dict] = []

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=self.headless)
            except Exception as e:
                return {
                    "success": False,
                    "error": "Playwright browser runtime not installed. Run `python -m playwright install chromium`.",
                    "details": str(e),
                    "target": target_url,
                }

            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            try:
                for tc in cases:
                    if scan_id is not None and is_cancel_requested(scan_id):
                        raise RuntimeError("Scan stopped by user")
                    found = self._run_case(page, tc.url, marker_id=marker_id, timeout_seconds=timeout)
                    if found:
                        vulnerabilities.append(
                            {
                                "type": "XSS",
                                "severity": "high",
                                "parameter": tc.parameter,
                                "payload": marker_payload,
                                "evidence": "DOM injection detected: marker element was created in the rendered DOM",
                                "poc": tc.url,
                                "cwe": "CWE-79",
                                "scan_type": "dom",
                                "confidence": "high",
                            }
                        )
                        if stop_on_first:
                            break
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass

        return {
            "success": True,
            "target": target_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "vulnerabilities": vulnerabilities,
            "total_found": len(vulnerabilities),
            "scan_time": "completed",
            "duration_seconds": round(time.monotonic() - started, 3),
            "cases_tested": len(cases),
            "marker_id": marker_id,
        }

    def _run_case(self, page, url: str, marker_id: str, timeout_seconds: int) -> bool:
        timeout_ms = max(1000, int(timeout_seconds) * 1000)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            # Let client-side JS run (DOM XSS is often asynchronous).
            page.wait_for_load_state("networkidle", timeout=timeout_ms)
        except Exception:
            # Still attempt DOM inspection even if the page didn't fully settle.
            pass

        try:
            return bool(
                page.evaluate(
                    f"() => Boolean(document.querySelector('#{marker_id}'))"
                )
            )
        except Exception:
            return False

    def _build_cases(self, target_url: str, marker_payload: str) -> List[_TestCase]:
        """Build test URLs for query parameters and hash-based DOM XSS."""
        parsed = urlparse(target_url)

        # Query param testcases
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        cases: List[_TestCase] = []
        if pairs:
            for k, _v in pairs:
                mutated = [(pk, (marker_payload if pk == k else pv)) for pk, pv in pairs]
                new_query = urlencode(mutated, doseq=True)
                new_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    )
                )
                cases.append(_TestCase(name=f"param:{k}", parameter=k, url=new_url))

        # Hash testcase (common for DOM XSS)
        hash_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                marker_payload,
            )
        )
        cases.append(_TestCase(name="hash", parameter="#", url=hash_url))

        # If no params were present, also create a single query param testcase.
        if not pairs:
            q = urlencode({"q": marker_payload})
            q_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    q,
                    parsed.fragment,
                )
            )
            cases.insert(0, _TestCase(name="param:q", parameter="q", url=q_url))

        return cases
