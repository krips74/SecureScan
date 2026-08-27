"""Stored XSS heuristic scanner.

True stored XSS generally requires a state-changing action (e.g., submitting a form)
followed by a later page view where the payload is rendered.

This implementation is intentionally conservative and GET-only:
- Fetch a baseline response.
- Inject a unique, non-executing HTML marker payload into a query parameter.
- Fetch the original URL again (without the payload).
- If the unique marker appears only after the injection, flag as a stored XSS candidate.

This detects a subset of stored XSS patterns (including unsafe endpoints that store
GET parameters) and avoids posting data.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

import requests
from utils.scan_storage import is_cancel_requested

logger = logging.getLogger(__name__)


@dataclass
class _HtmlForm:
    action: str
    method: str
    fields: Dict[str, str]
    text_fields: List[str]


class _FirstFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_form = False
        self.captured = False
        self.form_action = ""
        self.form_method = "get"
        self.fields: Dict[str, str] = {}
        self.text_fields: List[str] = []
        self._current_textarea: Optional[str] = None
        self._textarea_buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if self.captured:
            return

        attrs_d = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag.lower() == "form" and not self.in_form:
            self.in_form = True
            self.form_action = attrs_d.get("action", "")
            self.form_method = (attrs_d.get("method", "get") or "get").lower()
            return

        if not self.in_form:
            return

        if tag.lower() == "input":
            name = (attrs_d.get("name") or "").strip()
            if not name:
                return
            itype = (attrs_d.get("type") or "text").lower()
            value = attrs_d.get("value", "")
            self.fields.setdefault(name, value)
            if itype in ("text", "search", "email", "url", "tel", "password"):
                if name not in self.text_fields:
                    self.text_fields.append(name)
        elif tag.lower() == "textarea":
            name = (attrs_d.get("name") or "").strip()
            if not name:
                return
            self._current_textarea = name
            self._textarea_buf = []

    def handle_endtag(self, tag):
        if self.captured:
            return

        if tag.lower() == "textarea" and self.in_form and self._current_textarea:
            self.fields.setdefault(self._current_textarea, "".join(self._textarea_buf))
            if self._current_textarea not in self.text_fields:
                self.text_fields.append(self._current_textarea)
            self._current_textarea = None
            self._textarea_buf = []

        if tag.lower() == "form" and self.in_form:
            self.in_form = False
            self.captured = True

    def handle_data(self, data):
        if self.in_form and self._current_textarea:
            self._textarea_buf.append(data)


class StoredXssScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SecureScan/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    def scan_url(
        self,
        target_url: str,
        timeout: int = 8,
        max_params: int = 3,
        stop_on_first: bool = True,
        max_duration: int = 10,
        mode: str = "heuristic_get",
        allow_state_change: bool = False,
        cookies: Optional[Dict[str, str]] = None,
        scan_id: Optional[int] = None,
    ) -> Dict:
        started = time.monotonic()

        def time_remaining() -> float:
            try:
                md = float(max_duration)
            except Exception:
                md = 10.0
            return md - (time.monotonic() - started)

        def budgeted_timeout() -> float:
            try:
                per_req = float(timeout)
            except Exception:
                per_req = 8.0
            remaining = time_remaining()
            if remaining <= 0:
                return 0.0
            return min(per_req, max(1.0, remaining))

        try:
            if cookies and isinstance(cookies, dict):
                try:
                    self.session.cookies.update({str(k): str(v) for k, v in cookies.items()})
                except Exception:
                    pass

            # Baseline
            base_timeout = budgeted_timeout()
            if base_timeout <= 0:
                return {
                    "success": False,
                    "error": "Stored XSS time budget exceeded before baseline request",
                    "target": target_url,
                }

            baseline_resp = self.session.get(
                target_url,
                timeout=base_timeout,
                allow_redirects=True,
                verify=False,
            )
            baseline_text = baseline_resp.text or ""

            marker_id = f"ss_stored_xss_marker_{uuid4().hex}"
            marker_payload = f"<svg id=\"{marker_id}\"></svg>"

            requested_mode = (mode or "heuristic_get").strip().lower()
            if requested_mode in ("form", "form_post", "post"):
                if not allow_state_change:
                    return {
                        "success": True,
                        "target": target_url,
                        "timestamp": datetime.now().isoformat(),
                        "vulnerabilities": [],
                        "total_found": 0,
                        "scan_time": "completed",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "marker_id": marker_id,
                        "notes": ["Stored XSS form test skipped (requires allow_state_change=true)"],
                    }

                form = self._extract_first_form(baseline_text)
                if not form:
                    return {
                        "success": True,
                        "target": target_url,
                        "timestamp": datetime.now().isoformat(),
                        "vulnerabilities": [],
                        "total_found": 0,
                        "scan_time": "completed",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "marker_id": marker_id,
                        "notes": ["No form detected for stored XSS submission"],
                    }

                if form.method not in ("post", "get"):
                    form.method = "post"

                # Populate up to 2 text fields: one name-like, one message-like.
                payload_fields = dict(form.fields)
                if form.text_fields:
                    payload_fields[form.text_fields[0]] = "SecureScan"
                if len(form.text_fields) > 1:
                    payload_fields[form.text_fields[1]] = marker_payload
                elif form.text_fields:
                    payload_fields[form.text_fields[0]] = marker_payload

                submit_url = urllib.parse.urljoin(target_url, form.action or "")
                submit_timeout = budgeted_timeout()
                if submit_timeout <= 0:
                    return {
                        "success": False,
                        "error": "Stored XSS time budget exceeded before form submission",
                        "target": target_url,
                    }

                try:
                    if form.method == "get":
                        self.session.get(
                            submit_url,
                            params=payload_fields,
                            timeout=submit_timeout,
                            allow_redirects=True,
                            verify=False,
                        )
                    else:
                        self.session.post(
                            submit_url,
                            data=payload_fields,
                            timeout=submit_timeout,
                            allow_redirects=True,
                            verify=False,
                        )
                except requests.RequestException as e:
                    return {
                        "success": False,
                        "error": f"Form submission failed: {e}",
                        "target": target_url,
                    }

                clean_timeout = budgeted_timeout()
                if clean_timeout <= 0:
                    return {
                        "success": False,
                        "error": "Stored XSS time budget exceeded before verification fetch",
                        "target": target_url,
                    }

                try:
                    clean_resp = self.session.get(
                        target_url,
                        timeout=clean_timeout,
                        allow_redirects=True,
                        verify=False,
                    )
                except requests.RequestException as e:
                    return {
                        "success": False,
                        "error": f"Verification fetch failed: {e}",
                        "target": target_url,
                    }

                clean_text = clean_resp.text or ""
                if not self._is_html_like_response(clean_resp):
                    return {
                        "success": True,
                        "target": target_url,
                        "timestamp": datetime.now().isoformat(),
                        "vulnerabilities": [],
                        "total_found": 0,
                        "scan_time": "completed",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "marker_id": marker_id,
                        "notes": ["Verification response did not look like HTML/XML; skipping stored-XSS confirmation"],
                    }

                if (marker_payload in clean_text) and (marker_payload not in baseline_text):
                    return {
                        "success": True,
                        "target": target_url,
                        "timestamp": datetime.now().isoformat(),
                        "vulnerabilities": [
                            {
                                "type": "XSS",
                                "severity": "High",
                                "parameter": form.text_fields[1] if len(form.text_fields) > 1 else (form.text_fields[0] if form.text_fields else "form"),
                                "payload": marker_payload,
                                "evidence": "Marker payload persisted on a clean reload after form submission (stored XSS confirmed)",
                                "poc": submit_url,
                                "verification_url": target_url,
                                "cwe": "CWE-79",
                                "scan_type": "stored",
                                "confidence": "high",
                            }
                        ],
                        "total_found": 1,
                        "scan_time": "completed",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "marker_id": marker_id,
                    }

                return {
                    "success": True,
                    "target": target_url,
                    "timestamp": datetime.now().isoformat(),
                    "vulnerabilities": [],
                    "total_found": 0,
                    "scan_time": "completed",
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "marker_id": marker_id,
                    "notes": ["Form submission completed but marker did not persist"],
                }

            params = self._extract_params(target_url)
            param_names = list(params.keys())
            if not param_names:
                # No query parameters: do not attempt aggressive guesses here.
                return {
                    "success": True,
                    "target": target_url,
                    "timestamp": datetime.now().isoformat(),
                    "vulnerabilities": [],
                    "total_found": 0,
                    "scan_time": "completed",
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "notes": ["No query parameters found for stored-XSS heuristic"],
                    "marker_id": marker_id,
                }

            try:
                mp = int(max_params)
            except Exception:
                mp = 3
            if mp > 0:
                param_names = param_names[:mp]

            vulnerabilities: List[Dict] = []

            for param in param_names:
                if time_remaining() <= 0:
                    break
                if scan_id is not None and is_cancel_requested(scan_id):
                    raise RuntimeError("Scan stopped by user")

                injected_url = self._build_payload_url(target_url, param, marker_payload)
                inj_timeout = budgeted_timeout()
                if inj_timeout <= 0:
                    break

                try:
                    self.session.get(
                        injected_url,
                        timeout=inj_timeout,
                        allow_redirects=True,
                        verify=False,
                    )
                except requests.RequestException:
                    continue

                # Re-fetch original URL (clean) and check for persistence.
                clean_timeout = budgeted_timeout()
                if clean_timeout <= 0:
                    break

                try:
                    clean_resp = self.session.get(
                        target_url,
                        timeout=clean_timeout,
                        allow_redirects=True,
                        verify=False,
                    )
                except requests.RequestException:
                    continue

                clean_text = clean_resp.text or ""
                if not self._is_html_like_response(clean_resp):
                    continue

                if (marker_payload in clean_text) and (marker_payload not in baseline_text):
                    vulnerabilities.append(
                        {
                            "type": "XSS",
                            "severity": "High",
                            "parameter": param,
                            "payload": marker_payload,
                            "evidence": "Marker payload persisted on a clean reload after injection (stored XSS candidate)",
                            "poc": injected_url,
                            "verification_url": target_url,
                            "cwe": "CWE-79",
                            "scan_type": "stored",
                            "confidence": "heuristic",
                        }
                    )
                    if stop_on_first:
                        break

            return {
                "success": True,
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "scan_time": "completed",
                "duration_seconds": round(time.monotonic() - started, 3),
                "marker_id": marker_id,
            }

        except Exception as e:
            logger.error(f"[StoredXSS] Error: {e}")
            return {"success": False, "error": str(e), "target": target_url}

    def _extract_params(self, url: str) -> Dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in params.items()}

    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    def _extract_first_form(self, html: str) -> Optional[_HtmlForm]:
        try:
            parser = _FirstFormParser()
            parser.feed(html or "")
            if not parser.captured and not parser.fields and not parser.text_fields:
                return None
            return _HtmlForm(
                action=parser.form_action or "",
                method=(parser.form_method or "get").lower(),
                fields=parser.fields or {},
                text_fields=parser.text_fields or [],
            )
        except Exception:
            return None

    def _is_html_like_response(self, response) -> bool:
        try:
            ctype = (getattr(response, "headers", {}) or {}).get("Content-Type", "")
            ctype_l = str(ctype).lower()
            if "text/html" in ctype_l or "application/xhtml+xml" in ctype_l:
                return True
            if "svg" in ctype_l and "xml" in ctype_l:
                return True
            if "application/json" in ctype_l or "text/plain" in ctype_l:
                return False
            body = getattr(response, "text", "") or ""
            body_l = body[:4096].lower()
            return ("<html" in body_l) or ("<!doctype" in body_l) or ("<body" in body_l)
        except Exception:
            return False
