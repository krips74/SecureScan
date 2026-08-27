"""CORS misconfiguration tester (defensive).

This scanner is designed to detect common CORS misconfigurations by making
non-destructive requests (GET/OPTIONS) with a controlled Origin value.

It does NOT attempt exploitation, credential theft, or state changes.

Outputs an exploitability-first risk rating with evidence.

Key rule: Missing CORS headers (e.g., no ACAO/ACAC) is SAFE by default.
Browsers will block cross-origin reads unless the server explicitly opts in.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


_DEFAULT_ORIGIN = "https://evil.example"
_ALT_ORIGIN = "https://evil2.example"


def _hget(headers: requests.structures.CaseInsensitiveDict, name: str) -> str:
    return (headers.get(name) or "").strip()


def _is_http_url(url: str) -> bool:
    return bool(url) and url.startswith(("http://", "https://"))


def _same_site_origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _parse_allow_methods(value: str) -> List[str]:
    if not value:
        return []
    return [m.strip().upper() for m in value.split(",") if m.strip()]


def _parse_allow_headers(value: str) -> List[str]:
    if not value:
        return []
    return [h.strip() for h in value.split(",") if h.strip()]


@dataclass
class CorsProbe:
    kind: str  # 'simple' | 'preflight'
    url: str
    status_code: int
    request_origin: str
    response_headers: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "url": self.url,
            "status_code": self.status_code,
            "request_origin": self.request_origin,
            "response_headers": self.response_headers,
        }


class CORSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SecureScan/1.0",
                "Accept": "*/*",
            }
        )

    def _safe_headers_snapshot(self, resp: requests.Response) -> Dict[str, str]:
        # Only include CORS-relevant and cache-related headers to keep output focused.
        keep = {
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Expose-Headers",
            "Access-Control-Max-Age",
            "Vary",
            "Cache-Control",
            "Content-Type",
            "Location",
            "WWW-Authenticate",
            # Do not include Set-Cookie value; we only use presence as a sensitivity signal.
        }
        snap: Dict[str, str] = {}
        for k, v in resp.headers.items():
            if k in keep:
                snap[k] = v
        return snap

    def _has_set_cookie(self, resp: requests.Response) -> bool:
        try:
            v = resp.headers.get("Set-Cookie")
            return bool(v)
        except Exception:
            return False

    def _safe_body_sample(self, resp: requests.Response, limit: int = 4096) -> str:
        try:
            raw = getattr(resp, "content", b"")
            if not raw:
                return ""
            return raw[: int(limit)].decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _is_sensitive_context(self, url: str, resp: requests.Response) -> Dict[str, Any]:
        """Best-effort sensitivity detection.

        We only assert "sensitive" when there are *strong* signals to avoid false positives.
        """
        headers = resp.headers
        cache_control = (_hget(headers, "Cache-Control") or "").lower()
        www_auth = _hget(headers, "WWW-Authenticate")
        content_type = (_hget(headers, "Content-Type") or "").lower()

        set_cookie_present = self._has_set_cookie(resp)
        cache_private = any(x in cache_control for x in ("private", "no-store"))
        auth_challenge = bool(www_auth)

        # Lightweight body heuristics (only for JSON-ish responses)
        body = self._safe_body_sample(resp)
        body_sensitive = False
        if body and ("json" in content_type):
            # Avoid broad matching; look for common sensitive key names.
            body_sensitive = bool(
                re.search(r'"(access_token|refresh_token|token|email|username|apikey|api_key|secret|password)"\s*:', body, re.IGNORECASE)
            )

        # URL hints (supporting only)
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            path = (url or "").lower()
        path_hint = bool(re.search(r"/(api|account|profile|user|admin|session|auth|login)", path))

        strong = set_cookie_present or cache_private or auth_challenge or body_sensitive
        return {
            "sensitive": bool(strong and (path_hint or body_sensitive or set_cookie_present or auth_challenge)),
            "signals": {
                "set_cookie_present": set_cookie_present,
                "cache_private_or_no_store": cache_private,
                "www_authenticate_present": auth_challenge,
                "body_sensitive_keys": body_sensitive,
                "path_hint": path_hint,
            },
        }

    def _classify_exploitability_first(
        self,
        *,
        acao_effective: str,
        acac_effective: str,
        request_origin: str,
        reflects_origin: bool,
        dynamic_reflection: bool,
        preflight_ok: bool,
        sensitive: bool,
        sensitive_signals: Dict[str, Any],
        notes: List[str],
    ) -> Dict[str, Any]:
        """Exploitability-first classification.

        Rules:
        - Missing ACAO is SAFE (default browser behavior blocks reads).
        - Parameter/presence alone is never a vulnerability; require browser-readable + sensitive context.
        """
        acao = (acao_effective or "").strip()
        acac = (acac_effective or "").strip().lower()

        if not acao:
            return {
                "risk": "SAFE",
                "vulnerable": False,
                "confidence": "HIGH",
                "explanation": "No Access-Control-Allow-Origin (ACAO) header observed. Browsers will block cross-origin JavaScript reads by default.",
                "recommendation": "No action required. Only add CORS headers where cross-origin access is intended and validated.",
            }

        allows_any_origin = (acao == "*")
        allows_origin = allows_any_origin or reflects_origin or dynamic_reflection
        allows_credentials = (acac == "true")

        # CONDITION C: Wildcard + credentials is treated as HIGH misconfiguration.
        if allows_any_origin and allows_credentials:
            notes.append("ACAO='*' with ACAC=true is a severe CORS misconfiguration")
            return {
                "risk": "HIGH",
                "vulnerable": True,
                "confidence": "HIGH",
                "explanation": "Server indicates cross-origin access with credentials and a wildcard origin. This is commonly exploitable on sensitive endpoints.",
                "recommendation": "Do not use ACAO='*' with credentials. Reflect only trusted origins via an allowlist and set Vary: Origin.",
            }

        # Origin reflection / dynamic allow.
        if allows_origin and (reflects_origin or dynamic_reflection):
            if allows_credentials:
                if sensitive:
                    return {
                        "risk": "HIGH",
                        "vulnerable": True,
                        "confidence": "HIGH",
                        "explanation": "ACAO reflects an attacker-controlled Origin and ACAC=true. In browsers, this can allow a malicious origin to read authenticated responses.",
                        "recommendation": "Validate Origin using a strict allowlist. Never reflect arbitrary origins. Add Vary: Origin.",
                    }
                # Misconfig present but sensitivity not confirmed.
                return {
                    "risk": "MEDIUM",
                    "vulnerable": False,
                    "confidence": "MEDIUM",
                    "explanation": "ACAO appears to reflect an attacker-controlled Origin and ACAC=true, but sensitive response context was not confirmed for this endpoint.",
                    "recommendation": "Review this endpoint in an authenticated browser context. If sensitive data is returned, restrict origins using an allowlist.",
                }

            # No credentials: cross-origin reads can occur for non-credentialed requests.
            if sensitive and sensitive_signals.get("body_sensitive_keys"):
                return {
                    "risk": "MEDIUM",
                    "vulnerable": True,
                    "confidence": "MEDIUM",
                    "explanation": "ACAO allows an attacker-controlled Origin (without credentials). Response appears to include potentially sensitive data that would be readable cross-origin.",
                    "recommendation": "Avoid exposing sensitive data to unauthenticated requests and restrict allowed origins to trusted values.",
                }

            return {
                "risk": "LOW",
                "vulnerable": False,
                "confidence": "MEDIUM" if preflight_ok else "LOW",
                "explanation": "ACAO allows an attacker-controlled Origin (or wildcard) but credentials are not enabled and sensitive data exposure was not confirmed.",
                "recommendation": "If cross-origin access is not required, remove permissive CORS. Otherwise, restrict origins and ensure sensitive endpoints require authentication.",
            }

        # ACAO present but does not allow our cross-origin origin.
        return {
            "risk": "SAFE",
            "vulnerable": False,
            "confidence": "HIGH",
            "explanation": "ACAO is present but does not allow the tested cross-origin Origin. Browser cross-origin reads should be blocked.",
            "recommendation": "No action required. Ensure any allowed origins are intentionally trusted.",
        }

    def scan_url(self, target_url: str, timeout: int = 15, test_origin: str = _DEFAULT_ORIGIN, scan_id: Optional[int] = None) -> Dict[str, Any]:
        if not _is_http_url(target_url):
            return {"success": False, "error": "Valid URL required", "target": target_url}
        
        # Auto-upgrade HTTP to HTTPS if target is on common HTTPS ports
        if target_url.startswith('http://'):
            parsed = urlparse(target_url)
            if parsed.port in (443, 8443, 4280, 4443, 5001):
                target_url = target_url.replace('http://', 'https://', 1)

        try:
            notes: List[str] = []
            same_site = _same_site_origin(target_url)
            if test_origin == same_site:
                # Ensure we test cross-origin by default.
                test_origin = _DEFAULT_ORIGIN

            # 1) Simple request (GET) with Origin header
            simple_headers = {
                "Origin": test_origin,
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "cors",
            }

            logger.info(f"[CORS] Simple probe: {target_url} Origin={test_origin}")
            resp = self.session.get(
                target_url,
                headers=simple_headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
            )

            # Optional second-origin probe to confirm reflection/dynamic allowing.
            alt_origin = _ALT_ORIGIN if test_origin != _ALT_ORIGIN else _DEFAULT_ORIGIN
            alt_acao = ""
            try:
                alt_headers = dict(simple_headers)
                alt_headers["Origin"] = alt_origin
                logger.info(f"[CORS] Simple probe (alt origin): {target_url} Origin={alt_origin}")
                resp_alt = self.session.get(
                    target_url,
                    headers=alt_headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                )
                alt_acao = _hget(resp_alt.headers, "Access-Control-Allow-Origin")
            except Exception:
                alt_acao = ""

            acao = _hget(resp.headers, "Access-Control-Allow-Origin")
            acac = _hget(resp.headers, "Access-Control-Allow-Credentials")
            vary = _hget(resp.headers, "Vary")
            if acao and "Origin" not in vary and acao != "*":
                notes.append("ACAO is not '*' but Vary: Origin is missing (may cause cache poisoning risks)")

            simple_probe = CorsProbe(
                kind="simple",
                url=target_url,
                status_code=resp.status_code,
                request_origin=test_origin,
                response_headers=self._safe_headers_snapshot(resp),
            )

            # 2) Preflight request (OPTIONS)
            preflight_headers = {
                "Origin": test_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, authorization, x-csrf-token",
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "cors",
            }

            logger.info(f"[CORS] Preflight probe: {target_url} Origin={test_origin}")
            pre = self.session.options(
                target_url,
                headers=preflight_headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
            )

            pre_acao = _hget(pre.headers, "Access-Control-Allow-Origin")
            pre_acac = _hget(pre.headers, "Access-Control-Allow-Credentials")
            allow_methods = _parse_allow_methods(_hget(pre.headers, "Access-Control-Allow-Methods"))
            allow_headers = _parse_allow_headers(_hget(pre.headers, "Access-Control-Allow-Headers"))

            preflight_ok = False
            if pre.status_code < 400 and pre_acao:
                # Consider preflight OK if it allows requested method and some requested headers.
                if (not allow_methods) or ("POST" in allow_methods):
                    preflight_ok = True

            preflight_probe = CorsProbe(
                kind="preflight",
                url=target_url,
                status_code=pre.status_code,
                request_origin=test_origin,
                response_headers=self._safe_headers_snapshot(pre),
            )

            # Prefer simple response for classification; incorporate preflight if simple is missing.
            merged_acao = (acao or pre_acao or "").strip()
            merged_acac = (acac or pre_acac or "").strip()

            # Extra signals for safer reporting / triage.
            merged_acac_lc = (merged_acac or "").strip().lower()
            vary = vary or _hget(pre.headers, "Vary")
            vary_has_origin = bool(re.search(r"\bOrigin\b", vary, re.IGNORECASE))

            reflects_test_origin = (merged_acao == test_origin)
            reflects_alt_origin = bool(alt_acao and alt_acao.strip() == alt_origin)
            dynamic_reflection = bool(reflects_test_origin and reflects_alt_origin)
            if dynamic_reflection:
                notes.append("ACAO reflects multiple attacker-controlled Origins (dynamic allow / reflection behavior)")

            allows_any_origin = (merged_acao == "*")
            allows_credentials = (merged_acac_lc == "true")

            # Sensitivity / impact heuristics (best-effort)
            sensitivity = self._is_sensitive_context(target_url, resp)
            sensitive = bool(sensitivity.get("sensitive"))

            classification = self._classify_exploitability_first(
                acao_effective=merged_acao,
                acac_effective=merged_acac,
                request_origin=test_origin,
                reflects_origin=reflects_test_origin,
                dynamic_reflection=dynamic_reflection,
                preflight_ok=preflight_ok,
                sensitive=sensitive,
                sensitive_signals=sensitivity.get("signals") or {},
                notes=notes,
            )

            exploitable_pattern = bool(allows_credentials and (reflects_test_origin or allows_any_origin or dynamic_reflection))

            impact = "SAFE by default: browsers block cross-origin reads unless ACAO explicitly allows them."
            if classification.get("risk") != "SAFE":
                impact = "Review required: cross-origin read may be possible depending on browser rules, credentials, and response sensitivity."

            manual_verification_checklist = [
                "Confirm the response includes 'Access-Control-Allow-Origin' matching an attacker-controlled origin OR '*'.",
                "If 'Access-Control-Allow-Credentials: true' is present, confirm that the allowed origin is not overly broad or attacker-controlled.",
                "Check that 'Vary: Origin' is present when ACAO is not '*', to avoid caching issues.",
                "Check preflight behavior (OPTIONS) for sensitive endpoints: allowed methods and headers should be minimal.",
                "Confirm whether sensitive data endpoints return data only when authenticated (this affects real-world impact).",
            ]

            evidence_lines: List[str] = []
            evidence_lines.append(f"Simple probe HTTP {resp.status_code}; ACAO={acao or 'missing'}; ACAC={acac or 'missing'}")
            if alt_acao:
                evidence_lines.append(f"Alt-origin simple probe; Origin={alt_origin}; ACAO={alt_acao}")
            evidence_lines.append(f"Preflight probe HTTP {pre.status_code}; ACAO={pre_acao or 'missing'}; ACAC={pre_acac or 'missing'}")
            if allow_methods:
                evidence_lines.append(f"Preflight allow-methods: {', '.join(allow_methods)}")
            if allow_headers:
                evidence_lines.append(f"Preflight allow-headers: {', '.join(allow_headers[:12])}{'...' if len(allow_headers) > 12 else ''}")
            if notes:
                evidence_lines.extend(notes)

            return {
                "success": True,
                "url": target_url,
                "timestamp": datetime.now().isoformat(),
                "tested_origin": test_origin,
                "risk": classification.get("risk"),
                "vulnerable": bool(classification.get("vulnerable")),
                "confidence": classification.get("confidence"),
                # Backward-compatible fields used by current UI
                "reason": classification.get("explanation"),
                "impact": impact,
                # Required output schema
                "evidence": {
                    "acao": merged_acao or "",
                    "acac": merged_acac_lc or "",
                },
                "explanation": classification.get("explanation"),
                "recommendation": classification.get("recommendation"),
                # Additional debug/triage output
                "evidence_lines": evidence_lines,
                "signals": {
                    "acao": merged_acao or "missing",
                    "acac": (merged_acac_lc or "missing") or "missing",
                    "reflects_test_origin": reflects_test_origin,
                    "allows_any_origin": allows_any_origin,
                    "allows_credentials": allows_credentials,
                    "preflight_ok": preflight_ok,
                    "vary_origin_present": vary_has_origin,
                    "dynamic_reflection": dynamic_reflection,
                    "reflection": bool(reflects_test_origin or dynamic_reflection),
                    "sensitive": sensitive,
                    "sensitive_signals": sensitivity.get("signals"),
                },
                "exploitable_pattern": exploitable_pattern,
                "manual_verification_checklist": manual_verification_checklist,
                "probes": [simple_probe.to_dict(), preflight_probe.to_dict()],
                "limits": {
                    "mode": "non-destructive",
                    "notes": [
                        "No credentialed browser context is used; this is a header-based assessment",
                        "No state-changing requests are performed",
                        "Some servers send CORS headers only on specific endpoints or when authenticated",
                    ],
                },
            }

        except Exception as e:
            logger.error(f"[CORS] Error: {e}")
            return {"success": False, "error": str(e), "target": target_url}
