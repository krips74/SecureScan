"""HTTP Security Header Analysis.

This module intentionally distinguishes between:
- exploitable risk (HIGH)
- misconfiguration (MEDIUM)
- hardening gaps (LOW)
- informational disclosures (INFO)

and applies context-aware grading to reduce false positives.
"""
import requests
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import logging
import re
import urllib.parse

logger = logging.getLogger(__name__)

# NOTE: A previous implementation used header importance weights to subtract points.
# That model created harsh grades and false positives. The current implementation
# uses context-aware findings and a realistic rubric.

# Insecure headers that should NOT be present
INSECURE_HEADERS = {
    "Server": "Reveals server software and version",
    "X-Powered-By": "Reveals backend technology",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}


SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class HeaderScanner:
    """Checks HTTP security headers and provides a security grade."""

    def _normalize_host(self, host: str) -> str:
        h = (host or "").strip().lower()
        if h.startswith("www."):
            h = h[4:]
        return h

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SecureScan/1.0"
        })

    def _headers_to_lower_map(self, headers: Dict) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not headers:
            return out
        for k, v in dict(headers).items():
            if k is None:
                continue
            out[str(k).lower()] = str(v) if v is not None else ""
        return out

    def _get_header(self, headers_lc: Dict[str, str], name: str) -> Optional[str]:
        if not headers_lc:
            return None
        v = headers_lc.get((name or "").lower())
        if v is None:
            return None
        v = str(v)
        return v if v.strip() else None

    def _is_html_response(self, headers_lc: Dict[str, str]) -> bool:
        ct = (self._get_header(headers_lc, "Content-Type") or "").lower()
        if not ct:
            return False
        return ("text/html" in ct) or ("application/xhtml" in ct)

    def _auth_context(self, target_url: str, headers_lc: Dict[str, str]) -> bool:
        """Best-effort context check for auth/sensitive flows.

        We avoid network/body parsing and rely on URL + response headers.
        """
        try:
            p = urllib.parse.urlparse(target_url)
            path = (p.path or "").lower()
        except Exception:
            path = (target_url or "").lower()

        keywords = (
            "login",
            "signin",
            "sign-in",
            "account",
            "checkout",
            "payment",
            "pay",
            "oauth",
            "sso",
            "auth",
            "admin",
            "profile",
            "register",
            "password",
        )
        if any(k in path for k in keywords):
            return True

        set_cookie = (self._get_header(headers_lc, "Set-Cookie") or "").lower()
        if set_cookie:
            # Session/auth cookie names are common across frameworks.
            if re.search(r"(session|sess|token|jwt|auth|sid|csrftoken|xsrf)", set_cookie, re.IGNORECASE):
                return True

        if self._get_header(headers_lc, "WWW-Authenticate"):
            return True

        return False

    def _make_finding(
        self,
        header: str,
        severity: str,
        reason: str,
        recommendation: str,
        group: Optional[str] = None,
    ) -> Dict[str, str]:
        sev = (severity or "").upper()
        if sev not in SEVERITY_ORDER:
            sev = "INFO"
        return {
            "header": header,
            "severity": sev,
            "reason": reason,
            "recommendation": recommendation,
            "_group": group or header,
        }

    def _dedupe_findings(self, findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Dedupe/group related findings so they don't over-inflate scoring."""
        grouped: Dict[str, Dict[str, str]] = {}
        for f in findings:
            g = f.get("_group") or f.get("header") or "finding"
            if g not in grouped:
                grouped[g] = dict(f)
                continue
            # Merge reasons/recommendations, keep max severity
            existing = grouped[g]
            if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) > SEVERITY_ORDER.get(existing.get("severity", "INFO"), 0):
                existing["severity"] = f.get("severity")
            if f.get("reason") and f["reason"] not in existing.get("reason", ""):
                existing["reason"] = (existing.get("reason") + "\n" + f["reason"]).strip()
            if f.get("recommendation") and f["recommendation"] not in existing.get("recommendation", ""):
                existing["recommendation"] = (existing.get("recommendation") + "\n" + f["recommendation"]).strip()

        out = list(grouped.values())
        for f in out:
            f.pop("_group", None)
        # Sort by severity then header for stable UX
        out.sort(key=lambda x: (-SEVERITY_ORDER.get(x.get("severity", "INFO"), 0), (x.get("header") or "")))
        return out

    def _summary_counts(self, findings: List[Dict[str, str]]) -> Dict[str, int]:
        s = {"critical": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            if sev == "HIGH":
                s["critical"] += 1
            elif sev == "MEDIUM":
                s["medium"] += 1
            elif sev == "LOW":
                s["low"] += 1
            else:
                s["info"] += 1
        return s

    def _grade_from_findings(self, findings: List[Dict[str, str]], auth_context: bool) -> Tuple[str, str]:
        """Return (grade, explanation).

        Key guardrails:
        - Missing hardening-only headers must NOT push below C.
        - A single HIGH signal alone should not automatically become F.
        """
        counts = self._summary_counts(findings)
        high = counts["critical"]
        medium = counts["medium"]
        low = counts["low"]

        # Identify a small set of HIGH findings that are closer to direct exploitability
        # or well-known attack chains (e.g., permissive script execution under CSP).
        def _is_exploit_chain_high(f: Dict[str, str]) -> bool:
            if (f.get("severity") or "").upper() != "HIGH":
                return False
            h = (f.get("header") or "").lower()
            r = (f.get("reason") or "").lower()
            if "content-security-policy" in h and "unsafe-inline" in r and "unsafe-eval" in r:
                return True
            # Broad script sources combined with permissive script execution is also a common chain.
            if "content-security-policy" in h and "script-src" in r and ("*" in r or "data:" in r or "blob:" in r):
                return True
            return False

        has_exploit_chain_high = any(_is_exploit_chain_high(f) for f in findings)

        if high >= 1:
            if has_exploit_chain_high:
                return "F", "Critical exploit chain risk detected (HIGH) consistent with real-world exploitation patterns."
            if high >= 2:
                return "F", "Multiple HIGH-risk signals detected, indicating a critical security baseline failure."
            # Single HIGH signal: do not automatically grade F.
            return ("D" if auth_context else "C"), "A single HIGH-risk signal was detected; overall grade is moderated to avoid over-penalizing without a clear exploit chain."

        if medium == 0:
            if low == 0:
                return "A", "Strong baseline: no material security header issues detected."
            if low <= 2:
                return "B", "Good security posture with minor hardening gaps only."
            return "C", "Only low-severity hardening gaps detected; grade is capped at C to avoid harsh scoring."

        if medium == 1:
            return "B" if low <= 3 else "C", "One moderate misconfiguration detected; remaining issues are minor."
        if medium == 2:
            return "C", "Moderate misconfigurations present but no direct exploit chain identified."
        if medium == 3:
            return "D", "Multiple medium-severity misconfigurations indicate a weak header baseline."
        return "D", "Many medium-severity misconfigurations indicate a weak header baseline."

    def _parse_csp(self, csp_value: str) -> Dict[str, List[str]]:
        """Parse a Content-Security-Policy header into directives.

        Returns a mapping of directive -> list of tokens.
        """
        directives: Dict[str, List[str]] = {}
        if not csp_value or not isinstance(csp_value, str):
            return directives

        parts = [p.strip() for p in csp_value.split(';') if p.strip()]
        for part in parts:
            items = [i for i in part.split() if i]
            if not items:
                continue
            name = items[0].lower().strip()
            tokens = items[1:]
            directives[name] = tokens
        return directives

    def _csp_tokens(self, directives: Dict[str, List[str]], directive: str) -> List[str]:
        return [t.strip() for t in directives.get(directive.lower(), []) if isinstance(t, str)]

    def _has_any_token(self, tokens: List[str], needle_values: List[str]) -> bool:
        needles = {n.lower() for n in needle_values}
        return any((t or '').lower() in needles for t in tokens)

    def _csp_frame_ancestors_present(self, csp_value: Optional[str]) -> bool:
        directives = self._parse_csp(csp_value or "")
        return "frame-ancestors" in directives

    def analyze_headers(self, target_url: str, response_headers: Dict) -> Dict:
        """Analyze response headers and return an OWASP-style result dict.

        This is a pure analysis step (no network). `scan_url()` calls this.
        """
        headers_lc = self._headers_to_lower_map(response_headers or {})

        try:
            parsed = urllib.parse.urlparse(target_url)
            is_https = (parsed.scheme or "").lower() == "https"
        except Exception:
            is_https = False

        is_html = self._is_html_response(headers_lc)
        auth_ctx = self._auth_context(target_url, headers_lc)

        findings: List[Dict[str, str]] = []

        csp_value = self._get_header(headers_lc, "Content-Security-Policy")
        directives = self._parse_csp(csp_value or "") if csp_value else {}

        # ---- CSP ----
        if not csp_value:
            sev = "HIGH" if (is_html or auth_ctx) else "MEDIUM"
            findings.append(
                self._make_finding(
                    "Content-Security-Policy",
                    sev,
                    "Content-Security-Policy (CSP) is missing. CSP reduces the impact of XSS and injection bugs by restricting script and resource loading.",
                    "Add a restrictive CSP (start with default-src 'self'; then tighten script-src using nonces/hashes; add frame-ancestors and object-src 'none').",
                    group="csp",
                )
            )
        else:
            default_src = self._csp_tokens(directives, "default-src")
            script_src = self._csp_tokens(directives, "script-src") or default_src
            style_src = self._csp_tokens(directives, "style-src") or default_src

            unsafe_inline_script = self._has_any_token(script_src, ["'unsafe-inline'"])
            unsafe_eval_script = self._has_any_token(script_src, ["'unsafe-eval'"])
            unsafe_inline_style = self._has_any_token(style_src, ["'unsafe-inline'"])

            if unsafe_inline_script and unsafe_eval_script:
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        "HIGH",
                        "CSP allows both 'unsafe-inline' and 'unsafe-eval' for scripts. This significantly increases the exploitability of XSS and CSP bypass chains.",
                        "Remove 'unsafe-inline' and 'unsafe-eval' from script-src; use nonces/hashes for inline scripts and avoid eval()-like constructs.",
                        group="csp",
                    )
                )
            elif unsafe_inline_script:
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        "MEDIUM",
                        "CSP contains 'unsafe-inline' for scripts. This can make XSS easier to exploit depending on the application.",
                        "Prefer nonce- or hash-based CSP (script-src 'nonce-...'/sha256-...) instead of 'unsafe-inline'.",
                        group="csp",
                    )
                )
            elif unsafe_eval_script:
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        "MEDIUM",
                        "CSP contains 'unsafe-eval' for scripts. This can enable injection-to-code-execution patterns in some frameworks.",
                        "Avoid eval()/new Function() patterns and remove 'unsafe-eval' from script-src when possible.",
                        group="csp",
                    )
                )

            # Broad sources are often a misconfiguration, but not automatically exploitable.
            def _has_broad(tokens: List[str]) -> bool:
                toks = {(t or "").lower() for t in tokens}
                return ("*" in toks) or ("data:" in toks) or ("blob:" in toks)

            if _has_broad(script_src):
                sev = "HIGH" if (unsafe_inline_script or unsafe_eval_script) else "MEDIUM"
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        sev,
                        "CSP script-src allows overly broad sources (e.g., *, data:, blob:).",
                        "Restrict script-src to trusted origins and remove broad source expressions.",
                        group="csp",
                    )
                )

            if "object-src" not in directives:
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        "LOW",
                        "CSP is missing object-src. This is a hardening gap for legacy plugin content.",
                        "Add object-src 'none' unless plugin content is required.",
                        group="csp_hardening",
                    )
                )

            if "base-uri" not in directives:
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        "LOW",
                        "CSP is missing base-uri. This is a hardening gap against base tag injection.",
                        "Add base-uri 'self' or base-uri 'none'.",
                        group="csp_hardening",
                    )
                )

            # Mixed content within CSP is a misconfiguration.
            combined = (default_src or []) + (script_src or []) + (style_src or [])
            if any((t or "").lower().startswith("http://") for t in combined):
                findings.append(
                    self._make_finding(
                        "Content-Security-Policy",
                        "MEDIUM",
                        "CSP includes http:// sources, which can weaken protection and enable mixed-content policy issues.",
                        "Prefer https:// sources only; avoid http:// in CSP directives.",
                        group="csp",
                    )
                )

        frame_ancestors_present = self._csp_frame_ancestors_present(csp_value)

        # ---- HSTS ----
        hsts = self._get_header(headers_lc, "Strict-Transport-Security")
        if is_https:
            if not hsts:
                sev = "HIGH" if auth_ctx else "MEDIUM"
                findings.append(
                    self._make_finding(
                        "Strict-Transport-Security",
                        sev,
                        "HSTS is missing on an HTTPS site. Without HSTS, users can be forced onto HTTP in downgrade/MitM scenarios.",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload (after validating subdomains support HTTPS).",
                        group="hsts",
                    )
                )
            else:
                m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
                max_age = int(m.group(1)) if m else 0
                if max_age and max_age < 15552000:
                    findings.append(
                        self._make_finding(
                            "Strict-Transport-Security",
                            "LOW",
                            f"HSTS max-age is relatively low ({max_age}).",
                            "Increase max-age to at least 15552000 (180 days) or ideally 31536000 (1 year), after verifying HTTPS stability.",
                            group="hsts",
                        )
                    )
                if "includesubdomains" not in hsts.lower():
                    findings.append(
                        self._make_finding(
                            "Strict-Transport-Security",
                            "LOW",
                            "HSTS is missing includeSubDomains, leaving subdomains potentially downgradeable.",
                            "Add includeSubDomains once all subdomains are HTTPS-capable.",
                            group="hsts",
                        )
                    )

        # ---- Clickjacking protections ----
        xfo = self._get_header(headers_lc, "X-Frame-Options")
        if not xfo:
            if frame_ancestors_present:
                findings.append(
                    self._make_finding(
                        "X-Frame-Options",
                        "LOW",
                        "X-Frame-Options is missing, but CSP frame-ancestors is present (primary modern protection).",
                        "Optionally add X-Frame-Options: DENY or SAMEORIGIN for legacy browser defense-in-depth.",
                        group="clickjacking",
                    )
                )
            else:
                sev = "MEDIUM" if is_html else "LOW"
                findings.append(
                    self._make_finding(
                        "X-Frame-Options",
                        sev,
                        "Clickjacking protection is missing (no X-Frame-Options and no CSP frame-ancestors).",
                        "Add CSP frame-ancestors 'none'/'self' (preferred) or add X-Frame-Options: DENY/SAMEORIGIN.",
                        group="clickjacking",
                    )
                )
        else:
            val = xfo.strip().upper()
            if val not in ("DENY", "SAMEORIGIN"):
                findings.append(
                    self._make_finding(
                        "X-Frame-Options",
                        "LOW",
                        f"X-Frame-Options value '{xfo}' is not a recommended directive.",
                        "Use X-Frame-Options: DENY or SAMEORIGIN; prefer CSP frame-ancestors for modern control.",
                        group="clickjacking",
                    )
                )

        # ---- MIME sniffing ----
        xcto = self._get_header(headers_lc, "X-Content-Type-Options")
        if not xcto:
            sev = "MEDIUM" if (is_html or auth_ctx) else "LOW"
            findings.append(
                self._make_finding(
                    "X-Content-Type-Options",
                    sev,
                    "X-Content-Type-Options is missing. Without nosniff, some content-type confusion attacks are easier.",
                    "Add: X-Content-Type-Options: nosniff",
                    group="xcto",
                )
            )
        elif xcto.strip().lower() != "nosniff":
            findings.append(
                self._make_finding(
                    "X-Content-Type-Options",
                    "MEDIUM",
                    f"X-Content-Type-Options value '{xcto}' is not 'nosniff'.",
                    "Set: X-Content-Type-Options: nosniff",
                    group="xcto",
                )
            )

        # ---- Referrer-Policy + Permissions-Policy (dedup/group) ----
        missing_policy: List[str] = []
        refpol = self._get_header(headers_lc, "Referrer-Policy")
        if not refpol:
            missing_policy.append("Referrer-Policy")
        else:
            weak = refpol.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade")
            if weak:
                findings.append(
                    self._make_finding(
                        "Referrer-Policy",
                        "LOW",
                        f"Referrer-Policy '{refpol}' may leak more referrer data than necessary.",
                        "Prefer: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy).",
                        group="policy",
                    )
                )

        perm = self._get_header(headers_lc, "Permissions-Policy")
        if not perm:
            missing_policy.append("Permissions-Policy")

        if missing_policy:
            sev = "MEDIUM" if (is_html or auth_ctx) else "LOW"
            findings.append(
                self._make_finding(
                    "Missing Recommended Policies",
                    sev,
                    "Missing recommended policy headers: " + ", ".join(missing_policy) + ".",
                    "Add modern policy headers (e.g., Referrer-Policy: strict-origin-when-cross-origin; Permissions-Policy: camera=(), microphone=(), geolocation=()).",
                    group="policy_missing",
                )
            )

        # ---- Cross-origin isolation headers (only flag when relevant) ----
        coop = self._get_header(headers_lc, "Cross-Origin-Opener-Policy")
        coep = self._get_header(headers_lc, "Cross-Origin-Embedder-Policy")
        corp = self._get_header(headers_lc, "Cross-Origin-Resource-Policy")

        if coep:
            v = coep.strip().lower()
            if v not in ("require-corp", "credentialless"):
                findings.append(
                    self._make_finding(
                        "Cross-Origin-Embedder-Policy",
                        "MEDIUM",
                        f"COEP value '{coep}' is not a recognized isolation mode.",
                        "Use Cross-Origin-Embedder-Policy: require-corp (or credentialless) only if you need cross-origin isolation.",
                        group="cross_origin_isolation",
                    )
                )
            if not coop:
                findings.append(
                    self._make_finding(
                        "Cross-Origin-Opener-Policy",
                        "MEDIUM",
                        "COEP is set but COOP is missing; cross-origin isolation is incomplete (may break intended protections/features).",
                        "If you need cross-origin isolation, set Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp together.",
                        group="cross_origin_isolation",
                    )
                )
            if v == "require-corp" and not corp:
                findings.append(
                    self._make_finding(
                        "Cross-Origin-Resource-Policy",
                        "LOW",
                        "COEP require-corp is enabled but CORP is missing; some resource loads may not be protected/controlled as intended.",
                        "Consider setting Cross-Origin-Resource-Policy: same-site or same-origin for sensitive resources when using COEP.",
                        group="cross_origin_isolation",
                    )
                )
        elif coop:
            # COOP alone is often an optional hardening; don't over-score.
            findings.append(
                self._make_finding(
                    "Cross-Origin-Opener-Policy",
                    "INFO",
                    "COOP is present. Cross-origin isolation headers are optional unless you rely on SharedArrayBuffer / advanced isolation features.",
                    "No action required unless you need full cross-origin isolation (COOP + COEP).",
                    group="cross_origin_isolation",
                )
            )

        # ---- Deprecated X-XSS-Protection ----
        xxp = self._get_header(headers_lc, "X-XSS-Protection")
        if xxp:
            findings.append(
                self._make_finding(
                    "X-XSS-Protection",
                    "INFO",
                    "X-XSS-Protection is a deprecated header in modern browsers; relying on CSP and output encoding is preferred.",
                    "Consider removing it or explicitly disabling legacy behavior with: X-XSS-Protection: 0 (do not use as primary defense).",
                    group="deprecated",
                )
            )

        # ---- Info leaks (group) ----
        leaks: List[str] = []
        for hname, desc in INSECURE_HEADERS.items():
            v = self._get_header(headers_lc, hname)
            if v:
                leaks.append(f"{hname}: {v} ({desc})")
        if leaks:
            findings.append(
                self._make_finding(
                    "Information Disclosure",
                    "INFO",
                    "Informational headers exposed: " + "; ".join(leaks),
                    "Consider minimizing version/technology disclosure where practical (does not usually indicate direct exploitability by itself).",
                    group="info_leak",
                )
            )

        findings = self._dedupe_findings(findings)
        summary = self._summary_counts(findings)
        grade, grade_expl = self._grade_from_findings(findings, auth_ctx)

        risk_explanation = (
            f"Context: HTTPS={'yes' if is_https else 'no'}, HTML={'yes' if is_html else 'no'}, auth/sensitive={'yes' if auth_ctx else 'no'}. "
            f"Grade rationale: {grade_expl}"
        )

        return {
            "url": target_url,
            "grade": grade,
            "summary": summary,
            "findings": findings,
            "risk_explanation": risk_explanation,
            "_context": {"is_https": is_https, "is_html": is_html, "auth": auth_ctx},
        }

    def scan_url(self, target_url: str, timeout: int = 10, auth_session=None, scan_id: Optional[int] = None) -> Dict:
        try:
            logger.info(f"[Headers] Scanning: {target_url}")
            session = auth_session.session if auth_session else self.session
            vulnerabilities = []

            response = session.get(target_url, timeout=timeout, verify=False)

            # If we were redirected to a different site (or rate-limited), header analysis can become misleading.
            # Example: YouTube frequently redirects automated clients to Google "sorry" pages (429).
            try:
                orig_host = self._normalize_host(urllib.parse.urlparse(target_url).netloc)
                final_host = self._normalize_host(urllib.parse.urlparse(getattr(response, "url", "") or "").netloc)
            except Exception:
                orig_host, final_host = "", ""

            if response.status_code in (403, 429):
                return {
                    "success": True,
                    "target": target_url,
                    "url": target_url,
                    "timestamp": datetime.now().isoformat(),
                    "inconclusive": True,
                    "inconclusive_reason": f"Target blocked automated requests (HTTP {response.status_code}).",
                    "final_url": getattr(response, "url", None),
                    "grade": "N/A",
                    "summary": {"critical": 0, "medium": 0, "low": 0, "info": 0},
                    "findings": [],
                    "risk_explanation": "Scan inconclusive: target blocked automated requests; findings are suppressed to avoid false positives.",
                    "vulnerabilities": [],
                    "total_found": 0,
                    "headers": [],
                    "info_leaks": [],
                    "csp": None,
                    "csp_analysis": [],
                    "scan_time": "completed",
                }

            if orig_host and final_host and orig_host != final_host:
                return {
                    "success": True,
                    "target": target_url,
                    "url": target_url,
                    "timestamp": datetime.now().isoformat(),
                    "inconclusive": True,
                    "inconclusive_reason": f"Redirected to a different domain during scan ({final_host}).",
                    "final_url": getattr(response, "url", None),
                    "grade": "N/A",
                    "summary": {"critical": 0, "medium": 0, "low": 0, "info": 0},
                    "findings": [],
                    "risk_explanation": "Scan inconclusive: redirected to a different domain; findings are suppressed to avoid false positives.",
                    "vulnerabilities": [],
                    "total_found": 0,
                    "headers": [],
                    "info_leaks": [],
                    "csp": None,
                    "csp_analysis": [],
                    "scan_time": "completed",
                }

            if response.status_code >= 400:
                return {
                    "success": True,
                    "target": target_url,
                    "url": target_url,
                    "timestamp": datetime.now().isoformat(),
                    "inconclusive": True,
                    "inconclusive_reason": f"Target returned HTTP {response.status_code}; header scan may be incomplete.",
                    "final_url": getattr(response, "url", None),
                    "grade": "N/A",
                    "summary": {"critical": 0, "medium": 0, "low": 0, "info": 0},
                    "findings": [],
                    "risk_explanation": "Scan inconclusive: non-success HTTP response; findings are suppressed to avoid false positives.",
                    "vulnerabilities": [],
                    "total_found": 0,
                    "headers": [],
                    "info_leaks": [],
                    "csp": None,
                    "csp_analysis": [],
                    "scan_time": "completed",
                }

            resp_headers = response.headers

            analysis = self.analyze_headers(target_url, resp_headers)
            findings = analysis.get("findings", []) if isinstance(analysis, dict) else []
            summary = analysis.get("summary") if isinstance(analysis, dict) else None

            # Legacy compatibility: convert findings into the older `vulnerabilities` list.
            sev_map = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}
            for f in findings:
                vulnerabilities.append({
                    "type": "HTTP Security Header Finding",
                    "severity": sev_map.get((f.get("severity") or "INFO").upper(), "Medium"),
                    "parameter": f.get("header"),
                    "payload": "N/A",
                    "evidence": f.get("reason"),
                    "poc": target_url,
                    "cwe": "CWE-693",
                    "scan_type": "headers",
                    "recommendation": f.get("recommendation"),
                })

            # Avoid over-counting informational disclosures as vulnerabilities.
            total_findings = len(findings)
            total_found = 0
            if isinstance(summary, dict):
                try:
                    total_found = int(summary.get("critical", 0) or 0) + int(summary.get("medium", 0) or 0) + int(summary.get("low", 0) or 0)
                except Exception:
                    total_found = 0
            if not total_found:
                total_found = sum(1 for f in findings if (f.get("severity") or "INFO").upper() != "INFO")

            csp_value = resp_headers.get("Content-Security-Policy")
            info_leaks = []
            for header_name, description in INSECURE_HEADERS.items():
                value = resp_headers.get(header_name)
                if value:
                    info_leaks.append({
                        "header": header_name,
                        "value": value,
                        "description": description,
                    })

            return {
                "success": True,
                "target": target_url,
                "url": analysis.get("url", target_url),
                "timestamp": datetime.now().isoformat(),
                "grade": analysis.get("grade"),
                "summary": summary,
                "findings": findings,
                "risk_explanation": analysis.get("risk_explanation"),
                "vulnerabilities": vulnerabilities,
                "total_found": total_found,
                "total_findings": total_findings,
                "headers": list(resp_headers.items()),
                "info_leaks": info_leaks,
                "csp": csp_value,
                "scan_time": "completed",
            }

        except Exception as e:
            logger.error(f"[Headers] Error: {e}")
            return {"success": False, "error": str(e), "target": target_url}

    def scan_batch(self, urls: List[str], **kwargs) -> Dict:
        results = {"total_scanned": len(urls), "timestamp": datetime.now().isoformat(), "scans": []}
        for url in urls:
            results["scans"].append(self.scan_url(url, **kwargs))
        results["total_vulnerabilities"] = sum(s.get("total_found", 0) for s in results["scans"])
        return results
