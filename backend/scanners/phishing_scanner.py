"""
Phishing Scanner — checks URLs against public feeds (PhishTank, OpenPhish)
and runs heuristic analysis for brand impersonation and suspicious URLs.

API:
- PhishingScanner.check_url(url) -> dict

Design goals:
- Low false negatives for common real-world phishing URLs
- Reasonable false positive resistance via trusted-domain allowlist
- No network dependency for unit tests (background refresh can be disabled)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)

try:
    from ml.phishing_model import predict_probability, risk_from_probability
except Exception:  # pragma: no cover
    predict_probability = None
    risk_from_probability = None


COMMON_TWO_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "com.br",
    "com.mx",
    "co.jp",
    "co.kr",
    "com.sg",
    "com.tr",
    "com.sa",
    "com.ar",
}


TARGET_BRANDS = [
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "facebook",
    "netflix",
    "instagram",
    "whatsapp",
    "linkedin",
    "twitter",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "dropbox",
    "adobe",
    "dhl",
    "fedex",
    "usps",
    "irs",
    "coinbase",
    "binance",
    "metamask",
    "outlook",
    "yahoo",
    "aol",
]


SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".club",
    ".work",
    ".click",
    ".loan",
    ".win",
    ".racing",
    ".review",
    ".country",
    ".stream",
    ".gq",
    ".cf",
    ".tk",
    ".ml",
    ".ga",
    ".buzz",
    ".space",
    ".monster",
    ".icu",
    ".su",
    ".info",
    ".biz",
]


HOMOGLYPHS = {
    "a": ["а", "ạ", "ą", "à", "á", "â", "ã", "ä", "å", "ā"],
    "e": ["е", "ẹ", "ę", "è", "é", "ê", "ë", "ē"],
    "i": ["і", "ị", "ì", "í", "î", "ï", "ī"],
    "o": ["о", "ọ", "ö", "ò", "ó", "ô", "õ", "ō", "0"],
    "u": ["ụ", "ù", "ú", "û", "ü", "ū"],
    "l": ["1", "ⅼ", "ℓ", "|"],
    "n": ["ñ", "ń"],
    "c": ["ç", "ć"],
    "s": ["ś", "ş", "$"],
    "g": ["ğ"],
}


TRUSTED_DOMAINS = {
    "localhost",
    "google.com",
    "google.co.uk",
    "google.co.jp",
    "google.de",
    "google.fr",
    "google.co.in",
    "google.ca",
    "google.com.au",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "outlook.com",
    "amazon.com",
    "amazon.co.uk",
    "amazon.de",
    "amazon.co.jp",
    "amazon.in",
    "paypal.com",
    "paypal.me",
    "netflix.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "yahoo.com",
    "dropbox.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "citibank.com",
    "coinbase.com",
    "binance.com",
    "ebay.com",
    "walmart.com",
    "steampowered.com",
    "steamcommunity.com",
    "adobe.com",
    "github.com",
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "lnk.ink",
    "cutt.ly",
    "rebrand.ly",
    "is.gd",
    "s.id",
    "linktr.ee",
}


SUSPICIOUS_KEYWORDS_RE = re.compile(
    r"(login|signin|verify|verification|update|secure|account|support|billing|invoice|payment|wallet|password|bank)",
    re.IGNORECASE,
)


def _ensure_scheme(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return u
    parsed = urlparse(u)
    if parsed.scheme:
        return u
    return "https://" + u


def _extract_hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or "").lower().split(":")[0]


def _registrable_domain(hostname: str) -> str:
    host = (hostname or "").lower().strip("[]")
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host

    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in COMMON_TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return last_two


def _has_brand_boundary(text: str, brand: str) -> bool:
    if not text or not brand:
        return False
    # Treat '.', '-', '_' as boundaries (common in hostnames/paths).
    pattern = rf"(^|[\._\-]){re.escape(brand)}([\._\-]|$)"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def _hostname_is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address((hostname or "").strip("[]"))
        return True
    except Exception:
        return False


def _is_trusted_local_host(hostname: str) -> bool:
    normalized = (hostname or "").lower().strip("[]")
    if not normalized:
        return False

    if normalized == "localhost" or normalized.endswith(".localhost") or normalized == "::1":
        return True

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False

    return address.is_loopback or address.is_private or address.is_link_local


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        cur_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = cur_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            cur_row.append(min(insertions, deletions, substitutions))
        prev_row = cur_row

    return prev_row[-1]


def _normalize_url_for_feed(url: str) -> str:
    """Normalize URL for stable feed matching (best-effort, conservative)."""
    u = _ensure_scheme(url)
    parsed = urlparse(u)

    scheme = (parsed.scheme or "https").lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    netloc = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"

    path = parsed.path or ""
    query = parsed.query or ""

    # Common feed variance: treat trailing slash as equivalent when no query.
    if query == "" and path.endswith("/") and path != "/":
        path = path.rstrip("/")

    # Strip fragment.
    return urlunparse((scheme, netloc, path, "", query, ""))


def _feed_variants(url: str) -> Set[str]:
    normalized = _normalize_url_for_feed(url)
    variants: Set[str] = {normalized}

    parsed = urlparse(normalized)

    # http <-> https variants
    if parsed.scheme == "https":
        variants.add(urlunparse(("http", parsed.netloc, parsed.path, "", parsed.query, "")))
    elif parsed.scheme == "http":
        variants.add(urlunparse(("https", parsed.netloc, parsed.path, "", parsed.query, "")))

    # without query
    if parsed.query:
        variants.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", "")))

    return variants


class PhishingScanner:
    """Detects phishing via public feeds + heuristic analysis."""

    def __init__(self, cache_file: Optional[str] = None, *, enable_background_refresh: bool = True):
        from config import PHISHING_CACHE_FILE

        self.cache_file = cache_file or PHISHING_CACHE_FILE
        self.feed_urls: Set[str] = set()
        self.feed_hostnames: Set[str] = set()
        self.last_update: float = 0
        self._lock = threading.Lock()

        self._load_cache()
        if enable_background_refresh:
            self._start_feed_refresh()

    def _rebuild_feed_index(self) -> None:
        hostnames: Set[str] = set()
        for u in self.feed_urls:
            try:
                host = _extract_hostname(_ensure_scheme(u))
                if host:
                    hostnames.add(host)
            except Exception:
                continue
        self.feed_hostnames = hostnames

    def _load_cache(self) -> None:
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cached = data.get("urls", [])
                    self.feed_urls = {
                        _normalize_url_for_feed(u)
                        for u in cached
                        if isinstance(u, str) and u.strip()
                    }
                    self.last_update = float(data.get("last_update", 0) or 0)
                    self._rebuild_feed_index()
                    logger.info(f"[Phishing] Loaded {len(self.feed_urls)} cached URLs")
        except Exception as e:
            logger.error(f"[Phishing] Failed to load cache: {e}")

    def _save_cache(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "urls": list(self.feed_urls)[:100000],
                        "last_update": self.last_update,
                    },
                    f,
                )
            logger.info(f"[Phishing] Saved {len(self.feed_urls)} URLs to cache")
        except Exception as e:
            logger.error(f"[Phishing] Failed to save cache: {e}")

    def _fetch_feeds(self) -> None:
        new_urls: Set[str] = set()

        # OpenPhish (plain text, one URL per line)
        try:
            resp = requests.get("https://openphish.com/feed.txt", timeout=30)
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    u = line.strip()
                    if u.startswith("http"):
                        new_urls.add(_normalize_url_for_feed(u))
                logger.info(f"[Phishing] Fetched {len(new_urls)} URLs from OpenPhish")
        except Exception as e:
            logger.warning(f"[Phishing] OpenPhish fetch failed: {e}")

        # PhishTank (JSON format — may require API key for full access)
        try:
            resp = requests.get(
                "http://data.phishtank.com/data/online-valid.json",
                timeout=60,
                headers={"User-Agent": "phishtank/SecureScan"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    u = entry.get("url", "")
                    if isinstance(u, str) and u.strip():
                        new_urls.add(_normalize_url_for_feed(u))
                logger.info(f"[Phishing] Fetched {len(data)} entries from PhishTank")
        except Exception as e:
            logger.warning(f"[Phishing] PhishTank fetch failed: {e}")

        if new_urls:
            with self._lock:
                self.feed_urls = new_urls
                self.last_update = time.time()
                self._rebuild_feed_index()
            self._save_cache()

    def _start_feed_refresh(self) -> None:
        def refresh_loop() -> None:
            while True:
                try:
                    if time.time() - self.last_update > 6 * 3600 or len(self.feed_urls) == 0:
                        logger.info("[Phishing] Refreshing feeds...")
                        self._fetch_feeds()
                except Exception as e:
                    logger.error(f"[Phishing] Feed refresh error: {e}")
                time.sleep(3600)

        threading.Thread(target=refresh_loop, daemon=True).start()

    # ── Heuristic checks ─────────────────────────────────────────

    def _is_trusted_domain(self, url: str) -> bool:
        try:
            hostname = _extract_hostname(_ensure_scheme(url))
            if _is_trusted_local_host(hostname):
                return True
            for trusted in TRUSTED_DOMAINS:
                if hostname == trusted or hostname.endswith("." + trusted):
                    return True
        except Exception:
            pass
        return False

    def _check_feed(self, url: str) -> bool:
        variants = _feed_variants(url)
        with self._lock:
            if any(v in self.feed_urls for v in variants):
                return True
        return False

    def _check_brand_impersonation(self, url: str) -> List[Dict]:
        issues: List[Dict] = []
        parsed = urlparse(_ensure_scheme(url))
        domain = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()

        if _is_trusted_local_host(domain):
            return issues

        parts = [p for p in domain.split(".") if p]
        main_domain = _registrable_domain(domain)
        domain_base = main_domain.split(".")[0] if "." in main_domain else main_domain
        subdomain_part = ""
        if domain and main_domain and domain.endswith(main_domain) and domain != main_domain:
            subdomain_part = domain[: -(len(main_domain) + 1)]

        path_and_query = (parsed.path or "") + "?" + (parsed.query or "")
        has_lure_keywords = SUSPICIOUS_KEYWORDS_RE.search(path_and_query) is not None

        for brand in TARGET_BRANDS:
            # Brand in subdomain of a non-brand registrable domain (stronger when brand is boundary-delimited).
            if brand in domain and brand not in main_domain:
                sev = "High" if _has_brand_boundary(subdomain_part, brand) else "Medium"
                issues.append(
                    {
                        "type": "brand_in_subdomain",
                        "brand": brand,
                        "severity": sev,
                        "detail": f"Brand '{brand}' found in subdomain of {main_domain}",
                    }
                )

            # Brand references in path are common on legitimate sites; only flag if combined with lure keywords.
            if has_lure_keywords and brand in path and brand not in domain:
                issues.append(
                    {
                        "type": "brand_in_path",
                        "brand": brand,
                        "severity": "Low",
                        "detail": "Brand in URL path but not domain (with lure keywords present)",
                    }
                )

            dist = _levenshtein(brand, domain_base)
            if 0 < dist <= 2 and len(domain_base) >= 4:
                issues.append(
                    {
                        "type": "lookalike_domain",
                        "brand": brand,
                        "severity": "High",
                        "detail": f"Domain '{domain_base}' is similar to '{brand}' (distance: {dist})",
                    }
                )

        return issues

    def _check_homoglyphs(self, url: str) -> List[Dict]:
        domain = _extract_hostname(_ensure_scheme(url))
        issues: List[Dict] = []

        if _is_trusted_local_host(domain):
            return issues

        for char, lookalikes in HOMOGLYPHS.items():
            for glyph in lookalikes:
                if glyph in domain:
                    issues.append(
                        {
                            "type": "homoglyph",
                            "detail": f"Suspicious character '{glyph}' (looks like '{char}') in domain",
                        }
                    )
        return issues

    def _check_suspicious_tld(self, url: str) -> Optional[Dict]:
        domain = _extract_hostname(_ensure_scheme(url))
        if _is_trusted_local_host(domain):
            return None
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return {"type": "suspicious_tld", "detail": f"Domain uses suspicious TLD: {tld}"}
        return None

    def _check_url_entropy(self, url: str) -> Optional[Dict]:
        parsed = urlparse(_ensure_scheme(url))
        path_and_query = (parsed.path or "") + (parsed.query or "")
        if len(path_and_query) > 100:
            return {"type": "long_url", "detail": f"URL path is unusually long ({len(path_and_query)} chars)"}

        special_count = sum(1 for c in path_and_query if c in "-_~!@#$%^&*()")
        if special_count > 10:
            return {"type": "obfuscated_url", "detail": f"URL contains many special characters ({special_count})"}
        return None

    def _check_ip_address(self, url: str) -> Optional[Dict]:
        domain = _extract_hostname(_ensure_scheme(url))
        if _is_trusted_local_host(domain):
            return None
        try:
            ipaddress.ip_address(domain.strip("[]"))
            return {"type": "ip_address", "detail": "URL uses raw IP address instead of a domain name"}
        except Exception:
            return None

    def _check_at_symbol(self, url: str) -> Optional[Dict]:
        u = (url or "").strip().lower()
        if "@" in u and not u.startswith("mailto:"):
            return {"type": "at_symbol", "detail": "URL contains '@' which can disguise the real destination"}
        return None

    def _check_excessive_subdomains(self, url: str) -> Optional[Dict]:
        domain = _extract_hostname(_ensure_scheme(url))
        if _is_trusted_local_host(domain):
            return None
        parts = [p for p in domain.split(".") if p]
        if len(parts) > 4:
            return {"type": "excessive_subdomains", "detail": f"Hostname has many subdomains ({len(parts)} levels)"}
        return None

    def _check_no_https(self, url: str) -> Optional[Dict]:
        parsed = urlparse(_ensure_scheme(url))
        domain = (parsed.hostname or "").lower()
        if _is_trusted_local_host(domain):
            return None
        if (parsed.scheme or "").lower() == "http":
            return {"type": "no_https", "detail": "URL uses HTTP (not encrypted)"}
        return None

    def _check_punycode(self, url: str) -> Optional[Dict]:
        domain = _extract_hostname(_ensure_scheme(url))
        if _is_trusted_local_host(domain):
            return None
        if "xn--" in domain:
            return {"type": "punycode", "detail": "Domain contains punycode (xn--) which is often used for lookalikes"}
        return None

    def _check_suspicious_keywords(self, url: str) -> Optional[Dict]:
        parsed = urlparse(_ensure_scheme(url))
        text = (parsed.path or "") + "?" + (parsed.query or "")
        if SUSPICIOUS_KEYWORDS_RE.search(text):
            return {"type": "suspicious_keywords", "detail": "URL contains common phishing lure keywords (login/verify/update/etc.)"}
        return None

    def _check_shortener_domain(self, url: str) -> Optional[Dict]:
        domain = _extract_hostname(_ensure_scheme(url))
        if domain in SHORTENER_DOMAINS:
            return {"type": "url_shortener", "detail": f"URL uses a shortening domain ({domain}) which is frequently abused"}
        return None

    def _calculate_score(
        self,
        *,
        in_feed: bool,
        brand_issues: List[Dict],
        homoglyph_issues: List[Dict],
        tld_issue: Optional[Dict],
        entropy_issue: Optional[Dict],
        ip_issue: Optional[Dict],
        at_issue: Optional[Dict],
        subdomain_issue: Optional[Dict],
        https_issue: Optional[Dict],
        punycode_issue: Optional[Dict],
        keyword_issue: Optional[Dict],
        shortener_issue: Optional[Dict],
    ) -> int:
        score = 0
        if in_feed:
            score += 80

        # Brand indicators vary in strength; keep scoring conservative to reduce false positives.
        for bi in brand_issues:
            sev = (bi.get("severity") or "Medium").lower()
            if sev == "high":
                score += 18
            elif sev == "medium":
                score += 10
            else:
                score += 5
        score += len(homoglyph_issues) * 25

        if tld_issue:
            score += 15
        if entropy_issue:
            score += 6
        if ip_issue:
            score += 20
        if at_issue:
            score += 20
        if subdomain_issue:
            score += 6
        if https_issue:
            score += 6
        if punycode_issue:
            score += 20
        if keyword_issue:
            score += 5
        if shortener_issue:
            score += 12

        return min(score, 100)

    # ── Main scan ─────────────────────────────────────────────────

    def check_url(self, url: str, scan_id: Optional[int] = None) -> Dict:
        try:
            parsed = urlparse(_ensure_scheme(url))
            scheme = (parsed.scheme or "").lower()
            hostname = (parsed.hostname or "").lower()

            def _ml_reasons_text(p: Optional[float], level: Optional[str], err: Optional[str]) -> List[str]:
                if p is not None:
                    return [f"ML phishing probability: {p:.4f} (risk={level})"]
                if err:
                    return [f"ML unavailable: {err}"]
                return []

            # Internal/private hosts are not meaningfully scannable for phishing intent.
            if _is_trusted_local_host(hostname):
                ml_probability = None
                ml_risk_level = None
                ml_error = "skipped_internal"
                return {
                    "success": True,
                    "target": url,
                    "timestamp": datetime.now().isoformat(),
                    "safe": True,
                    "risk_level": "INTERNAL",
                    "scannable": False,
                    "score": 0,
                    "reasons": [],
                    "feed_match": False,
                    "feed_size": len(self.feed_urls),
                    "feed_last_update": datetime.fromtimestamp(self.last_update).isoformat() if self.last_update else "never",
                    "vulnerabilities": [],
                    "total_found": 0,
                    "url": url,
                    "ml_probability": ml_probability,
                    "ml_risk_level": ml_risk_level,
                    "ml_error": ml_error,
                    "reasons_text": _ml_reasons_text(ml_probability, ml_risk_level, ml_error),
                }

            # Always check the phishing feed first.
            in_feed = self._check_feed(url)

            # Context guard: for raw-IP hosts (non-blacklisted), do not allow ML alone to mark HIGH.
            # These URLs are common in internal/test setups and are a frequent FP source.
            host_is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname.strip("[]")))

            # ML prediction (optional). Never trains at request-time.
            ml_probability = None
            ml_risk_level = None
            ml_error = None
            ml_note = None
            if callable(predict_probability) and callable(risk_from_probability) and not in_feed:
                ml_probability, ml_error = predict_probability(url, timeout=10)
                ml_risk_level = risk_from_probability(ml_probability)
                if host_is_ip and ml_risk_level == "HIGH":
                    ml_risk_level = "MEDIUM"
                    ml_note = "Context rule: raw IP host → ML HIGH capped to MEDIUM"
            elif in_feed:
                ml_probability = 1.0
                ml_risk_level = "HIGH"

            if scheme not in ("http", "https") or not hostname:
                reasons_text = _ml_reasons_text(ml_probability, ml_risk_level, ml_error)
                if ml_note:
                    reasons_text.append(ml_note)
                return {
                    "success": True,
                    "target": url,
                    "timestamp": datetime.now().isoformat(),
                    "safe": True,
                    "risk_level": "INVALID",
                    "scannable": False,
                    "score": 0,
                    "reasons": [],
                    "feed_match": False,
                    "feed_size": len(self.feed_urls),
                    "feed_last_update": datetime.fromtimestamp(self.last_update).isoformat() if self.last_update else "never",
                    "vulnerabilities": [],
                    "total_found": 0,
                    "url": url,
                    "ml_probability": ml_probability,
                    "ml_risk_level": ml_risk_level,
                    "ml_error": ml_error,
                    "reasons_text": reasons_text,
                }

            if not in_feed and self._is_trusted_domain(url):
                reasons_text = _ml_reasons_text(ml_probability, ml_risk_level, ml_error)
                if ml_note:
                    reasons_text.append(ml_note)
                return {
                    "success": True,
                    "target": url,
                    "timestamp": datetime.now().isoformat(),
                    "safe": True,
                    "risk_level": "SAFE",
                    "scannable": True,
                    "score": 0,
                    "reasons": [],
                    "feed_match": False,
                    "feed_size": len(self.feed_urls),
                    "feed_last_update": datetime.fromtimestamp(self.last_update).isoformat() if self.last_update else "never",
                    "vulnerabilities": [],
                    "total_found": 0,
                    "url": url,
                    "ml_probability": ml_probability,
                    "ml_risk_level": ml_risk_level,
                    "ml_error": ml_error,
                    "reasons_text": reasons_text,
                }

            host_is_ip = _hostname_is_ip(hostname)

            # Signals are confidence-weighted and context-filtered.
            # High = 4, Medium = 2, Low = 1
            signals: List[Dict[str, str]] = []
            total_points = 0
            high_count = 0
            medium_count = 0
            low_count = 0

            def add_signal(*, confidence: str, points: int, severity: str, detail: str) -> None:
                nonlocal total_points, high_count, medium_count, low_count
                total_points += points
                if confidence == "high":
                    high_count += 1
                elif confidence == "medium":
                    medium_count += 1
                else:
                    low_count += 1
                signals.append({"severity": severity, "detail": detail, "confidence": confidence, "points": str(points)})

            if in_feed:
                add_signal(confidence="high", points=8, severity="Critical", detail="URL found in known phishing feed")

            # Low-confidence technical imperfections (never decide phishing alone)
            https_issue = self._check_no_https(url)
            if https_issue:
                add_signal(confidence="low", points=1, severity="Low", detail=https_issue["detail"])

            ip_issue = self._check_ip_address(url)
            if ip_issue:
                add_signal(confidence="low", points=1, severity="Low", detail=ip_issue["detail"])

            # Context: public IP hosts with non-root paths are often used for disposable phishing drop zones.
            # Keep this as LOW confidence to avoid false positives.
            if host_is_ip:
                path = parsed.path or ""
                if path and path not in ("/", ""):
                    add_signal(
                        confidence="low",
                        points=1,
                        severity="Low",
                        detail="URL uses a public IP address with a non-root path",
                    )

            entropy_issue = self._check_url_entropy(url)
            if entropy_issue:
                add_signal(confidence="medium", points=2, severity="Medium", detail=entropy_issue["detail"])

            keyword_issue = self._check_suspicious_keywords(url)
            if keyword_issue:
                add_signal(confidence="medium", points=2, severity="Medium", detail=keyword_issue["detail"])

            shortener_issue = self._check_shortener_domain(url)
            if shortener_issue:
                add_signal(confidence="medium", points=2, severity="Medium", detail=shortener_issue["detail"])

            at_issue = self._check_at_symbol(url)
            if at_issue:
                add_signal(confidence="high", points=4, severity="High", detail=at_issue["detail"])

            # Context rule: IP hosts are not domains — skip domain-based checks.
            if not host_is_ip:
                punycode_issue = self._check_punycode(url)
                if punycode_issue:
                    add_signal(confidence="medium", points=2, severity="Medium", detail=punycode_issue["detail"])

                homoglyph_issues = self._check_homoglyphs(url)
                for issue in homoglyph_issues:
                    add_signal(confidence="high", points=4, severity="High", detail=issue["detail"])

                tld_issue = self._check_suspicious_tld(url)
                if tld_issue:
                    add_signal(confidence="medium", points=2, severity="Medium", detail=tld_issue["detail"])

                subdomain_issue = self._check_excessive_subdomains(url)
                if subdomain_issue:
                    add_signal(confidence="medium", points=2, severity="Medium", detail=subdomain_issue["detail"])

                brand_issues = self._check_brand_impersonation(url)
                for issue in brand_issues:
                    sev = (issue.get("severity") or "Medium")
                    if sev.lower() == "high":
                        add_signal(confidence="high", points=4, severity="High", detail=issue["detail"])
                    elif sev.lower() == "low":
                        add_signal(confidence="low", points=1, severity="Low", detail=issue["detail"])
                    else:
                        add_signal(confidence="medium", points=2, severity="Medium", detail=issue["detail"])

            # Multi-signal guard to reduce ML-only false positives:
            # If there are no rule-based signals at all, don't escalate purely based on ML.
            if not in_feed and not signals and ml_risk_level in ("HIGH", "MEDIUM"):
                ml_risk_level = "MEDIUM" if ml_risk_level == "HIGH" else "LOW"

            # Hybrid decision logic:
            # - If blacklisted/feed hit => HIGH immediately (phishing)
            # - Else ML probability drives LOW/MEDIUM/HIGH risk level
            # - Rule-based signals remain in the response for explainability
            if in_feed:
                risk_level = "PHISHING"
            else:
                if ml_risk_level == "HIGH":
                    risk_level = "PHISHING"
                elif ml_risk_level == "MEDIUM":
                    risk_level = "SUSPICIOUS"
                else:
                    # If ML unavailable/LOW, fall back to rule-based suspicion.
                    if high_count >= 1:
                        risk_level = "PHISHING"
                    elif medium_count >= 2 and (low_count >= 1 or medium_count >= 3):
                        risk_level = "SUSPICIOUS"
                    elif low_count >= 3:
                        risk_level = "SUSPICIOUS"
                    elif total_points >= 4:
                        risk_level = "SUSPICIOUS"
                    else:
                        risk_level = "SAFE"

            # Map points to a 0-100 score.
            score = min(100, total_points * 10)
            if risk_level == "PHISHING":
                score = max(score, 80)
            elif risk_level == "SAFE":
                score = min(score, 30)
            elif risk_level in ("INVALID", "INTERNAL"):
                score = 0

            result = self._format_result(url, in_feed, score, signals, risk_level=risk_level, scannable=True)
            result["url"] = url
            result["ml_probability"] = ml_probability
            result["ml_risk_level"] = ml_risk_level
            result["ml_error"] = ml_error
            # Human-friendly combined reasons for API clients that want strings.
            combined_reasons = [s.get("detail") for s in signals if isinstance(s, dict) and s.get("detail")]
            if ml_probability is not None:
                combined_reasons.append(f"ML phishing probability: {ml_probability:.4f} (risk={ml_risk_level})")
            elif ml_error:
                combined_reasons.append(f"ML unavailable: {ml_error}")
            if ml_note:
                combined_reasons.append(ml_note)
            result["reasons_text"] = combined_reasons
            # Keep required keys at top-level of result object.
            result["risk_level_ml"] = ml_risk_level
            return result

        except Exception as e:
            logger.error(f"[Phishing] Error checking {url}: {e}")
            return {"success": False, "error": str(e), "target": url}

    def _format_result(
        self,
        url: str,
        in_feed: bool,
        score: int,
        reasons: List[Dict[str, str]],
        *,
        risk_level: str = "SAFE",
        scannable: bool = True,
    ) -> Dict:
        safe = risk_level in ("SAFE", "INTERNAL")

        return {
            "success": True,
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "safe": safe,
            "risk_level": risk_level,
            "scannable": scannable,
            "score": score,
            "reasons": reasons,
            "feed_match": in_feed,
            "feed_size": len(self.feed_urls),
            "feed_last_update": datetime.fromtimestamp(self.last_update).isoformat() if self.last_update else "never",
            "vulnerabilities": [
                {
                    "type": "Phishing",
                    "severity": r["severity"],
                    "parameter": "URL",
                    "payload": "N/A",
                    "evidence": r["detail"],
                    "poc": url,
                    "cwe": "CWE-451",
                    "scan_type": "phishing",
                }
                for r in reasons
            ],
            "total_found": len(reasons),
        }
