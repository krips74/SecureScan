from __future__ import annotations

import math
import re
import socket
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "support",
    "billing",
    "invoice",
    "payment",
    "wallet",
    "password",
    "bank",
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

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "club",
    "work",
    "click",
    "loan",
    "win",
    "racing",
    "review",
    "country",
    "stream",
    "gq",
    "cf",
    "tk",
    "ml",
    "ga",
    "buzz",
    "space",
    "monster",
    "icu",
    "su",
    "info",
    "biz",
}

TARGET_BRANDS = {
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
}


def _is_ip(hostname: str) -> bool:
    if not hostname:
        return False
    host = hostname.strip("[]")
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))


def _count_digits(s: str) -> int:
    return sum(1 for c in s if c.isdigit())


def _words_from_url(url: str) -> list[str]:
    # Split into tokens commonly used in URL feature sets.
    parts = re.split(r"[^A-Za-z0-9]+", url)
    return [p for p in parts if p]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _get_domain_parts(hostname: str) -> Tuple[str, str]:
    # Returns (domain, tld)
    if not hostname:
        return "", ""
    parts = [p for p in hostname.lower().split(".") if p]
    if len(parts) < 2:
        return hostname.lower(), ""
    return ".".join(parts[-2:]), parts[-1]


@dataclass
class PageFetchResult:
    final_url: str
    html: str
    status_code: int
    redirects: int


def fetch_page(url: str, timeout: int = 10) -> Optional[PageFetchResult]:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "SecureScan"})
        return PageFetchResult(
            final_url=str(resp.url),
            html=resp.text or "",
            status_code=int(resp.status_code),
            redirects=len(resp.history or []),
        )
    except Exception:
        return None


def extract_features(url: str, feature_columns: Iterable[str], *, timeout: int = 10) -> Dict[str, float]:
    """Best-effort feature extraction for the dataset_phishing.csv feature set.

    Notes:
    - Some dataset fields rely on external services (whois, traffic, pagerank). For stability,
      this extractor uses safe fallbacks (-1 or 0) when information isn't available.
    - Feature values are numeric; missing values default to -1.
    """

    cols = list(feature_columns)
    out: Dict[str, float] = {c: float("nan") for c in cols}

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    netloc = parsed.netloc or ""

    full = url
    host_len = len(hostname)

    domain, tld = _get_domain_parts(hostname)
    subdomains = hostname.split(".")[:-2] if hostname.count(".") >= 2 else []

    # URL lexical counts
    out.update(
        {
            "length_url": float(len(full)),
            "length_hostname": float(host_len),
            "ip": float(1 if _is_ip(hostname) else 0),
            "nb_dots": float(full.count(".")),
            "nb_hyphens": float(full.count("-")),
            "nb_at": float(full.count("@")),
            "nb_qm": float(full.count("?")),
            "nb_and": float(full.count("&")),
            "nb_or": float(full.lower().count("or")),
            "nb_eq": float(full.count("=")),
            "nb_underscore": float(full.count("_")),
            "nb_tilde": float(full.count("~")),
            "nb_percent": float(full.count("%")),
            "nb_slash": float(full.count("/")),
            "nb_star": float(full.count("*")),
            "nb_colon": float(full.count(":")),
            "nb_comma": float(full.count(",")),
            "nb_semicolumn": float(full.count(";")),
            "nb_dollar": float(full.count("$")),
            "nb_space": float(full.count(" ")),
            "nb_www": float(1 if "www" in hostname else 0),
            "nb_com": float(1 if hostname.endswith(".com") else 0),
            "nb_dslash": float(full.count("//") - 1 if "//" in full else 0),
            "http_in_path": float(1 if "http" in path.lower() else 0),
            "https_token": float(1 if "https" in full.lower().replace("https://", "") else 0),
            "ratio_digits_url": float(_count_digits(full) / max(1, len(full))),
            "ratio_digits_host": float(_count_digits(hostname) / max(1, len(hostname))),
            "punycode": float(1 if "xn--" in hostname else 0),
            "port": float(1 if ":" in netloc and parsed.port else 0),
            "tld_in_path": float(1 if tld and tld in path.lower() else 0),
            "tld_in_subdomain": float(1 if tld and any(tld == sd for sd in subdomains) else 0),
            "abnormal_subdomain": float(1 if any(sd in {"com", "net", "org"} for sd in subdomains) else 0),
            "nb_subdomains": float(len(subdomains)),
            "prefix_suffix": float(1 if "-" in domain.split(".")[0] else 0),
            "random_domain": float(1 if _entropy(domain) > 3.5 else 0),
            "shortening_service": float(1 if hostname in SHORTENER_DOMAINS else 0),
            "path_extension": float(1 if re.search(r"\.[a-zA-Z0-9]{1,6}$", path) else 0),
        }
    )

    # Word-based features
    words = _words_from_url(full)
    if words:
        lengths = [len(w) for w in words]
        out["length_words_raw"] = float(len(words))
        out["shortest_words_raw"] = float(min(lengths))
        out["longest_words_raw"] = float(max(lengths))
        out["avg_words_raw"] = float(sum(lengths) / len(lengths))
        out["char_repeat"] = float(sum(1 for w in words if len(set(w)) <= max(1, len(w) // 3)))
    else:
        out["length_words_raw"] = 0.0
        out["shortest_words_raw"] = 0.0
        out["longest_words_raw"] = 0.0
        out["avg_words_raw"] = 0.0
        out["char_repeat"] = 0.0

    host_words = _words_from_url(hostname)
    if host_words:
        out["shortest_word_host"] = float(min(len(w) for w in host_words))
        out["longest_word_host"] = float(max(len(w) for w in host_words))
        out["avg_word_host"] = float(sum(len(w) for w in host_words) / len(host_words))
    else:
        out["shortest_word_host"] = 0.0
        out["longest_word_host"] = 0.0
        out["avg_word_host"] = 0.0

    path_words = _words_from_url(path)
    if path_words:
        out["shortest_word_path"] = float(min(len(w) for w in path_words))
        out["longest_word_path"] = float(max(len(w) for w in path_words))
        out["avg_word_path"] = float(sum(len(w) for w in path_words) / len(path_words))
    else:
        out["shortest_word_path"] = 0.0
        out["longest_word_path"] = 0.0
        out["avg_word_path"] = 0.0

    # Hint/brand features
    lower_full = full.lower()
    out["phish_hints"] = float(sum(1 for w in SUSPICIOUS_WORDS if w in lower_full))
    out["domain_in_brand"] = float(1 if any(b in domain for b in TARGET_BRANDS) else 0)
    out["brand_in_subdomain"] = float(1 if any(b in ".".join(subdomains) for b in TARGET_BRANDS) else 0)
    out["brand_in_path"] = float(1 if any(b in path.lower() for b in TARGET_BRANDS) else 0)
    out["suspecious_tld"] = float(1 if tld in SUSPICIOUS_TLDS else 0)

    # DNS record
    try:
        socket.gethostbyname(hostname)
        out["dns_record"] = 1.0
    except Exception:
        out["dns_record"] = 0.0

    # Page-based signals (best-effort)
    page = fetch_page(url, timeout=timeout)
    if page:
        out["nb_redirection"] = float(page.redirects)
        final_host = (urlparse(page.final_url).hostname or "").lower()
        out["nb_external_redirection"] = float(1 if final_host and final_host != hostname else 0)

        soup = BeautifulSoup(page.html, "html.parser")

        # Title features
        title = (soup.title.string.strip() if soup.title and soup.title.string else "")
        out["empty_title"] = float(1 if not title else 0)
        out["domain_in_title"] = float(1 if domain and domain.split(".")[0] in title.lower() else 0)
        out["domain_with_copyright"] = float(1 if ("copyright" in page.html.lower() and domain.split(".")[0] in page.html.lower()) else 0)

        # Hyperlinks
        links = [a.get("href") for a in soup.find_all("a")]
        links = [h.strip() for h in links if isinstance(h, str)]
        total_links = len(links)
        null_links = sum(1 for h in links if h in ("#", "") or h.lower().startswith("javascript") or h.lower().startswith("mailto:"))

        def is_internal(href: str) -> bool:
            if href.startswith("/"):
                return True
            ph = urlparse(href)
            if not ph.hostname:
                return True
            return (ph.hostname or "").lower().endswith(hostname)

        int_links = sum(1 for h in links if is_internal(h))
        ext_links = total_links - int_links

        out["nb_hyperlinks"] = float(total_links)
        if total_links > 0:
            out["ratio_intHyperlinks"] = float(int_links / total_links)
            out["ratio_extHyperlinks"] = float(ext_links / total_links)
            out["ratio_nullHyperlinks"] = float(null_links / total_links)
        else:
            out["ratio_intHyperlinks"] = 0.0
            out["ratio_extHyperlinks"] = 0.0
            out["ratio_nullHyperlinks"] = 0.0

        # External CSS
        css_links = soup.find_all("link", rel=lambda v: v and "stylesheet" in v)
        ext_css = 0
        for l in css_links:
            href = l.get("href")
            if not isinstance(href, str) or not href.strip():
                continue
            ph = urlparse(href)
            if ph.hostname and hostname and (ph.hostname.lower() != hostname):
                ext_css += 1
        out["nb_extCSS"] = float(ext_css)

        # Login form
        forms = soup.find_all("form")
        has_password = bool(soup.find("input", {"type": "password"}))
        out["login_form"] = float(1 if (forms and has_password) else 0)

        # External favicon
        icon = soup.find("link", rel=lambda v: v and "icon" in v)
        if icon and isinstance(icon.get("href"), str):
            ph = urlparse(icon.get("href"))
            out["external_favicon"] = float(1 if ph.hostname and ph.hostname.lower() != hostname else 0)
        else:
            out["external_favicon"] = 0.0

        # Media ratios
        media_srcs = []
        for tag in soup.find_all(["img", "audio", "video", "source"]):
            src = tag.get("src")
            if isinstance(src, str) and src.strip():
                media_srcs.append(src.strip())
        total_media = len(media_srcs)
        int_media = sum(1 for s in media_srcs if is_internal(s))
        ext_media = total_media - int_media
        if total_media > 0:
            out["ratio_intMedia"] = float(int_media / total_media * 100)
            out["ratio_extMedia"] = float(ext_media / total_media * 100)
        else:
            out["ratio_intMedia"] = 0.0
            out["ratio_extMedia"] = 0.0

        # Iframe
        out["iframe"] = float(1 if soup.find("iframe") else 0)

        # Popup window / onmouseover / right click
        html_lower = page.html.lower()
        out["popup_window"] = float(1 if "window.open" in html_lower else 0)
        out["onmouseover"] = float(1 if "onmouseover" in html_lower else 0)
        out["right_clic"] = float(1 if "oncontextmenu" in html_lower else 0)

        # Safe anchor (%)
        if total_links > 0:
            safe = sum(1 for h in links if h and not (h in ("#", "") or h.lower().startswith("javascript")))
            out["safe_anchor"] = float(safe / total_links * 100)
        else:
            out["safe_anchor"] = 0.0

        # SFH (simplified)
        sfh_val = 0.0
        for f in forms:
            action = f.get("action")
            if not isinstance(action, str) or not action.strip() or action.strip().lower() in ("about:blank", "#"):
                sfh_val = max(sfh_val, 1.0)
                continue
            ah = urlparse(action).hostname
            if ah and hostname and ah.lower() != hostname:
                sfh_val = max(sfh_val, 2.0)
        out["sfh"] = float(sfh_val)

        # Submit to email
        submit_email = 0.0
        for f in forms:
            action = f.get("action")
            if isinstance(action, str) and action.lower().startswith("mailto:"):
                submit_email = 1.0
        out["submit_email"] = float(submit_email)

        # links_in_tags (simplified: count link/src/href in meta/script/link tags)
        tag_links = 0
        for tag in soup.find_all(["meta", "script", "link"]):
            for attr in ("content", "src", "href"):
                v = tag.get(attr)
                if isinstance(v, str) and v.strip():
                    if "http" in v.lower() or v.startswith("/"):
                        tag_links += 1
        out["links_in_tags"] = float(tag_links)

        # Placeholders for features that require heavier infra/services.
        # Keep as NaN so the model's imputer can fill a reasonable median.
        out.setdefault("statistical_report", float("nan"))
        out.setdefault("google_index", float("nan"))
        out.setdefault("page_rank", float("nan"))
        out.setdefault("web_traffic", float("nan"))
        out.setdefault("whois_registered_domain", float("nan"))
        out.setdefault("domain_registration_length", float("nan"))
        out.setdefault("domain_age", float("nan"))
        out.setdefault("domain_in_title", out.get("domain_in_title", 0.0))
    else:
        out["nb_redirection"] = 0.0
        out["nb_external_redirection"] = 0.0
        out["nb_hyperlinks"] = 0.0
        out["ratio_intHyperlinks"] = 0.0
        out["ratio_extHyperlinks"] = 0.0
        out["ratio_nullHyperlinks"] = 0.0
        out["nb_extCSS"] = 0.0
        out["ratio_intMedia"] = 0.0
        out["ratio_extMedia"] = 0.0
        out["login_form"] = 0.0
        out["external_favicon"] = 0.0
        out["links_in_tags"] = 0.0
        out["submit_email"] = 0.0
        out["sfh"] = 0.0
        out["iframe"] = 0.0
        out["popup_window"] = 0.0
        out["safe_anchor"] = 0.0
        out["onmouseover"] = 0.0
        out["right_clic"] = 0.0
        out["right_clic"] = 0.0
        out["domain_in_title"] = 0.0
        out["empty_title"] = 1.0
        out["domain_with_copyright"] = 0.0
        out.setdefault("statistical_report", float("nan"))
        out.setdefault("google_index", float("nan"))
        out.setdefault("page_rank", float("nan"))
        out.setdefault("web_traffic", float("nan"))
        out.setdefault("whois_registered_domain", float("nan"))
        out.setdefault("domain_registration_length", float("nan"))
        out.setdefault("domain_age", float("nan"))

    # Ensure all requested columns exist
    for c in cols:
        if c not in out:
            out[c] = float("nan")

    return out
