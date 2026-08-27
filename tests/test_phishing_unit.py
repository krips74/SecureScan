import os
import sys
import tempfile
import json


# Allow importing backend modules without requiring the Flask app to boot.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

from scanners.phishing_scanner import PhishingScanner  # noqa: E402


def _make_scanner_with_feed(urls: list[str]) -> PhishingScanner:
    fd, path = tempfile.mkstemp(prefix="phishing_cache_", suffix=".json")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"urls": urls, "last_update": 0}, f)

    return PhishingScanner(cache_file=path, enable_background_refresh=False)


def test_handles_missing_scheme():
    scanner = _make_scanner_with_feed([])
    res = scanner.check_url("example.com/login")
    assert res["success"] is True
    assert res["target"] == "example.com/login"


def test_feed_match_tolerates_trailing_slash():
    scanner = _make_scanner_with_feed(["https://phish.test/login"])

    res = scanner.check_url("https://phish.test/login/")
    assert res["success"] is True
    assert res["feed_match"] is True
    assert res["total_found"] >= 1


def test_feed_does_not_match_by_hostname_only():
    scanner = _make_scanner_with_feed(["https://phish.test/bad-path"])

    res = scanner.check_url("https://phish.test/some-other-path")
    assert res["success"] is True
    assert res["feed_match"] is False


def test_detects_at_symbol_trick():
    scanner = _make_scanner_with_feed([])

    res = scanner.check_url("http://example.com@evil.test/login")
    assert res["success"] is True
    # should flag @
    evidences = "\n".join(v.get("evidence", "") for v in res.get("vulnerabilities", []))
    assert "@" in evidences


def test_brand_in_subdomain_is_flagged():
    scanner = _make_scanner_with_feed([])

    res = scanner.check_url("https://paypal.verify-security.example/login")
    assert res["success"] is True
    assert res["total_found"] >= 1
    assert any("Brand 'paypal'" in v.get("evidence", "") for v in res.get("vulnerabilities", []))


def test_public_ip_http_with_path_is_suspicious_not_phishing():
    scanner = _make_scanner_with_feed([])

    res = scanner.check_url("http://202.51.82.150/reesults/")
    assert res["success"] is True
    assert res.get("risk_level") in ("SAFE", "SUSPICIOUS", "PHISHING")
    assert res["risk_level"] == "SUSPICIOUS"
