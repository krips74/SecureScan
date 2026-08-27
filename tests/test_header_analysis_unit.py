import os
import sys

import pytest


# Allow importing backend modules without requiring the Flask app to boot.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

from scanners.header_scanner import HeaderScanner  # noqa: E402


def _find(findings, header):
    for f in findings:
        if f.get("header") == header:
            return f
    return None


def test_missing_hsts_on_https_auth_is_high_and_grade_not_harsh_f():
    scanner = HeaderScanner()
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        # No HSTS
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
        "X-Content-Type-Options": "nosniff",
    }

    res = scanner.analyze_headers("https://example.com/login", headers)
    assert res["url"].startswith("https://")
    assert res["grade"] in ("C", "D")  # context-aware; single high signal shouldn't force F

    f = _find(res["findings"], "Strict-Transport-Security")
    assert f is not None
    assert f["severity"] == "HIGH"


def test_x_frame_options_missing_downgraded_when_frame_ancestors_present():
    scanner = HeaderScanner()
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
        "X-Content-Type-Options": "nosniff",
        # No X-Frame-Options
    }

    res = scanner.analyze_headers("https://example.com/", headers)
    f = _find(res["findings"], "X-Frame-Options")
    assert f is not None
    assert f["severity"] in ("LOW", "INFO")


def test_csp_unsafe_inline_and_eval_is_high_and_can_drive_f_with_chain():
    scanner = HeaderScanner()
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'",
        # Also missing X-Content-Type-Options => medium/low depending on context, should create a chain
    }

    res = scanner.analyze_headers("https://example.com/account", headers)
    f = _find(res["findings"], "Content-Security-Policy")
    assert f is not None
    assert f["severity"] == "HIGH"

    # With additional weaknesses, grade can become F.
    assert res["grade"] in ("D", "F")


def test_info_leak_headers_are_info_and_do_not_over_score():
    scanner = HeaderScanner()
    headers = {
        "Content-Type": "text/html",
        "Server": "cloudflare",
        "X-Powered-By": "Express",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    }

    res = scanner.analyze_headers("https://example.com/", headers)
    f = _find(res["findings"], "Information Disclosure")
    assert f is not None
    assert f["severity"] == "INFO"
    assert res["summary"]["critical"] == 0


def test_missing_policy_headers_are_grouped_single_finding():
    scanner = HeaderScanner()
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        # Missing Referrer-Policy + Permissions-Policy
    }

    res = scanner.analyze_headers("https://example.com/", headers)
    f = _find(res["findings"], "Missing Recommended Policies")
    assert f is not None
    assert "Referrer-Policy" in f["reason"]
    assert "Permissions-Policy" in f["reason"]

    # Ensure dedup: only one grouped finding for the missing policies.
    assert sum(1 for x in res["findings"] if x.get("header") == "Missing Recommended Policies") == 1
