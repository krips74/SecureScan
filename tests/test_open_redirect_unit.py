import os
import sys
import urllib.parse

import pytest


# Allow importing backend modules without requiring the Flask app to boot.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

from scanners.open_redirect_scanner import OpenRedirectScanner  # noqa: E402


class _Resp:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def test_confirmed_open_redirect_external_location(monkeypatch):
    scanner = OpenRedirectScanner()

    target = "https://example.com/login?next=/"

    def fake_get(url, *args, **kwargs):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        v = (qs.get("next") or [""])[0]
        # Scanner injects attacker.invalid
        if "attacker.invalid" in urllib.parse.unquote(v):
            return _Resp(302, {"Location": "https://attacker.invalid/"})
        return _Resp(200, {})

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(target, parameters=["next"], timeout=2)
    assert res["success"] is True
    assert res["result"]["severity"] == "HIGH"
    assert res["result"]["is_vulnerable"] is True
    assert res["result"]["exploitability"] == "CONFIRMED"
    assert res["result"]["evidence"]["final_url"].startswith("https://attacker.invalid")


def test_internal_redirect_only_is_low(monkeypatch):
    scanner = OpenRedirectScanner()
    target = "https://example.com/continue"

    def fake_get(url, *args, **kwargs):
        # Always internal redirect
        return _Resp(302, {"Location": "/home"})

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(target, parameters=["next"], timeout=2)
    assert res["success"] is True
    assert res["result"]["severity"] in ("LOW", "INFO")
    assert res["result"]["is_vulnerable"] is False


def test_no_redirect_is_info(monkeypatch):
    scanner = OpenRedirectScanner()
    target = "https://example.com/"

    def fake_get(url, *args, **kwargs):
        return _Resp(200, {})

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(target, parameters=["next"], timeout=2)
    assert res["success"] is True
    assert res["result"]["severity"] == "INFO"
    assert res["result"]["exploitability"] == "NONE"


def test_redirect_to_example_domain_is_not_flagged(monkeypatch):
    scanner = OpenRedirectScanner()
    target = "https://example.com/login?next=/"

    def fake_get(url, *args, **kwargs):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        v = (qs.get("next") or [""])[0]
        if "attacker.invalid" in urllib.parse.unquote(v):
            # Placeholder domain redirect should be ignored by FP prevention.
            return _Resp(302, {"Location": "https://example.org/"})
        return _Resp(200, {})

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(target, parameters=["next"], timeout=2)
    assert res["success"] is True
    assert res["result"]["severity"] == "INFO"
    assert res["result"]["is_vulnerable"] is False


def test_redirect_chain_internal_then_external(monkeypatch):
    scanner = OpenRedirectScanner()
    target = "https://example.com/login?next=/"

    def fake_get(url, *args, **kwargs):
        # First hop internal, second hop external
        if url.startswith("https://example.com/login"):
            return _Resp(302, {"Location": "/step2"})
        if url.startswith("https://example.com/step2"):
            return _Resp(302, {"Location": "https://attacker.invalid/"})
        return _Resp(200, {})

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(target, parameters=["next"], timeout=2)
    assert res["success"] is True
    assert res["result"]["severity"] in ("MEDIUM", "HIGH")
    chain = res["result"]["evidence"]["redirect_chain"]
    assert isinstance(chain, list) and len(chain) >= 2
    assert res["result"]["evidence"]["final_url"].startswith("https://attacker.invalid")
