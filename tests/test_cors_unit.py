import os
import sys

import pytest


# Allow importing backend modules without requiring the Flask app to boot.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

from scanners.cors_scanner import CORSScanner  # noqa: E402


class _Resp:
    def __init__(self, status_code=200, headers=None, content=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content


def test_missing_acao_is_safe(monkeypatch):
    scanner = CORSScanner()

    def fake_get(url, *args, **kwargs):
        return _Resp(200, {"Content-Type": "text/html"}, b"ok")

    def fake_options(url, *args, **kwargs):
        return _Resp(204, {"Access-Control-Allow-Methods": "GET"}, b"")

    monkeypatch.setattr(scanner.session, "get", fake_get)
    monkeypatch.setattr(scanner.session, "options", fake_options)

    res = scanner.scan_url("https://example.com/public")
    assert res["success"] is True
    assert res["risk"] == "SAFE"
    assert res["vulnerable"] is False


def test_wildcard_with_credentials_is_high(monkeypatch):
    scanner = CORSScanner()

    def fake_get(url, *args, **kwargs):
        return _Resp(
            200,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "application/json",
            },
            b"{}",
        )

    def fake_options(url, *args, **kwargs):
        return _Resp(
            204,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST",
            },
            b"",
        )

    monkeypatch.setattr(scanner.session, "get", fake_get)
    monkeypatch.setattr(scanner.session, "options", fake_options)

    res = scanner.scan_url("https://example.com/api")
    assert res["success"] is True
    assert res["risk"] == "HIGH"
    assert res["vulnerable"] is True


def test_origin_reflection_with_credentials_and_cookie_is_high(monkeypatch):
    scanner = CORSScanner()

    def fake_get(url, *args, **kwargs):
        origin = (kwargs.get("headers") or {}).get("Origin")
        return _Resp(
            200,
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Set-Cookie": "sid=abc; Path=/; HttpOnly",
                "Content-Type": "application/json",
            },
            b"{\"ok\":true}",
        )

    def fake_options(url, *args, **kwargs):
        origin = (kwargs.get("headers") or {}).get("Origin")
        return _Resp(
            204,
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST",
            },
            b"",
        )

    monkeypatch.setattr(scanner.session, "get", fake_get)
    monkeypatch.setattr(scanner.session, "options", fake_options)

    res = scanner.scan_url("https://example.com/account")
    assert res["success"] is True
    assert res["risk"] == "HIGH"
    assert res["vulnerable"] is True
    assert res["signals"]["reflection"] is True


def test_origin_reflection_with_credentials_but_not_sensitive_is_medium_not_vulnerable(monkeypatch):
    scanner = CORSScanner()

    def fake_get(url, *args, **kwargs):
        origin = (kwargs.get("headers") or {}).get("Origin")
        return _Resp(
            200,
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "text/plain",
            },
            b"public",
        )

    def fake_options(url, *args, **kwargs):
        origin = (kwargs.get("headers") or {}).get("Origin")
        return _Resp(
            204,
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET",
            },
            b"",
        )

    monkeypatch.setattr(scanner.session, "get", fake_get)
    monkeypatch.setattr(scanner.session, "options", fake_options)

    res = scanner.scan_url("https://example.com/public")
    assert res["success"] is True
    assert res["risk"] == "MEDIUM"
    assert res["vulnerable"] is False


def test_fixed_allowed_origin_is_safe(monkeypatch):
    scanner = CORSScanner()

    def fake_get(url, *args, **kwargs):
        return _Resp(
            200,
            {
                "Access-Control-Allow-Origin": "https://trusted.example",
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "text/plain",
            },
            b"ok",
        )

    def fake_options(url, *args, **kwargs):
        return _Resp(
            204,
            {
                "Access-Control-Allow-Origin": "https://trusted.example",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET",
            },
            b"",
        )

    monkeypatch.setattr(scanner.session, "get", fake_get)
    monkeypatch.setattr(scanner.session, "options", fake_options)

    res = scanner.scan_url("https://example.com/api")
    assert res["success"] is True
    assert res["risk"] == "SAFE"
    assert res["vulnerable"] is False
