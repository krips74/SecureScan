import os
import sys
import html
import urllib.parse

import pytest


# Allow importing backend modules without requiring the Flask app to boot.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

from scanners.xss_scanner import XSSScanner  # noqa: E402
from scanners.stored_xss_scanner import StoredXssScanner  # noqa: E402
from scanners.dom_xss_scanner import DomXssScanner  # noqa: E402


class _Resp:
    def __init__(
        self,
        text: str = "",
        status_code: int = 200,
        headers: dict | None = None,
    ):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}


class _FakeUUID:
    def __init__(self, hex_value: str):
        self.hex = hex_value


@pytest.fixture()
def fixed_uuid(monkeypatch):
    """Force uuid/uuid4 to be deterministic for tests."""
    import scanners.xss_scanner as xss_mod
    import scanners.stored_xss_scanner as stored_mod

    seq = iter(
        [
            _FakeUUID("a" * 32),
            _FakeUUID("b" * 32),
            _FakeUUID("c" * 32),
            _FakeUUID("d" * 32),
        ]
    )

    def _next():
        return next(seq)

    monkeypatch.setattr(xss_mod.uuid, "uuid4", _next)
    monkeypatch.setattr(stored_mod, "uuid4", _next)


def test_reflected_xss_no_false_positive_on_static_payload_text(fixed_uuid, monkeypatch):
    """If the response contains a common payload string, we should NOT flag unless the unique marker payload is reflected."""

    scanner = XSSScanner()

    target = "http://example.com/search?q=test"
    template_payload = "<script>alert(1)</script>"

    # What the scanner will actually send once marker is injected.
    scan_marker = "SSXSS" + ("a" * 10)
    unique_payload = scanner._inject_marker_into_payload(template_payload, scan_marker)

    def fake_get(url, *args, **kwargs):
        # Baseline request
        if url == target:
            return _Resp("baseline")

        # Probe request uses its own unique marker (different UUID), we don't reflect it.
        decoded_url = urllib.parse.unquote_plus(url)

        if "SSXSS" in url and decoded_url.find(unique_payload) == -1:
            return _Resp("probe-no-reflection")

        # Payload attempt: return a page containing only the *template* payload, not the unique one.
        if decoded_url.find(unique_payload) != -1:
            return _Resp(f"header {template_payload} footer")

        return _Resp("other")

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(
        target,
        parameters=["q"],
        timeout=2,
        custom_payloads=[template_payload],
        max_duration=3,
        max_payloads=1,
        stop_on_first=True,
    )

    assert res["success"] is True
    assert res["total_found"] == 0


def test_reflected_xss_reports_only_on_unique_raw_reflection(fixed_uuid, monkeypatch):
    scanner = XSSScanner()

    target = "http://example.com/search?q=test"
    template_payload = "<img src=x onerror=alert(1)>"

    scan_marker = "SSXSS" + ("a" * 10)
    unique_payload = scanner._inject_marker_into_payload(template_payload, scan_marker)

    def fake_get(url, *args, **kwargs):
        if url == target:
            return _Resp("baseline")

        # Probe (ignore)
        decoded_url = urllib.parse.unquote_plus(url)

        if "SSXSS" in url and decoded_url.find(unique_payload) == -1:
            return _Resp("probe-no-reflection")

        # Vulnerable reflection: reflect the exact unique payload unescaped
        if decoded_url.find(unique_payload) != -1:
            return _Resp(f"<html>{unique_payload}</html>")

        return _Resp("other")

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(
        target,
        parameters=["q"],
        timeout=2,
        custom_payloads=[template_payload],
        max_duration=3,
        max_payloads=1,
        stop_on_first=True,
    )

    assert res["success"] is True
    assert res["total_found"] == 1
    v = res["vulnerabilities"][0]
    assert v["scan_type"] == "reflected_raw"
    assert v["payload"] == unique_payload
    assert v["marker"] == scan_marker
    assert v["payload_template"] == template_payload


def test_reflected_xss_does_not_report_when_only_escaped_reflection(fixed_uuid, monkeypatch):
    scanner = XSSScanner()

    target = "http://example.com/search?q=test"
    template_payload = "<svg onload=alert(1)>"

    scan_marker = "SSXSS" + ("a" * 10)
    unique_payload = scanner._inject_marker_into_payload(template_payload, scan_marker)

    def fake_get(url, *args, **kwargs):
        if url == target:
            return _Resp("baseline")

        decoded_url = urllib.parse.unquote_plus(url)

        if "SSXSS" in url and decoded_url.find(unique_payload) == -1:
            return _Resp("probe-no-reflection")

        if decoded_url.find(unique_payload) != -1:
            return _Resp(html.escape(unique_payload))

        return _Resp("other")

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(
        target,
        parameters=["q"],
        timeout=2,
        custom_payloads=[template_payload],
        max_duration=3,
        max_payloads=1,
        stop_on_first=True,
    )

    assert res["success"] is True
    assert res["total_found"] == 0


def test_reflected_xss_does_not_report_on_json_reflection(fixed_uuid, monkeypatch):
    """Raw reflection inside JSON should not be reported as XSS."""
    scanner = XSSScanner()

    target = "http://example.com/api?q=test"
    template_payload = "<script>alert(1)</script>"

    scan_marker = "SSXSS" + ("a" * 10)
    unique_payload = scanner._inject_marker_into_payload(template_payload, scan_marker)

    def fake_get(url, *args, **kwargs):
        if url == target:
            return _Resp("{}", headers={"Content-Type": "application/json"})

        decoded_url = urllib.parse.unquote_plus(url)
        if "SSXSS" in url and decoded_url.find(unique_payload) == -1:
            return _Resp("{}", headers={"Content-Type": "application/json"})

        if decoded_url.find(unique_payload) != -1:
            # Simulate an API that echoes the input back in JSON.
            return _Resp(
                '{"echo": "%s"}' % unique_payload.replace('"', '\\"'),
                headers={"Content-Type": "application/json"},
            )

        return _Resp("{}", headers={"Content-Type": "application/json"})

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(
        target,
        parameters=["q"],
        timeout=2,
        custom_payloads=[template_payload],
        max_duration=3,
        max_payloads=1,
        stop_on_first=True,
    )

    assert res["success"] is True
    assert res["total_found"] == 0


def test_stored_xss_heuristic_flags_only_if_marker_persists(fixed_uuid, monkeypatch):
    scanner = StoredXssScanner()
    target = "http://example.com/page?msg=hi"

    marker_id = "ss_stored_xss_marker_" + ("a" * 32)
    marker_payload = f"<svg id=\"{marker_id}\"></svg>"

    calls = {"n": 0}

    def fake_get(url, *args, **kwargs):
        calls["n"] += 1
        # 1) Baseline
        if calls["n"] == 1:
            return _Resp("baseline")
        # 2) Injection request (ignore response)
        if calls["n"] == 2:
            return _Resp("injected")
        # 3) Clean reload returns marker -> should be flagged
        if calls["n"] == 3:
            return _Resp(f"<html>ok {marker_payload}</html>")
        return _Resp("other")

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(
        target,
        timeout=2,
        max_params=1,
        stop_on_first=True,
        max_duration=5,
        mode="heuristic_get",
    )

    assert res["success"] is True
    assert res["total_found"] == 1
    v = res["vulnerabilities"][0]
    assert v["scan_type"] == "stored"
    assert v["confidence"] == "heuristic"


def test_dom_xss_build_cases_includes_marker_payload():
    dom = DomXssScanner(headless=True)
    payload = '<svg id="ss_dom_xss_test"></svg>'
    cases = dom._build_cases("https://example.com/path?x=1", payload)

    assert cases
    # At least one case should include marker payload either in query or fragment
    assert any(payload in urllib.parse.unquote(c.url) for c in cases)
