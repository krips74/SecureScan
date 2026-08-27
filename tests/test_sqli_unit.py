import os
import sys
import urllib.parse

import pytest


# Allow importing backend modules without requiring the Flask app to boot.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

from scanners.sqli_scanner import SQLiScanner  # noqa: E402


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


def test_sqli_boolean_blind_detects_numeric_targets_even_with_string_original(monkeypatch):
    """Regression: some blind-SQLi labs expect numeric `id`.

    If the URL starts with a non-numeric id (e.g. id=admin), the scanner should still
    try a numeric baseline/true/false pair and detect boolean-based blind SQLi.
    """

    scanner = SQLiScanner(safe_mode=True)

    target = "https://pentest-ground.invalid:4280/vulnerabilities/sqli_blind/?id=admin&Submit=Submit"

    def fake_get(url, *args, **kwargs):
        parsed = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(parsed.query)
        val = (q.get("id") or [""])[0]

        # Simulate DVWA-style output differences.
        # Original id=admin doesn't behave meaningfully (same output for most probes).
        if val == "admin":
            return _Resp("User ID is MISSING")

        # Numeric baseline.
        if val == "1":
            return _Resp("User ID exists")

        # Boolean true/false probes.
        if "AND 1=1" in val:
            return _Resp("User ID exists")
        if "AND 1=2" in val:
            return _Resp("User ID is MISSING")

        # Anything else (payload loop) returns baseline-ish.
        return _Resp("User ID exists")

    monkeypatch.setattr(scanner.session, "get", fake_get)

    res = scanner.scan_url(
        target,
        parameters=["id"],
        timeout=2,
        safe_mode=True,
        custom_payloads=["'"],
        method="GET",
    )

    assert res["success"] is True
    assert res["total_found"] >= 1
    assert any(v.get("scan_type") == "boolean_blind" for v in res.get("vulnerabilities", []))
