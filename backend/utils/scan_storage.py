import json
from typing import Any, Dict, Iterable, Optional

from datetime import datetime

from database import get_db


_SEVERITY_ORDER = {
    "clean": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        return None

    v = value.strip().lower()
    if v in ("crit", "critical"):
        return "critical"
    if v in ("high",):
        return "high"
    if v in ("med", "medium"):
        return "medium"
    if v in ("low",):
        return "low"
    if v in ("info", "informational"):
        return "info"
    if v in ("clean", "none"):
        return "clean"
    return None


def _walk_severities(obj: Any) -> Iterable[str]:
    if isinstance(obj, dict):
        sev = _normalize_severity(obj.get("severity"))
        if sev:
            yield sev
        for v in obj.values():
            yield from _walk_severities(v)
        return

    if isinstance(obj, list):
        for item in obj:
            yield from _walk_severities(item)


def compute_overall_severity(results: Dict) -> str:
    """Compute an overall severity for a scan.

    Prefers the highest per-finding severity if present. Falls back to a
    conservative count-based heuristic.
    """
    severities = list(_walk_severities(results))
    if severities:
        return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0))

    total = results.get("total_vulnerabilities")
    if total is None:
        total = results.get("total_found", 0)

    try:
        total_int = int(total)
    except Exception:
        total_int = 0

    if total_int > 10:
        return "critical"
    if total_int > 5:
        return "high"
    if total_int > 2:
        return "medium"
    if total_int > 0:
        return "low"
    return "clean"


def save_scan_to_db(user_id: int, url: str, scan_types, results: Dict) -> Optional[int]:
    """Persist scan results to MySQL."""
    try:
        total = results.get("total_vulnerabilities")
        if total is None:
            total = results.get("total_found", 0)

        try:
            total_int = int(total)
        except Exception:
            total_int = 0

        severity = compute_overall_severity(results)

        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """INSERT INTO scans (user_id, target_url, scan_types, status, total_vulns, severity, results_json, completed_at)
               VALUES (%s, %s, %s, 'completed', %s, %s, %s, NOW())""",
            (user_id, url, json.dumps(scan_types), total_int, severity, json.dumps(results)),
        )
        scan_id = cursor.lastrowid

        _insert_vulnerabilities_rows(cursor, scan_id, url, results)

        cursor.close()
        db.close()
        return scan_id
    except Exception as e:
        print(f"DB save error: {e}")
        return None


def _ensure_scans_cancel_columns(cursor) -> None:
    """Best-effort migration: add cancel fields to scans."""
    try:
        cursor.execute("SHOW COLUMNS FROM scans LIKE 'cancel_requested'")
        has_req = cursor.fetchone() is not None
        cursor.execute("SHOW COLUMNS FROM scans LIKE 'cancel_reason'")
        has_reason = cursor.fetchone() is not None
        cursor.execute("SHOW COLUMNS FROM scans LIKE 'canceled_at'")
        has_at = cursor.fetchone() is not None

        if not has_req:
            cursor.execute("ALTER TABLE scans ADD COLUMN cancel_requested BOOLEAN DEFAULT FALSE")
        if not has_reason:
            cursor.execute("ALTER TABLE scans ADD COLUMN cancel_reason VARCHAR(255)")
        if not has_at:
            cursor.execute("ALTER TABLE scans ADD COLUMN canceled_at DATETIME")
    except Exception:
        return


def _ensure_vulnerabilities_triage_columns(cursor) -> None:
    """Best-effort migration: add triage fields to vulnerabilities."""
    try:
        cursor.execute("SHOW COLUMNS FROM vulnerabilities LIKE 'triage_status'")
        has_status = cursor.fetchone() is not None
        cursor.execute("SHOW COLUMNS FROM vulnerabilities LIKE 'triaged_at'")
        has_at = cursor.fetchone() is not None

        if not has_status:
            cursor.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN triage_status ENUM('unreviewed','confirmed','false_positive') DEFAULT 'unreviewed'"
            )
        if not has_at:
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN triaged_at DATETIME")
    except Exception:
        return


def _insert_vulnerabilities_rows(cursor, scan_id: int, base_url: str, results: Dict) -> None:
    """Insert per-issue rows into vulnerabilities table (best-effort).

    Supports multiple scanner result formats:
    - Unified scans: results['scans'][kind]['issues'|'vulnerabilities']
    - Single scanner: results['vulnerabilities'] or results['issues']
    """

    def _iter_issue_groups(obj: Any):
        if not isinstance(obj, dict):
            return

        # Common direct formats
        for key in ("vulnerabilities", "issues", "findings"):
            items = obj.get(key)
            if isinstance(items, list) and items:
                for it in items:
                    yield None, it

        # Unified scan format
        scans_obj = obj.get("scans")
        if isinstance(scans_obj, dict):
            for scan_kind, scan_result in scans_obj.items():
                if not isinstance(scan_result, dict):
                    continue
                for key in ("issues", "vulnerabilities", "findings"):
                    items = scan_result.get(key)
                    if isinstance(items, list) and items:
                        for it in items:
                            yield scan_kind, it

    def _build_description(issue: Dict[str, Any]) -> Optional[str]:
        desc = issue.get("description") or issue.get("details") or issue.get("reason") or issue.get("evidence")
        cwe = issue.get("cwe")
        conf = issue.get("confidence")
        extras = []
        if cwe:
            extras.append(f"CWE: {cwe}")
        if conf:
            extras.append(f"Confidence: {conf}")
        if extras:
            if desc:
                return f"{desc} ({' • '.join(extras)})"
            return " • ".join(extras)
        return str(desc) if desc is not None else None

    try:
        _ensure_vulnerabilities_triage_columns(cursor)

        inserted_any = False
        for scan_kind, issue in _iter_issue_groups(results):
            if not isinstance(issue, dict):
                continue

            base_type = issue.get("type") or issue.get("vuln_type") or scan_kind or "unknown"
            scan_type = issue.get("scan_type")
            vuln_type = f"{base_type}:{scan_type}" if scan_type else base_type

            sev = (
                _normalize_severity(issue.get("severity"))
                or _normalize_severity(issue.get("risk"))
                or _normalize_severity(issue.get("level"))
                or "medium"
            )

            vuln_url = issue.get("poc") or issue.get("url") or issue.get("target") or base_url
            parameter = issue.get("parameter") or issue.get("param")
            payload = issue.get("payload") or issue.get("vector")
            description = _build_description(issue)

            cursor.execute(
                """INSERT INTO vulnerabilities (scan_id, vuln_type, severity, url, parameter, payload, description, found_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    scan_id,
                    str(vuln_type)[:50],
                    sev,
                    str(vuln_url)[:500] if vuln_url is not None else None,
                    str(parameter)[:100] if parameter is not None else None,
                    str(payload) if payload is not None else None,
                    str(description) if description is not None else None,
                    datetime.utcnow(),
                ),
            )
            inserted_any = True

        # Backwards compatibility: older unified format used scans[kind].issues
        # and severity on the scan_result; if nothing was inserted above,
        # try the older path.
        if not inserted_any:
            scans_obj = results.get("scans") if isinstance(results, dict) else None
            if isinstance(scans_obj, dict):
                for scan_kind, scan_result in scans_obj.items():
                    if not isinstance(scan_result, dict):
                        continue
                    issues = scan_result.get("issues")
                    if not isinstance(issues, list) or not issues:
                        continue
                    for issue in issues:
                        if not isinstance(issue, dict):
                            continue
                        vuln_type = (issue.get("type") or scan_kind or "unknown")
                        sev = _normalize_severity(issue.get("severity")) or _normalize_severity(scan_result.get("severity")) or "medium"
                        vuln_url = issue.get("url") or issue.get("target") or base_url
                        parameter = issue.get("parameter") or issue.get("param")
                        payload = issue.get("payload") or issue.get("vector")
                        description = _build_description(issue)
                        cursor.execute(
                            """INSERT INTO vulnerabilities (scan_id, vuln_type, severity, url, parameter, payload, description, found_at)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                            (
                                scan_id,
                                str(vuln_type)[:50],
                                sev,
                                str(vuln_url)[:500] if vuln_url is not None else None,
                                str(parameter)[:100] if parameter is not None else None,
                                str(payload) if payload is not None else None,
                                str(description) if description is not None else None,
                                datetime.utcnow(),
                            ),
                        )
    except Exception:
        return


def create_running_scan(user_id: int, url: str, scan_types) -> Optional[int]:
    """Create a scan row in 'running' status for live monitoring."""
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_scans_cancel_columns(cursor)

        cursor.execute(
            """INSERT INTO scans (user_id, target_url, scan_types, status, total_vulns, severity, results_json, started_at)
               VALUES (%s, %s, %s, 'running', 0, 'info', NULL, NOW())""",
            (user_id, url, json.dumps(scan_types)),
        )
        scan_id = cursor.lastrowid
        cursor.close()
        db.close()
        return scan_id
    except Exception:
        return None


def is_cancel_requested(scan_id: int) -> bool:
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_scans_cancel_columns(cursor)
        cursor.execute("SELECT cancel_requested FROM scans WHERE id=%s LIMIT 1", (scan_id,))
        row = cursor.fetchone() or {}
        cursor.close()
        db.close()
        return bool(row.get("cancel_requested"))
    except Exception:
        return False


def finalize_scan(scan_id: int, user_id: int, url: str, scan_types, results: Dict, status: str = "completed") -> bool:
    """Finalize an existing scan row (completed/failed) and insert vulnerabilities."""
    if status not in ("completed", "failed"):
        status = "completed"

    try:
        total = results.get("total_vulnerabilities")
        if total is None:
            total = results.get("total_found", 0)

        try:
            total_int = int(total)
        except Exception:
            total_int = 0

        severity = compute_overall_severity(results)

        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_scans_cancel_columns(cursor)

        cursor.execute(
            """UPDATE scans
               SET status=%s,
                   total_vulns=%s,
                   severity=%s,
                   results_json=%s,
                   completed_at=NOW(),
                   canceled_at=CASE WHEN cancel_requested=TRUE AND canceled_at IS NULL THEN NOW() ELSE canceled_at END
               WHERE id=%s AND user_id=%s""",
            (status, total_int, severity, json.dumps(results), scan_id, user_id),
        )

        _insert_vulnerabilities_rows(cursor, scan_id, url, results)

        cursor.close()
        db.close()
        return True
    except Exception:
        return False
