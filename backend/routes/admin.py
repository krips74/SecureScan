import os
import hmac
import uuid
import json
from functools import wraps
from typing import Any, Dict

import bcrypt

from dotenv import load_dotenv
from flask import Blueprint, jsonify, request, session

from database import get_db

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

admin_bp = Blueprint("admin", __name__)


def _admin_email() -> str:
    return (os.getenv("ADMIN_EMAIL") or "admin@securescan.com").strip()


def _admin_password() -> str:
    # Intentionally read from env; do NOT embed in frontend.
    return os.getenv("ADMIN_PASSWORD") or "Secure@12345"


def _verify_admin_db(email: str, password: str) -> bool:
    """Check admin credentials stored in DB (users.role='admin').

    Passwords are stored as bcrypt hashes in users.password_hash.
    """
    if not email or not password:
        return False

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, password_hash, is_active
            FROM users
            WHERE email=%s AND role='admin'
            LIMIT 1
            """,
            (email,),
        )
        row = cursor.fetchone()
        cursor.close()
        db.close()
    except Exception:
        return False

    if not row:
        return False
    if not bool(row.get("is_active")):
        return False

    ph = row.get("password_hash")
    if not isinstance(ph, str) or not ph:
        return False
    try:
        return bool(bcrypt.checkpw(password.encode("utf-8"), ph.encode("utf-8")))
    except Exception:
        return False


def _ensure_admin_sessions_table(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            session_id     CHAR(36) NOT NULL,
            admin_email    VARCHAR(120) NOT NULL,
            ip_address     VARCHAR(45),
            user_agent     VARCHAR(255),
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            logged_out_at  DATETIME,
            UNIQUE KEY uq_admin_session_id (session_id),
            INDEX idx_admin_sessions_email (admin_email),
            INDEX idx_admin_sessions_last_seen (last_seen_at)
        ) ENGINE=InnoDB
        """
    )


def _ensure_feedback_table(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            user_id       INT NOT NULL,
            subject       VARCHAR(200) NOT NULL,
            message       TEXT NOT NULL,
            category      ENUM('bug','feature','false_positive','general') DEFAULT 'general',
            status        ENUM('pending','resolved') DEFAULT 'pending',
            admin_reply   TEXT,
            replied_at    DATETIME,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_feedback_user (user_id),
            INDEX idx_feedback_status (status),
            INDEX idx_feedback_category (category),
            INDEX idx_feedback_created (created_at)
        ) ENGINE=InnoDB
        """
    )


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


def _is_admin_session() -> bool:
    return bool(session.get("is_admin") is True and session.get("admin_session_id"))


def _touch_admin_session(cursor, session_id: str) -> None:
    cursor.execute(
        "UPDATE admin_sessions SET last_seen_at=NOW() WHERE session_id=%s AND logged_out_at IS NULL",
        (session_id,),
    )


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _is_admin_session():
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # Best-effort audit: if the DB user cannot create/update the admin_sessions table,
        # do not block admin access (admin APIs still require DB for their core data).
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            try:
                _ensure_admin_sessions_table(cursor)
                _touch_admin_session(cursor, session.get("admin_session_id"))
            except Exception:
                pass
            finally:
                cursor.close()
                db.close()
        except Exception:
            pass

        return fn(*args, **kwargs)

    return wrapper


@admin_bp.route("/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password required"}), 400

    expected_email = _admin_email()
    expected_password = _admin_password()

    # Prefer DB-backed admin credential if present; keep env fallback.
    env_ok = bool(hmac.compare_digest(email, expected_email) and hmac.compare_digest(password, expected_password))
    db_ok = _verify_admin_db(email, password)

    if not (env_ok or db_ok):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    session_id = str(uuid.uuid4())
    session.clear()
    session["is_admin"] = True
    session["admin_session_id"] = session_id
    session["admin_email"] = email

    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    ua = (request.headers.get("User-Agent") or "").strip()[:255]

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            _ensure_admin_sessions_table(cursor)
            cursor.execute(
                """INSERT INTO admin_sessions (session_id, admin_email, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s)""",
                (session_id, email, ip, ua),
            )
        except Exception:
            # If the DB user lacks permission to create/insert into admin_sessions,
            # continue without audit rather than breaking admin login.
            pass
        finally:
            cursor.close()
            db.close()
    except Exception:
        # If DB is completely unavailable, admin pages will not be useful; still
        # avoid breaking the login flow into a confusing user-JWT fallback.
        return jsonify({"success": True, "email": email, "audit": "unavailable"})

    return jsonify({"success": True, "email": email})


@admin_bp.route("/bootstrap", methods=["POST"])
def admin_bootstrap():
    """One-time bootstrap: create the first admin user in the DB.

    Security properties:
    - Works only when no admin user exists yet.
    - Stores password as bcrypt hash.
    """
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not email or "@" not in email or "." not in email:
        return jsonify({"success": False, "error": "Valid email required"}), 400
    if not password or len(password) < 8:
        return jsonify({"success": False, "error": "Password must be ≥ 8 characters"}), 400

    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    if ip not in ("127.0.0.1", "::1", "localhost"):
        # Keep it local-only to prevent remote bootstrapping.
        return jsonify({"success": False, "error": "Bootstrap allowed only from localhost"}), 403

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'")
        c = int((cursor.fetchone() or {}).get("c") or 0)
        if c > 0:
            cursor.close()
            db.close()
            return jsonify({"success": False, "error": "Admin already exists"}), 409

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Username is display-only; keep it stable for admin.
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, role, email_verified, email_verified_at, is_active)
            VALUES (%s, %s, %s, 'admin', 1, NOW(), 1)
            """,
            ("Admin", email, pw_hash),
        )
        admin_id = cursor.lastrowid
        cursor.close()
        db.close()
        return jsonify({"success": True, "admin_user_id": admin_id})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/logout", methods=["POST"])
@admin_required
def admin_logout():
    sid = session.get("admin_session_id")
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_admin_sessions_table(cursor)
        cursor.execute(
            "UPDATE admin_sessions SET logged_out_at=NOW() WHERE session_id=%s AND logged_out_at IS NULL",
            (sid,),
        )
        cursor.close()
        db.close()
    except Exception:
        pass

    session.clear()
    return jsonify({"success": True})


@admin_bp.route("/me", methods=["GET"])
@admin_required
def admin_me():
    return jsonify({"success": True, "email": session.get("admin_email")})


def _parse_scan_types(raw: Any) -> str:
    if raw is None:
        return "—"
    if isinstance(raw, (list, tuple)):
        return ", ".join([str(x) for x in raw])
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return "—"
        try:
            v = json.loads(s)
            if isinstance(v, list):
                return ", ".join([str(x) for x in v])
        except Exception:
            return s
        return s
    return str(raw)


@admin_bp.route("/dashboard", methods=["GET"])
@admin_required
def admin_dashboard():
    """Dashboard stats + chart data + recent activity."""
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)

        cursor.execute("SELECT COUNT(*) AS c FROM users")
        total_users = int((cursor.fetchone() or {}).get("c") or 0)

        cursor.execute("SELECT COUNT(*) AS c FROM users WHERE is_active=TRUE")
        active_users = int((cursor.fetchone() or {}).get("c") or 0)

        cursor.execute("SELECT COUNT(*) AS c FROM scans")
        total_scans = int((cursor.fetchone() or {}).get("c") or 0)

        # Prefer normalized vulnerabilities table if present.
        try:
            cursor.execute("SELECT COUNT(*) AS c FROM vulnerabilities")
            total_vulns_found = int((cursor.fetchone() or {}).get("c") or 0)
        except Exception:
            cursor.execute("SELECT COALESCE(SUM(total_vulns),0) AS s FROM scans")
            total_vulns_found = int((cursor.fetchone() or {}).get("s") or 0)

        cursor.execute("SELECT COUNT(*) AS c FROM feedback")
        total_feedback = int((cursor.fetchone() or {}).get("c") or 0)

        # Chart 1: scans by scanner type (counts based on scan_types list)
        cursor.execute("SELECT scan_types FROM scans ORDER BY started_at DESC LIMIT 500")
        type_counts: Dict[str, int] = {}
        for r in cursor.fetchall() or []:
            s = r.get("scan_types")
            types: Any = None
            if isinstance(s, str) and s:
                try:
                    types = json.loads(s)
                except Exception:
                    types = None
            if not isinstance(types, list):
                continue
            for t in types:
                key = (str(t) or "").strip().lower()
                if not key:
                    continue
                type_counts[key] = type_counts.get(key, 0) + 1

        scans_by_type = [{"type": k, "count": v} for k, v in sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)]

        # Chart 2: daily scan activity (last 14 days)
        cursor.execute(
            """
            SELECT DATE(started_at) AS day, COUNT(*) AS c
            FROM scans
            WHERE started_at >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
            GROUP BY DATE(started_at)
            ORDER BY day ASC
            """
        )
        daily = []
        for r in cursor.fetchall() or []:
            daily.append({"day": str(r.get("day")), "count": int(r.get("c") or 0)})

        # Recent activity
        cursor.execute(
            """
            SELECT s.id AS scan_id, u.username, s.scan_types, s.target_url, s.status, s.started_at
            FROM scans s
            JOIN users u ON u.id = s.user_id
            ORDER BY s.started_at DESC
            LIMIT 20
            """
        )
        activity = []
        for r in cursor.fetchall() or []:
            activity.append(
                {
                    "scan_id": r.get("scan_id"),
                    "username": r.get("username"),
                    "scan_type": _parse_scan_types(r.get("scan_types")),
                    "target_url": r.get("target_url"),
                    "status": r.get("status"),
                    "timestamp": str(r.get("started_at")) if r.get("started_at") else None,
                }
            )

        cursor.close()
        db.close()

        return jsonify(
            {
                "success": True,
                "stats": {
                    "total_users": total_users,
                    "active_users": active_users,
                    "total_scans": total_scans,
                    "total_vulnerabilities": total_vulns_found,
                    "total_feedback": total_feedback,
                },
                "charts": {
                    "scans_by_type": scans_by_type,
                    "daily_scans": daily,
                },
                "recent_activity": activity,
            }
        )
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/users", methods=["GET"])
@admin_required
def admin_users():
    q = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()  # active|banned|all

    where = []
    params = []

    if q:
        where.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s)")
        params.extend([f"%{q}%", f"%{q}%"])

    if status == "active":
        where.append("u.is_active=TRUE")
    elif status == "banned":
        where.append("u.is_active=FALSE")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
              u.id,
              u.username,
              u.email,
              u.last_login,
              u.is_active,
              (SELECT COUNT(*) FROM scans s WHERE s.user_id=u.id) AS total_scans
            FROM users u
            {where_sql}
            ORDER BY u.created_at DESC
            LIMIT 500
            """,
            tuple(params),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        db.close()

        users = []
        for r in rows:
            users.append(
                {
                    "id": r.get("id"),
                    "username": r.get("username"),
                    "email": r.get("email"),
                    "total_scans": int(r.get("total_scans") or 0),
                    "last_active": str(r.get("last_login")) if r.get("last_login") else None,
                    "status": "Active" if bool(r.get("is_active")) else "Banned",
                }
            )

        return jsonify({"success": True, "users": users})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def admin_user_detail(user_id: int):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("SELECT id, username, email, role, is_active, created_at, last_login FROM users WHERE id=%s", (user_id,))
        u = cursor.fetchone()
        if not u:
            cursor.close()
            db.close()
            return jsonify({"success": False, "error": "Not found"}), 404

        cursor.execute(
            """
            SELECT id, target_url, scan_types, status, total_vulns, severity, started_at, completed_at
            FROM scans
            WHERE user_id=%s
            ORDER BY started_at DESC
            LIMIT 200
            """,
            (user_id,),
        )
        scans = cursor.fetchall() or []

        cursor.close()
        db.close()

        user_obj = {
            "id": u.get("id"),
            "username": u.get("username"),
            "email": u.get("email"),
            "role": u.get("role"),
            "status": "Active" if bool(u.get("is_active")) else "Banned",
            "created_at": str(u.get("created_at")) if u.get("created_at") else None,
            "last_active": str(u.get("last_login")) if u.get("last_login") else None,
        }

        scan_rows = []
        for s in scans:
            scan_rows.append(
                {
                    "id": s.get("id"),
                    "target_url": s.get("target_url"),
                    "scan_types": _parse_scan_types(s.get("scan_types")),
                    "risk_level": (s.get("severity") or "info"),
                    "status": s.get("status"),
                    "timestamp": str(s.get("started_at")) if s.get("started_at") else None,
                }
            )

        return jsonify({"success": True, "user": user_obj, "scans": scan_rows})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/users/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_user_ban(user_id: int):
    data = request.get_json() or {}
    banned = bool(data.get("banned", True))
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("UPDATE users SET is_active=%s WHERE id=%s", (False if banned else True, user_id))
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_user_delete(user_id: int):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/scans", methods=["GET"])
@admin_required
def admin_scans():
    q = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()
    severity = (request.args.get("severity") or "").strip().lower()

    where = []
    params = []
    if q:
        where.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s OR LOWER(s.target_url) LIKE %s)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    if status:
        where.append("LOWER(s.status)=%s")
        params.append(status)

    if severity:
        where.append("LOWER(s.severity)=%s")
        params.append(severity)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_scans_cancel_columns(cursor)
        cursor.execute(
            f"""
            SELECT s.id, u.username, u.email, u.role, s.target_url, s.scan_types, s.severity, s.status,
                   s.total_vulns, s.started_at, s.cancel_requested, s.cancel_reason, s.canceled_at
            FROM scans s
            JOIN users u ON u.id=s.user_id
            {where_sql}
            ORDER BY s.started_at DESC
            LIMIT 500
            """,
            tuple(params),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        db.close()

        scans = []
        for r in rows:
            scans.append(
                {
                    "id": r.get("id"),
                    "user": r.get("username"),
                    "role": r.get("role"),
                    "target_url": r.get("target_url"),
                    "scanner_type": _parse_scan_types(r.get("scan_types")),
                    "risk_level": (r.get("severity") or "info"),
                    "status": r.get("status"),
                    "cancel_requested": bool(r.get("cancel_requested")),
                    "cancel_reason": r.get("cancel_reason"),
                    "canceled_at": str(r.get("canceled_at")) if r.get("canceled_at") else None,
                    "timestamp": str(r.get("started_at")) if r.get("started_at") else None,
                    "total_vulns": int(r.get("total_vulns") or 0),
                }
            )

        return jsonify({"success": True, "scans": scans})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/scans/<int:scan_id>", methods=["GET"])
@admin_required
def admin_scan_detail(scan_id: int):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_scans_cancel_columns(cursor)
        cursor.execute(
            """
            SELECT s.id, u.username, u.email, u.role, s.target_url, s.scan_types, s.status, s.total_vulns, s.severity,
                   s.results_json, s.started_at, s.completed_at,
                   s.cancel_requested, s.cancel_reason, s.canceled_at
            FROM scans s
            JOIN users u ON u.id=s.user_id
            WHERE s.id=%s
            LIMIT 1
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        db.close()
        if not row:
            return jsonify({"success": False, "error": "Not found"}), 404

        results = None
        raw = row.get("results_json")
        if isinstance(raw, str) and raw:
            try:
                results = json.loads(raw)
            except Exception:
                results = raw

        scan_obj = {
            "id": row.get("id"),
            "user": row.get("username"),
            "email": row.get("email"),
            "role": row.get("role"),
            "target_url": row.get("target_url"),
            "scan_types": _parse_scan_types(row.get("scan_types")),
            "status": row.get("status"),
            "cancel_requested": bool(row.get("cancel_requested")),
            "cancel_reason": row.get("cancel_reason"),
            "canceled_at": str(row.get("canceled_at")) if row.get("canceled_at") else None,
            "total_vulns": int(row.get("total_vulns") or 0),
            "risk_level": row.get("severity"),
            "started_at": str(row.get("started_at")) if row.get("started_at") else None,
            "completed_at": str(row.get("completed_at")) if row.get("completed_at") else None,
            "results": results,
        }

        return jsonify({"success": True, "scan": scan_obj})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/scans/<int:scan_id>/stop", methods=["POST"])
@admin_required
def admin_scan_stop(scan_id: int):
    """Request cancellation of a running scan.

    Note: scanners run in-process; cancellation is best-effort and checked
    between scan phases.
    """
    data = request.get_json() or {}
    reason = (data.get("reason") or "Stopped by admin").strip()[:255]

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_scans_cancel_columns(cursor)

        cursor.execute("SELECT status, cancel_requested FROM scans WHERE id=%s LIMIT 1", (scan_id,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            db.close()
            return jsonify({"success": False, "error": "Not found"}), 404

        if (row.get("status") or "").lower() != "running":
            cursor.close()
            db.close()
            return jsonify({"success": True, "message": "Scan is not running"})

        cursor.execute(
            """UPDATE scans
               SET cancel_requested=TRUE,
                   cancel_reason=%s
               WHERE id=%s""",
            (reason, scan_id),
        )
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/feedback", methods=["GET"])
@admin_required
def admin_feedback_list():
    q = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()
    category = (request.args.get("category") or "").strip().lower()

    where = []
    params = []

    if q:
        where.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s OR LOWER(f.subject) LIKE %s OR LOWER(f.message) LIKE %s)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])

    if status in ("pending", "resolved"):
        where.append("f.status=%s")
        params.append(status)

    if category in ("bug", "feature", "false_positive", "general"):
        where.append("f.category=%s")
        params.append(category)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)
        cursor.execute(
            f"""
            SELECT f.id, u.username, u.email, f.category, f.subject, f.message, f.status,
                   f.admin_reply, f.replied_at, f.created_at
            FROM feedback f
            JOIN users u ON u.id=f.user_id
            {where_sql}
            ORDER BY f.created_at DESC
            LIMIT 500
            """,
            tuple(params),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        db.close()

        out = []
        for r in rows:
            out.append(
                {
                    "id": r.get("id"),
                    "user": r.get("username"),
                    "category": r.get("category"),
                    "subject": r.get("subject"),
                    "message": r.get("message"),
                    "status": r.get("status"),
                    "admin_reply": r.get("admin_reply"),
                    "date": str(r.get("created_at")) if r.get("created_at") else None,
                }
            )

        return jsonify({"success": True, "feedback": out})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/feedback/<int:feedback_id>/resolve", methods=["POST"])
@admin_required
def admin_feedback_resolve(feedback_id: int):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)
        cursor.execute("UPDATE feedback SET status='resolved' WHERE id=%s", (feedback_id,))
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/feedback/<int:feedback_id>/reply", methods=["POST"])
@admin_required
def admin_feedback_reply(feedback_id: int):
    data = request.get_json() or {}
    reply = (data.get("reply") or "").strip()
    if not reply:
        return jsonify({"success": False, "error": "Reply required"}), 400

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)
        cursor.execute(
            "UPDATE feedback SET admin_reply=%s, replied_at=NOW() WHERE id=%s",
            (reply, feedback_id),
        )
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/feedback/<int:feedback_id>", methods=["DELETE"])
@admin_required
def admin_feedback_delete(feedback_id: int):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)
        cursor.execute("DELETE FROM feedback WHERE id=%s", (feedback_id,))
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/vulnerabilities", methods=["GET"])
@admin_required
def admin_vulnerabilities_list():
    """System-wide vulnerabilities with filters."""
    severity = (request.args.get("severity") or "").strip().lower()
    vuln_type = (request.args.get("vuln_type") or "").strip().lower()
    triage = (request.args.get("triage") or "").strip().lower()  # unreviewed|confirmed|false_positive
    q = (request.args.get("q") or "").strip().lower()

    where = []
    params = []

    if severity in ("critical", "high", "medium", "low", "info"):
        where.append("LOWER(v.severity)=%s")
        params.append(severity)

    if triage in ("unreviewed", "confirmed", "false_positive"):
        where.append("v.triage_status=%s")
        params.append(triage)

    if vuln_type:
        where.append("LOWER(v.vuln_type)=%s")
        params.append(vuln_type)

    if q:
        where.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s OR LOWER(s.target_url) LIKE %s OR LOWER(v.url) LIKE %s OR LOWER(v.description) LIKE %s)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_vulnerabilities_triage_columns(cursor)

        cursor.execute(
            f"""
            SELECT v.id, v.vuln_type, v.severity, v.triage_status, v.triaged_at,
                   v.url, v.parameter, v.payload, v.description, v.found_at,
                   s.id AS scan_id, s.scan_types, s.target_url, s.status AS scan_status, s.started_at,
                   u.id AS user_id, u.username, u.email
            FROM vulnerabilities v
            JOIN scans s ON s.id=v.scan_id
            JOIN users u ON u.id=s.user_id
            {where_sql}
            ORDER BY v.found_at DESC
            LIMIT 1000
            """,
            tuple(params),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        db.close()

        vulns = []
        for r in rows:
            vulns.append(
                {
                    "id": r.get("id"),
                    "scan_id": r.get("scan_id"),
                    "user": r.get("username"),
                    "email": r.get("email"),
                    "target_url": r.get("target_url"),
                    "scan_types": _parse_scan_types(r.get("scan_types")),
                    "scan_status": r.get("scan_status"),
                    "vuln_type": r.get("vuln_type"),
                    "severity": r.get("severity"),
                    "triage_status": r.get("triage_status") or "unreviewed",
                    "triaged_at": str(r.get("triaged_at")) if r.get("triaged_at") else None,
                    "url": r.get("url"),
                    "parameter": r.get("parameter"),
                    "payload": r.get("payload"),
                    "description": r.get("description"),
                    "found_at": str(r.get("found_at")) if r.get("found_at") else None,
                }
            )

        return jsonify({"success": True, "vulnerabilities": vulns})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/vulnerabilities/bulk/triage", methods=["POST"])
@admin_required
def admin_vulnerabilities_bulk_triage():
    """Bulk update triage status for multiple vulnerabilities."""
    data = request.get_json() or {}
    ids = data.get("ids", [])
    status = (data.get("status") or "").strip().lower()

    if not isinstance(ids, list) or not ids:
        return jsonify({"success": False, "error": "Invalid IDs list"}), 400
    if status not in ("unreviewed", "confirmed", "false_positive"):
        return jsonify({"success": False, "error": "Invalid status"}), 400

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_vulnerabilities_triage_columns(cursor)

        placeholders = ",".join(["%s"] * len(ids))
        cursor.execute(
            f"UPDATE vulnerabilities SET triage_status=%s, triaged_at=NOW() WHERE id IN ({placeholders})",
            (status, *ids),
        )
        db.commit()
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/vulnerabilities/bulk/delete", methods=["POST"])
@admin_required
def admin_vulnerabilities_bulk_delete():
    """Bulk delete multiple vulnerabilities."""
    data = request.get_json() or {}
    ids = data.get("ids", [])

    if not isinstance(ids, list) or not ids:
        return jsonify({"success": False, "error": "Invalid IDs list"}), 400

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        placeholders = ",".join(["%s"] * len(ids))
        cursor.execute(f"DELETE FROM vulnerabilities WHERE id IN ({placeholders})", tuple(ids))
        db.commit()
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/vulnerabilities/<int:vuln_id>", methods=["DELETE"])
@admin_required
def admin_vulnerability_delete(vuln_id: int):
    """Hard-delete a vulnerability record (admin only)."""
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("DELETE FROM vulnerabilities WHERE id=%s", (vuln_id,))
        db.commit()
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@admin_bp.route("/vulnerabilities/<int:vuln_id>/triage", methods=["POST"])
@admin_required
def admin_vulnerability_triage(vuln_id: int):
    data = request.get_json() or {}
    status = (data.get("status") or "").strip().lower()
    if status not in ("unreviewed", "confirmed", "false_positive"):
        return jsonify({"success": False, "error": "Invalid status"}), 400

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_vulnerabilities_triage_columns(cursor)
        cursor.execute(
            "UPDATE vulnerabilities SET triage_status=%s, triaged_at=NOW() WHERE id=%s",
            (status, vuln_id),
        )
        cursor.close()
        db.close()
        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
