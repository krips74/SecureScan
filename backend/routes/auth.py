import os
from datetime import datetime, timedelta
import re
import hashlib
import hmac
import secrets
import shutil
import subprocess

import bcrypt
import jwt
from dotenv import load_dotenv
from flask import Blueprint, jsonify, request, current_app, redirect

from database import get_db

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

auth_bp = Blueprint("auth", __name__)
JWT_SECRET = os.getenv("JWT_SECRET", "change_me")

_OTP_TTL_MINUTES = 10
_RESET_TOKEN_TTL_MINUTES = 15
_OTP_MAX_ATTEMPTS = 5

_EMAIL_VERIFY_TTL_HOURS = 24

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_INDEX_NAME_RE = re.compile(r"^[a-zA-Z0-9_]+$")


def _ensure_password_resets_table(cursor) -> None:
    """Best-effort migration: create password reset table if missing."""
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            id                INT AUTO_INCREMENT PRIMARY KEY,
            user_id           INT NOT NULL,
            otp_hash          CHAR(64) NOT NULL,
            otp_expires_at    DATETIME NOT NULL,
            otp_verified_at   DATETIME NULL,
            reset_token_hash  CHAR(64) NULL,
            reset_expires_at  DATETIME NULL,
            attempts          INT DEFAULT 0,
            created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_pr_user (user_id),
            INDEX idx_pr_otp_exp (otp_expires_at),
            INDEX idx_pr_reset_exp (reset_expires_at)
        ) ENGINE=InnoDB
        """
    )


def _hash_secret(value: str) -> str:
    """Server-side keyed hash for OTPs/tokens stored in DB."""
    key = (JWT_SECRET or "change_me").encode("utf-8")
    msg = (value or "").encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _send_otp_via_nodemailer(to_email: str, otp: str) -> None:
    """Send OTP email by invoking Node.js nodemailer script."""
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is not installed or not on PATH")

    script_path = os.path.join(os.path.dirname(__file__), "..", "utils", "send_otp.js")
    script_path = os.path.abspath(script_path)
    if not os.path.isfile(script_path):
        raise RuntimeError("Mailer script missing")

    # Run: node send_otp.js <toEmail> <otp>
    # Inherits env (including .env loaded by python-dotenv)
    res = subprocess.run(
        [node, script_path, to_email, otp],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(err or "Failed to send OTP")


def _ensure_email_verifications_table(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            user_id     INT NOT NULL,
            token_hash  CHAR(64) NOT NULL,
            expires_at  DATETIME NOT NULL,
            used_at     DATETIME NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE KEY uq_ev_token (token_hash),
            INDEX idx_ev_user (user_id),
            INDEX idx_ev_exp (expires_at)
        ) ENGINE=InnoDB
        """
    )


def _ensure_users_email_verified_columns(cursor) -> None:
    """Best-effort migration: add verification columns if missing."""
    try:
        cursor.execute("SHOW COLUMNS FROM users LIKE 'email_verified'")
        has_verified = cursor.fetchone() is not None
        cursor.execute("SHOW COLUMNS FROM users LIKE 'email_verified_at'")
        has_verified_at = cursor.fetchone() is not None

        if not has_verified:
            cursor.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE")
        if not has_verified_at:
            cursor.execute("ALTER TABLE users ADD COLUMN email_verified_at DATETIME NULL")
    except Exception:
        return


def _send_verification_link_via_nodemailer(to_email: str, verify_url: str) -> None:
    """Send verification link email by invoking Node.js nodemailer script."""
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is not installed or not on PATH")

    script_path = os.path.join(os.path.dirname(__file__), "..", "utils", "send_verification.js")
    script_path = os.path.abspath(script_path)
    if not os.path.isfile(script_path):
        raise RuntimeError("Mailer script missing")

    res = subprocess.run(
        [node, script_path, to_email, verify_url],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(err or "Failed to send verification email")


def _drop_unique_username_index(cursor) -> None:
    """Best-effort migration: remove UNIQUE constraint on users.username.

    Older schema versions created a unique index for the username column.
    This app now treats usernames as display names (not unique identifiers).
    """
    try:
        cursor.execute("SHOW INDEX FROM users WHERE Column_name='username' AND Non_unique=0")
        rows = cursor.fetchall() or []
        for r in rows:
            key_name = (r.get("Key_name") or "").strip()
            if not key_name or key_name.upper() == "PRIMARY":
                continue
            if not _INDEX_NAME_RE.match(key_name):
                continue
            cursor.execute(f"ALTER TABLE users DROP INDEX `{key_name}`")
    except Exception:
        # Ignore migration failures (e.g., permissions, table missing)
        return


def make_token(user_id, username, role):
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"success": False, "error": "All fields required"}), 400
    if not _USERNAME_RE.match(username):
        return jsonify({"success": False, "error": "Username must be 3-32 chars (letters, numbers, underscore)"}), 400
    if not _EMAIL_RE.match(email):
        return jsonify({"success": False, "error": "Invalid email"}), 400
    if len(password) < 8:
        return jsonify({"success": False, "error": "Password must be ≥ 8 characters"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        db = get_db()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cursor = db.cursor(dictionary=True)
    try:
        _ensure_users_email_verified_columns(cursor)
        _ensure_email_verifications_table(cursor)

        # Ensure email is the only unique identifier; username may repeat.
        _drop_unique_username_index(cursor)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, hashed),
        )
        user_id = cursor.lastrowid

        # Create a fresh email verification token (store only hashed token)
        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_secret(raw_token)
        expires_at = datetime.utcnow() + timedelta(hours=_EMAIL_VERIFY_TTL_HOURS)

        cursor.execute("DELETE FROM email_verifications WHERE user_id=%s", (user_id,))
        cursor.execute(
            "INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user_id, token_hash, expires_at),
        )

        base_url = (os.getenv("APP_BASE_URL") or request.host_url or "").strip()
        base_url = base_url.rstrip("/")
        if not base_url:
            raise RuntimeError("Could not determine application base URL")
        verify_url = f"{base_url}/api/auth/verify-email?token={raw_token}"

        try:
            _send_verification_link_via_nodemailer(email, verify_url)
        except Exception:
            # If we can't email the link, rollback the account creation for clarity
            cursor.execute("DELETE FROM email_verifications WHERE user_id=%s", (user_id,))
            cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
            raise

        return jsonify(
            {
                "success": True,
                "message": "Account created. Please verify your email before signing in.",
            }
        ), 201
    except Exception as e:
        msg = str(e)
        if "Duplicate" in msg:
            if "email" in msg:
                return jsonify({"success": False, "error": "Email already exists"}), 409
            if "username" in msg:
                # This can still happen if the DB wasn't migrated.
                return jsonify({"success": False, "error": "Username is currently set as unique in the database. Please migrate schema or use a different username."}), 409
            return jsonify({"success": False, "error": "Duplicate value"}), 409
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        db.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    identifier = email or username
    if not identifier or not password:
        return jsonify({"success": False, "error": "Email/username and password required"}), 400

    try:
        db = get_db()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cursor = db.cursor(dictionary=True)
    try:
        _ensure_users_email_verified_columns(cursor)

        if email:
            cursor.execute(
                "SELECT id, username, email, password_hash, role, email_verified FROM users WHERE email=%s AND is_active=1",
                (email,),
            )
            user = cursor.fetchone()
        else:
            cursor.execute(
                "SELECT id, username, email, password_hash, role, email_verified FROM users WHERE username=%s AND is_active=1",
                (username,),
            )
            users = cursor.fetchall() or []
            if len(users) > 1:
                return jsonify({"success": False, "error": "Multiple accounts share this username. Please sign in with email."}), 409
            user = users[0] if users else None
        if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        # Admins must use the admin control-panel session login.
        # This prevents admins from obtaining a user JWT and accessing user scan UI.
        if (user.get("role") or "").lower() == "admin":
            return jsonify({"success": False, "error": "Admin accounts must sign in via the admin portal."}), 403

        if not bool(user.get("email_verified")):
            return jsonify({"success": False, "error": "Please verify your email before signing in."}), 403

        cursor.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))
        token = make_token(user["id"], user["username"], user["role"])
        return jsonify(
            {
                "success": True,
                "token": token,
                "username": user["username"],
                "email": user.get("email"),
                "role": user["role"],
            }
        ), 200
    finally:
        cursor.close()
        db.close()


@auth_bp.route("/verify-email", methods=["GET"])
def verify_email():
    token = (request.args.get("token") or "").strip()
    if not token or len(token) < 16:
        return redirect("/login.html?verified=0")

    token_hash = _hash_secret(token)

    try:
        db = get_db()
    except Exception:
        return redirect("/login.html?verified=0")

    cursor = db.cursor(dictionary=True)
    try:
        _ensure_users_email_verified_columns(cursor)
        _ensure_email_verifications_table(cursor)

        cursor.execute(
            """
            SELECT ev.id AS ev_id, ev.user_id, ev.expires_at, ev.used_at,
                   u.email_verified
            FROM email_verifications ev
            JOIN users u ON u.id = ev.user_id
            WHERE ev.token_hash=%s
            LIMIT 1
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if not row:
            return redirect("/login.html?verified=0")

        if bool(row.get("email_verified")):
            return redirect("/login.html?verified=1")

        if row.get("used_at") is not None:
            return redirect("/login.html?verified=1")

        expires_at = row.get("expires_at")
        if not expires_at or datetime.utcnow() > expires_at:
            return redirect("/login.html?verified=0")

        cursor.execute(
            "UPDATE users SET email_verified=1, email_verified_at=NOW() WHERE id=%s",
            (row["user_id"],),
        )
        cursor.execute(
            "UPDATE email_verifications SET used_at=NOW() WHERE id=%s",
            (row["ev_id"],),
        )
        return redirect("/login.html?verified=1")
    finally:
        cursor.close()
        db.close()


def verify_token(req):
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth_header[7:], JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


@auth_bp.route("/logout", methods=["POST"])
def logout_route():
    """JWT logout is client-side; this endpoint exists for completeness."""
    return jsonify({"success": True}), 200


@auth_bp.route("/password-reset/request", methods=["POST"])
def password_reset_request():
    """Request an OTP for password reset (always returns success)."""
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    if not email or not _EMAIL_RE.match(email):
        return jsonify({"success": False, "error": "Invalid email"}), 400

    try:
        db = get_db()
    except Exception:
        # Keep response generic
        return jsonify({"success": True}), 200

    cursor = db.cursor(dictionary=True)
    try:
        _ensure_password_resets_table(cursor)
        cursor.execute("SELECT id FROM users WHERE email=%s AND is_active=1 LIMIT 1", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"success": True}), 200

        user_id = int(user["id"])

        # Replace any existing reset attempts for this user.
        cursor.execute("DELETE FROM password_resets WHERE user_id=%s", (user_id,))

        otp = f"{secrets.randbelow(1_000_000):06d}"
        otp_hash = _hash_secret(otp)

        cursor.execute(
            """
            INSERT INTO password_resets (user_id, otp_hash, otp_expires_at, attempts)
            VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL %s MINUTE), 0)
            """,
            (user_id, otp_hash, _OTP_TTL_MINUTES),
        )

        # Send OTP via NodeMailer.
        _send_otp_via_nodemailer(email, otp)
        return jsonify({"success": True}), 200
    except Exception as e:
        # Do not leak details; client should just show generic message.
        try:
            current_app.logger.warning(f"Password reset OTP send failed: {e}")
        except Exception:
            pass
        return jsonify({"success": True}), 200
    finally:
        cursor.close()
        db.close()


@auth_bp.route("/password-reset/verify", methods=["POST"])
def password_reset_verify():
    """Verify OTP and return a short-lived reset token."""
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    otp = (data.get("otp") or "").strip()

    if not email or not _EMAIL_RE.match(email):
        return jsonify({"success": False, "error": "Invalid email"}), 400
    if not re.fullmatch(r"\d{6}", otp or ""):
        return jsonify({"success": False, "error": "Invalid OTP"}), 400

    try:
        db = get_db()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cursor = db.cursor(dictionary=True)
    try:
        _ensure_password_resets_table(cursor)
        cursor.execute("SELECT id FROM users WHERE email=%s AND is_active=1 LIMIT 1", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"success": False, "error": "Invalid OTP"}), 400
        user_id = int(user["id"])

        cursor.execute(
            """
            SELECT id, otp_hash, otp_expires_at, otp_verified_at, attempts,
                   (otp_expires_at > NOW()) AS otp_valid
            FROM password_resets
            WHERE user_id=%s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Invalid OTP"}), 400

        if row.get("otp_verified_at") is not None:
            return jsonify({"success": False, "error": "OTP already used"}), 400

        if int(row.get("attempts") or 0) >= _OTP_MAX_ATTEMPTS:
            return jsonify({"success": False, "error": "Too many attempts"}), 429

        if not row.get("otp_valid"):
            return jsonify({"success": False, "error": "OTP expired"}), 400

        if _hash_secret(otp) != (row.get("otp_hash") or ""):
            cursor.execute(
                "UPDATE password_resets SET attempts=attempts+1 WHERE id=%s",
                (row["id"],),
            )
            return jsonify({"success": False, "error": "Invalid OTP"}), 400

        reset_token = secrets.token_urlsafe(32)
        reset_hash = _hash_secret(reset_token)
        cursor.execute(
            """
            UPDATE password_resets
            SET otp_verified_at=NOW(), reset_token_hash=%s,
                reset_expires_at=DATE_ADD(NOW(), INTERVAL %s MINUTE)
            WHERE id=%s
            """,
            (reset_hash, _RESET_TOKEN_TTL_MINUTES, row["id"]),
        )

        return jsonify({"success": True, "reset_token": reset_token}), 200
    finally:
        cursor.close()
        db.close()


@auth_bp.route("/password-reset/confirm", methods=["POST"])
def password_reset_confirm():
    """Set new password after OTP verification."""
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    reset_token = (data.get("reset_token") or "").strip()
    new_password = data.get("new_password") or ""

    if not email or not _EMAIL_RE.match(email):
        return jsonify({"success": False, "error": "Invalid email"}), 400
    if not reset_token or len(reset_token) < 20:
        return jsonify({"success": False, "error": "Invalid reset token"}), 400
    if len(new_password) < 8:
        return jsonify({"success": False, "error": "Password must be ≥ 8 characters"}), 400

    try:
        db = get_db()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cursor = db.cursor(dictionary=True)
    try:
        _ensure_password_resets_table(cursor)
        cursor.execute("SELECT id FROM users WHERE email=%s AND is_active=1 LIMIT 1", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"success": False, "error": "Invalid reset token"}), 400
        user_id = int(user["id"])

        reset_hash = _hash_secret(reset_token)
        cursor.execute(
            """
            SELECT id, reset_expires_at, otp_verified_at, reset_token_hash,
                   (reset_expires_at > NOW()) AS reset_valid
            FROM password_resets
            WHERE user_id=%s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Invalid reset token"}), 400
        if row.get("otp_verified_at") is None:
            return jsonify({"success": False, "error": "OTP not verified"}), 400
        if (row.get("reset_token_hash") or "") != reset_hash:
            return jsonify({"success": False, "error": "Invalid reset token"}), 400

        if not row.get("reset_valid"):
            return jsonify({"success": False, "error": "Reset token expired"}), 400

        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("UPDATE users SET password_hash=%s WHERE id=%s", (hashed, user_id))
        cursor.execute("DELETE FROM password_resets WHERE user_id=%s", (user_id,))
        return jsonify({"success": True}), 200
    finally:
        cursor.close()
        db.close()
