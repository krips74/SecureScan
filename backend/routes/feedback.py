import os
from typing import Any

from dotenv import load_dotenv
from flask import Blueprint, jsonify, request

from database import get_db

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

feedback_bp = Blueprint("feedback", __name__)


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


def _normalize_category(value: Any) -> str:
    v = (value or "").strip().lower()
    if v in ("bug", "feature", "false_positive", "general"):
        return v
    if v in ("falsepositive", "false-positive", "fp"):
        return "false_positive"
    if v in ("feature_request", "feature-request", "request"):
        return "feature"
    return "general"


@feedback_bp.route("/submit", methods=["POST"])
def submit_feedback():
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    subject = (data.get("subject") or "").strip()
    message = (data.get("message") or "").strip()
    category = _normalize_category(data.get("category"))

    if not subject or not message:
        return jsonify({"success": False, "error": "Subject and message are required"}), 400

    if len(subject) > 200:
        return jsonify({"success": False, "error": "Subject too long"}), 400

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)
        cursor.execute(
            "INSERT INTO feedback (user_id, subject, message, category, status) VALUES (%s, %s, %s, %s, 'pending')",
            (payload["user_id"], subject, message, category),
        )
        feedback_id = cursor.lastrowid
        cursor.close()
        db.close()
        return jsonify({"success": True, "id": feedback_id})
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503


@feedback_bp.route("/mine", methods=["GET"])
def list_my_feedback():
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        _ensure_feedback_table(cursor)
        cursor.execute(
            """
            SELECT id, category, subject, message, status, admin_reply, created_at
            FROM feedback
            WHERE user_id=%s
            ORDER BY created_at DESC
            LIMIT 200
            """,
            (payload["user_id"],),
        )
        rows = cursor.fetchall() or []
        cursor.close()
        db.close()

        out = []
        for r in rows:
            out.append(
                {
                    "id": r.get("id"),
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
