from flask import Blueprint, request, jsonify
from database import get_db
from utils.scan_storage import is_cancel_requested

scans_bp = Blueprint("scans", __name__)


@scans_bp.route("/<int:scan_id>/stop", methods=["POST"])
def stop_scan(scan_id: int):
    """Request cancellation of a running scan (user can only stop their own scans)."""
    # Authenticate user
    try:
        from routes.auth import verify_token
        payload = verify_token(request)
        if not payload or not payload.get("user_id"):
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        user_id = payload["user_id"]
    except Exception as e:
        return jsonify({"success": False, "error": "Authentication failed"}), 401

    # Verify ownership and that scan is running
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT user_id, status FROM scans WHERE id=%s LIMIT 1", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        if row["user_id"] != user_id:
            return jsonify({"success": False, "error": "Not authorized"}), 403
        if row["status"] != "running":
            return jsonify({"success": False, "error": f"Scan is not running (status: {row['status']})"}), 400

        # Set cancel flag
        cursor.execute("UPDATE scans SET cancel_requested=TRUE, canceled_at=NOW() WHERE id=%s", (scan_id,))
        db.commit()
        cursor.close()
        db.close()
        return jsonify({"success": True, "message": "Cancellation requested"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
