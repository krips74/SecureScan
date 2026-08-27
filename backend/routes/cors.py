from flask import Blueprint, jsonify, request
import logging

from scanners.cors_scanner import CORSScanner
from utils.scan_storage import create_running_scan, finalize_scan

logger = logging.getLogger(__name__)
scanner = CORSScanner()
cors_bp = Blueprint("cors", __name__)


@cors_bp.route("/scan", methods=["POST"])
def scan_cors():
    """CORS misconfiguration tester (defensive).

    Input JSON:
      {"url": "https://target.tld/path"}

    Performs only non-destructive GET/OPTIONS probes with a controlled Origin.
    """
    try:
        # Authentication: get user_id if available
        user_id = None
        try:
            from routes.auth import verify_token
            payload = verify_token(request)
            if payload and payload.get("user_id"):
                user_id = payload["user_id"]
        except Exception:
            pass

        data = request.get_json() or {}
        url = data.get("url")
        if not url or not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Valid URL required"}), 400

        logger.info(f"Starting CORS scan for: {url}")

        scan_id = None
        if user_id:
            scan_id = create_running_scan(user_id, url, ["cors"])

        result = scanner.scan_url(url, scan_id=scan_id)

        if result.get("success"):
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["cors"], result, status="completed")
                result["scan_id"] = scan_id
            return jsonify({"success": True, "data": result}), 200
        else:
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["cors"], result, status="failed")
            return jsonify({"success": False, "error": result.get("error")}), 500

    except Exception as e:
        logger.error(f"CORS scan error: {e}")
        if 'scan_id' in locals() and scan_id is not None and 'user_id' in locals() and user_id is not None:
            try:
                finalize_scan(scan_id, user_id, url if 'url' in locals() else '', ["cors"], {"success": False, "error": str(e)}, status="failed")
            except Exception:
                pass
        if "stopped by user" in (str(e) or "").lower():
            return jsonify({"success": False, "error": "Scan cancelled by user"}), 409
        return jsonify({"success": False, "error": str(e)}), 500


@cors_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "healthy",
        "scanner": "CORS Scanner",
        "available": True,
    }), 200
