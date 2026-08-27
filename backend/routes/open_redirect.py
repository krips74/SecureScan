from flask import Blueprint, request, jsonify
import logging

from scanners.open_redirect_scanner import OpenRedirectScanner
from utils.scan_storage import create_running_scan, finalize_scan

scanner = OpenRedirectScanner()
logger = logging.getLogger(__name__)
redirect_bp = Blueprint("open_redirect", __name__)


@redirect_bp.route("/scan", methods=["POST"])
def scan_redirect():
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

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        url = data.get("url")
        if not url or not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Valid URL required"}), 400

        parameters = data.get("parameters")

        logger.info(f"Starting Open Redirect scan for: {url}")

        # Create running scan record if authenticated
        scan_id = None
        if user_id:
            scan_id = create_running_scan(user_id, url, ["open_redirect"])

        result = scanner.scan_url(
            url,
            parameters=parameters,
            timeout=10,
            scan_id=scan_id,
        )

        if result.get("success"):
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["open_redirect"], result, status="completed")
                result["scan_id"] = scan_id
            return jsonify({"success": True, "data": result}), 200
        return jsonify({"success": False, "error": result.get("error")}), 500

    except Exception as e:
        logger.error(f"Redirect scan error: {e}")
        if 'scan_id' in locals() and scan_id is not None and 'user_id' in locals() and user_id is not None:
            try:
                finalize_scan(scan_id, user_id, url if 'url' in locals() else '', ["open_redirect"], {"success": False, "error": str(e)}, status="failed")
            except Exception:
                pass
        if "stopped by user" in (str(e) or "").lower():
            return jsonify({"success": False, "error": "Scan cancelled by user"}), 409
        return jsonify({"success": False, "error": str(e)}), 500


@redirect_bp.route("/scan/batch", methods=["POST"])
def scan_redirect_batch():
    try:
        data = request.get_json()
        urls = data.get("urls", [])
        if not urls or len(urls) > 50:
            return jsonify({"success": False, "error": "1-50 URLs required"}), 400
        result = scanner.scan_batch(urls)
        return jsonify({"success": True, "data": result}), 200
    except Exception as e:
        logger.error(f"Redirect batch error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@redirect_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True, "status": "healthy",
        "scanner": "Open Redirect Scanner", "available": True,
        "payloads_loaded": len(scanner.payloads),
    }), 200
