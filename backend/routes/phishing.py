from flask import Blueprint, request, jsonify
import logging

from scanners.phishing_scanner import PhishingScanner
from utils.scan_storage import create_running_scan, finalize_scan

scanner = PhishingScanner()
logger = logging.getLogger(__name__)
phishing_bp = Blueprint("phishing", __name__)


@phishing_bp.route("/check", methods=["POST"])
def check_phishing():
    """Check a URL for phishing indicators."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        url = data.get("url")
        if not url:
            return jsonify({"success": False, "error": "URL required"}), 400

        result = scanner.check_url(url)

        return jsonify({"success": True, "data": result}), 200

    except Exception as e:
        logger.error(f"Phishing check error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@phishing_bp.route("/scan", methods=["POST"])
def scan_phishing():
    """Scan a URL for phishing indicators.

    Mirrors other scanners (XSS/SQLi/etc.): returns a result object and, when the
    request is authenticated, persists the scan and includes a scan_id.
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

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        url = data.get("url")
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400

        if isinstance(url, str) and not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Valid URL required (http/https)"}), 400

        logger.info(f"Starting Phishing scan for: {url}")

        # Create running scan record if authenticated
        scan_id = None
        if user_id:
            scan_id = create_running_scan(user_id, url, ["phishing"])

        result = scanner.check_url(url, scan_id=scan_id)

        if result.get("success"):
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["phishing"], result, status="completed")
                result["scan_id"] = scan_id
            return jsonify({"success": True, "data": result}), 200
        else:
            msg = result.get("error", "Unknown")
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["phishing"], result, status="failed")
            return jsonify({"success": False, "error": msg}), 500

    except Exception as e:
        logger.error(f"Phishing scan error: {e}")
        if 'scan_id' in locals() and scan_id is not None and 'user_id' in locals() and user_id is not None:
            try:
                finalize_scan(scan_id, user_id, url if 'url' in locals() else '', ["phishing"], {"success": False, "error": str(e)}, status="failed")
            except Exception:
                pass
        if "stopped by user" in (str(e) or "").lower():
            return jsonify({"success": False, "error": "Scan cancelled by user"}), 409
        return jsonify({"success": False, "error": str(e)}), 500


@phishing_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True, "status": "healthy",
        "scanner": "Phishing Scanner",
        "available": True,
        "feed_size": len(scanner.feed_urls),
    }), 200
