from flask import Blueprint, request, jsonify
import os
import logging

from scanners.sqli_scanner import SQLiScanner
from utils.scan_storage import create_running_scan, finalize_scan, is_cancel_requested

scanner = SQLiScanner(
    payload_file=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanners", "sqli-payload.txt")
)
logger = logging.getLogger(__name__)
sqli_bp = Blueprint("sqli", __name__)


@sqli_bp.route("/scan", methods=["POST"])
def scan_sqli():
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
            return jsonify({"success": False, "error": "Valid URL required (http/https)"}), 400

        safe_mode = data.get("safe_mode", True)
        method = data.get("method", "GET")
        body_template = data.get("body_template")
        custom_payloads = data.get("custom_payloads")
        parameters = data.get("parameters")
        timeout = data.get("timeout", 10)
        stop_on_first = data.get("stop_on_first", False)
        if isinstance(stop_on_first, str):
            stop_on_first = stop_on_first.strip().lower() in ("1", "true", "yes", "y", "on")

        logger.info(f"Starting SQLi scan for: {url} (safe_mode={safe_mode})")

        # Create running scan record if authenticated
        scan_id = None
        if user_id:
            scan_id = create_running_scan(user_id, url, ["sqli"])

        result = scanner.scan_url(
            url,
            parameters=parameters,
            safe_mode=safe_mode,
            method=method,
            body_template=body_template,
            custom_payloads=custom_payloads,
            timeout=timeout,
            stop_on_first=stop_on_first,
            scan_id=scan_id,
        )

        if result.get("success"):
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["sqli"], result, status="completed")
                result["scan_id"] = scan_id
            return jsonify({"success": True, "data": result}), 200
        else:
            msg = result.get("error", "Unknown")
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["sqli"], result, status="failed")
            return jsonify({"success": False, "error": msg}), 500

    except Exception as e:
        logger.error(f"SQLi scan error: {e}")
        if 'scan_id' in locals() and scan_id is not None and 'user_id' in locals() and user_id is not None:
            try:
                finalize_scan(scan_id, user_id, url if 'url' in locals() else '', ["sqli"], {"success": False, "error": str(e)}, status="failed")
            except Exception:
                pass
        if "stopped by user" in (str(e) or "").lower():
            return jsonify({"success": False, "error": "Scan cancelled by user"}), 409
        return jsonify({"success": False, "error": str(e)}), 500


@sqli_bp.route("/scan/batch", methods=["POST"])
def scan_sqli_batch():
    try:
        data = request.get_json()
        urls = data.get("urls", [])
        if not urls or len(urls) > 50:
            return jsonify({"success": False, "error": "1-50 URLs required"}), 400

        safe_mode = data.get("safe_mode", True)
        result = scanner.scan_batch(urls, safe_mode=safe_mode)
        return jsonify({"success": True, "data": result}), 200

    except Exception as e:
        logger.error(f"SQLi batch error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@sqli_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "healthy",
        "scanner": "SQLi Scanner",
        "available": True,
        "safe_payloads": len(scanner.payloads.get("safe", [])),
        "unsafe_payloads": len(scanner.payloads.get("time_based", [])) + len(scanner.payloads.get("union_based", [])),
    }), 200
