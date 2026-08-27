import os
import sys
import warnings
from flask import Flask, jsonify, request, send_from_directory, redirect
from flask_cors import CORS
import logging
from datetime import datetime
import urllib3
import json
import requests

# Suppress SSL warnings for scanning (we intentionally skip verification)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), 'frontend')
sys.path.insert(0, BASE_DIR)

import config

from database import get_db
from utils.scan_storage import save_scan_to_db

# Initialize Flask app.
# NOTE: Do not mount Flask's built-in static route at the URL root (""), because it can
# intercept GET / and return a 404 before our explicit @app.route('/') handler runs.
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='/static')

# Required for session-based features (admin login).
app.secret_key = os.getenv("FLASK_SECRET_KEY") or getattr(config, "JWT_SECRET", "dev_secret_change_in_prod")
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
# In production behind HTTPS, set SESSION_COOKIE_SECURE=1 in env.
app.config["SESSION_COOKIE_SECURE"] = (os.getenv("SESSION_COOKIE_SECURE") or "0").strip().lower() in ("1", "true", "yes")


@app.after_request
def set_security_headers(resp):
    # Baseline hardening headers
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    resp.headers.setdefault("X-XSS-Protection", "0")

    # CSP tuned for current static pages (allows inline scripts/styles used by existing HTML)
    csp = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "upgrade-insecure-requests"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    return resp

# Configure CORS — allow all origins + chrome extensions
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configure logging
if not getattr(config, "LOG_TO_FILE", False):
    try:
        stale_log_path = os.path.join(config.LOGS_DIR, "scan_logs.txt")
        if os.path.exists(stale_log_path):
            os.remove(stale_log_path)
    except OSError:
        # Best-effort cleanup; file can be locked on Windows if an old server process is still running.
        pass

log_handlers = [logging.StreamHandler()]
if getattr(config, "LOG_TO_FILE", False):
    os.makedirs(config.LOGS_DIR, exist_ok=True)
    log_handlers.insert(0, logging.FileHandler(os.path.join(config.LOGS_DIR, 'scan_logs.txt')))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers,
)

logger = logging.getLogger(__name__)


# ── Import route blueprints ──────────────────────────────────────
from routes.xss import xss_bp
from routes.sqli import sqli_bp
from routes.open_redirect import redirect_bp
from routes.cors import cors_bp
from routes.header_scan import headers_bp
from routes.phishing import phishing_bp
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.feedback import feedback_bp
from routes.scans import scans_bp

# ── Register blueprints ─────────────────────────────────────────
app.register_blueprint(xss_bp, url_prefix='/api/xss')
app.register_blueprint(sqli_bp, url_prefix='/api/sqli')
app.register_blueprint(redirect_bp, url_prefix='/api/open-redirect')
app.register_blueprint(cors_bp, url_prefix='/api/cors')
app.register_blueprint(headers_bp, url_prefix='/api/headers')
app.register_blueprint(phishing_bp, url_prefix='/api/phishing')
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(feedback_bp, url_prefix='/api/feedback')
app.register_blueprint(scans_bp, url_prefix='/api/scans')


# ── Unified Scan Endpoint ───────────────────────────────────────
@app.route('/api/scan/unified', methods=['POST'])
def unified_scan():
    """
    Run multiple scan types in one request.
    
    Request JSON:
    {
        "url": "https://target.com",
        "scan_types": ["xss", "sqli", "headers", "open_redirect", "cors"],
        "method": "GET",
        "options": {
            "safe_mode": true,
            "timeout": 10
        },
        "auth": {
            "high": { ...login_config... },
            "low": { ...login_config... }
        },
        "endpoints": ["/admin", "/api/users"]
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        url = data.get("url", "")
        requested_scan_types = data.get("scan_types", [])
        allowed_scan_types = {
            "xss",
            "sqli",
            "headers",
            "open_redirect",
            "cors",
            "phishing",
        }
        scan_types = [scan_type for scan_type in requested_scan_types if scan_type in allowed_scan_types]
        options = data.get("options", {})
        timeout = options.get("timeout", config.DEFAULT_TIMEOUT)
        safe_mode = options.get("safe_mode", config.SCAN_SAFE_MODE)

        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400

        # Setup auth if provided (single-session mode)
        auth_session = None
        auth_config = data.get("auth")
        if auth_config:
            high_cfg = auth_config.get("high")
            if high_cfg:
                try:
                    session = requests.Session()
                    # Disable SSL warnings for scanning
                    requests.packages.urllib3.disable_warnings()
                    # Optional: set headers from config
                    custom_headers = high_cfg.get("headers")
                    if custom_headers:
                        session.headers.update(custom_headers)
                    # If a login_url is provided, attempt form login
                    login_url = high_cfg.get("login_url")
                    if login_url:
                        username = high_cfg.get("username", "")
                        password = high_cfg.get("password", "")
                        username_field = high_cfg.get("username_field", "username")
                        password_field = high_cfg.get("password_field", "password")
                        login_data = {username_field: username, password_field: password}
                        resp = session.post(login_url, data=login_data, verify=False, timeout=10)
                        if resp.status_code >= 400:
                            logger.warning(f"Auth login failed: HTTP {resp.status_code}")
                    # Wrap session to provide .session attribute expected by scanners
                    auth_session = type('AuthSession', (), {'session': session})()
                except Exception as e:
                    logger.warning(f"Auth setup failed: {e}")
                    auth_session = None

        # Unified scan is a user action (admins do not run scans).
        from routes.auth import verify_token

        payload = verify_token(request)
        if not payload:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        if (payload.get("role") or "").lower() == "admin":
            return jsonify({"success": False, "error": "Admins cannot run scans."}), 403

        from utils.scan_storage import create_running_scan, is_cancel_requested, finalize_scan

        scan_id = create_running_scan(payload["user_id"], url, scan_types)

        results = {
            "success": True,
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "scan_types": scan_types,
            "scans": {},
            "total_vulnerabilities": 0,
        }

        if scan_id is not None:
            results["scan_id"] = scan_id

        def _maybe_cancel() -> bool:
            if scan_id is None:
                return False
            return bool(is_cancel_requested(int(scan_id)))

        # Run each requested scan type (check cancel requests between phases)
        if "xss" in scan_types:
            if _maybe_cancel():
                raise RuntimeError("Scan stopped by admin")
            # Use the same XSS engine as /api/xss/scan (reflected + DOM + stored).
            # This keeps Advanced Scan results consistent with the dedicated XSS page.
            from routes.xss import _scan_one_url

            # DOM check uses Playwright and needs sufficient time.
            # Match the dedicated XSS scan defaults to ensure consistent results.
            dom_timeout = max(10, min(20, int(timeout or 12)))
            stored_timeout = max(8, min(15, int(timeout or 10)))
            results["scans"]["xss"] = _scan_one_url(
                url=url,
                timeout=timeout,
                max_duration=15,
                include_dom=True,
                dom_timeout=dom_timeout,
                include_stored=True,
                stored_timeout=stored_timeout,
                stop_on_first=True,
            )

        if "sqli" in scan_types:
            if _maybe_cancel():
                raise RuntimeError("Scan stopped by admin")
            from scanners.sqli_scanner import SQLiScanner
            s = SQLiScanner(safe_mode=safe_mode)
            results["scans"]["sqli"] = s.scan_url(url, timeout=timeout, safe_mode=safe_mode,
                                                    method=data.get("method", "GET"),
                                                    auth_session=auth_session)

        if "headers" in scan_types:
            if _maybe_cancel():
                raise RuntimeError("Scan stopped by admin")
            from scanners.header_scanner import HeaderScanner
            s = HeaderScanner()
            results["scans"]["headers"] = s.scan_url(url, timeout=timeout, auth_session=auth_session)

        if "open_redirect" in scan_types:
            if _maybe_cancel():
                raise RuntimeError("Scan stopped by admin")
            from scanners.open_redirect_scanner import OpenRedirectScanner
            s = OpenRedirectScanner()
            results["scans"]["open_redirect"] = s.scan_url(url, timeout=timeout, auth_session=auth_session)

        if "cors" in scan_types:
            if _maybe_cancel():
                raise RuntimeError("Scan stopped by admin")
            from scanners.cors_scanner import CORSScanner
            s = CORSScanner()
            results["scans"]["cors"] = s.scan_url(url, timeout=timeout)

        if "phishing" in scan_types:
            if _maybe_cancel():
                raise RuntimeError("Scan stopped by admin")
            from scanners.phishing_scanner import PhishingScanner

            # Avoid spawning background refresh threads during unified scans.
            s = PhishingScanner(enable_background_refresh=False)
            results["scans"]["phishing"] = s.check_url(url)

        # Sum total vulnerabilities
        for scan_name, scan_result in results["scans"].items():
            results["total_vulnerabilities"] += scan_result.get("total_found", 0)

        # Finalize running scan record (if created)
        if scan_id is not None:
            finalize_scan(int(scan_id), payload["user_id"], url, scan_types, results, status="completed")
        else:
            # Fallback to legacy insert-only persistence
            results["scan_id"] = save_scan_to_db(payload["user_id"], url, scan_types, results)

        return jsonify(results), 200

    except Exception as e:
        try:
            # If we created a running record, finalize as failed with partial results.
            from routes.auth import verify_token
            from utils.scan_storage import finalize_scan

            payload = verify_token(request)
            if payload and 'scan_id' in locals() and scan_id is not None:
                uid = payload.get("user_id")
                if not uid:
                    raise RuntimeError("Missing user_id")
                partial = {
                    "success": False,
                    "target": (locals().get("url") or (data or {}).get("url", "")),
                    "timestamp": datetime.now().isoformat(),
                    "scan_types": (locals().get("scan_types") or (data or {}).get("scan_types", [])),
                    "scans": (locals().get("results") or {}).get("scans", {}),
                    "total_vulnerabilities": (locals().get("results") or {}).get("total_vulnerabilities", 0),
                    "error": str(e),
                }
                finalize_scan(int(scan_id), int(uid), (locals().get("url") or url), (locals().get("scan_types") or scan_types), partial, status="failed")
        except Exception:
            pass

        logger.error(f"Unified scan error: {e}")
        msg = str(e)
        if "stopped by admin" in (msg or "").lower():
            return jsonify({"success": False, "error": msg}), 409
        return jsonify({"success": False, "error": msg}), 500


# ── Extension Quick-Scan ────────────────────────────────────────
@app.route('/api/extension/quick-scan', methods=['POST'])
def extension_quick_scan():
    """Lightweight scan optimized for the Chrome extension popup."""
    try:
        data = request.get_json()
        url = data.get("url", "")
        if not url:
            return jsonify({"success": False, "error": "URL required"}), 400

        from scanners.phishing_scanner import PhishingScanner
        from scanners.header_scanner import HeaderScanner

        phishing_result = PhishingScanner().check_url(url)
        header_result = HeaderScanner().scan_url(url, timeout=5)

        score = phishing_result.get("score", 0)
        header_grade = header_result.get("grade", "?")

        # Only add header penalty when there's already phishing suspicion.
        # Header deficiencies (missing COOP/CORP, etc.) are a separate
        # security concern and should not push trusted, safe sites past the
        # phishing warning threshold.
        header_penalty = {"A": 0, "B": 5, "C": 15, "D": 30, "F": 50}.get(header_grade, 25)
        if phishing_result.get("safe", True) and score == 0:
            header_penalty = min(header_penalty, 10)
        risk = min(100, score + header_penalty)

        return jsonify({
            "success": True,
            "url": url,
            "risk_score": risk,
            "phishing": {"score": score, "safe": phishing_result.get("safe", True), "reasons": phishing_result.get("reasons", [])},
            "headers": {"grade": header_grade, "issues": header_result.get("total_found", 0)},
            "recommendation": "Safe" if risk < 30 else ("Caution" if risk < 60 else "Dangerous"),
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scans/history', methods=['GET'])
def scan_history():
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """SELECT id, target_url, scan_types, status, total_vulns, severity, started_at, completed_at
               FROM scans WHERE user_id=%s ORDER BY started_at DESC LIMIT 50""",
            (payload["user_id"],),
        )
        rows = cursor.fetchall()
        cursor.close()
        db.close()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    for r in rows:
        r["started_at"] = str(r["started_at"]) if r.get("started_at") else None
        r["completed_at"] = str(r["completed_at"]) if r.get("completed_at") else None
        if r.get("scan_types") is not None and not isinstance(r["scan_types"], str):
            r["scan_types"] = json.dumps(r["scan_types"])

    return jsonify({"success": True, "scans": rows})


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id: int):
    """Return a single scan (including stored results_json) for the authenticated user."""
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """SELECT id, target_url, scan_types, status, total_vulns, severity, results_json, started_at, completed_at
               FROM scans WHERE id=%s AND user_id=%s LIMIT 1""",
            (scan_id, payload["user_id"]),
        )
        row = cursor.fetchone()
        cursor.close()
        db.close()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    if not row:
        return jsonify({"success": False, "error": "Not found"}), 404

    # Normalize datetime fields
    row["started_at"] = str(row["started_at"]) if row.get("started_at") else None
    row["completed_at"] = str(row["completed_at"]) if row.get("completed_at") else None

    # Parse scan_types if it is JSON
    scan_types_raw = row.get("scan_types")
    if isinstance(scan_types_raw, str) and scan_types_raw:
        try:
            row["scan_types"] = json.loads(scan_types_raw)
        except Exception:
            row["scan_types"] = scan_types_raw

    # Parse results_json if it is JSON
    results_raw = row.get("results_json")
    if isinstance(results_raw, str) and results_raw:
        try:
            row["results"] = json.loads(results_raw)
        except Exception:
            row["results"] = results_raw
    else:
        row["results"] = None

    # Keep the raw JSON out of the normal response (still available as `results`)
    row.pop("results_json", None)

    return jsonify({"success": True, "scan": row}), 200


@app.route('/api/scans/stats', methods=['GET'])
def scan_stats():
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        uid = payload["user_id"]

        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE user_id=%s", (uid,))
        total_scans = cursor.fetchone()["total"]

        cursor.execute("SELECT COALESCE(SUM(total_vulns),0) AS total FROM scans WHERE user_id=%s", (uid,))
        total_vulns = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS c FROM scans WHERE user_id=%s AND severity IN ('critical','high')", (uid,))
        high_risk = cursor.fetchone()["c"]

        cursor.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE user_id=%s AND started_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
            (uid,),
        )
        week_scans = cursor.fetchone()["c"]

        cursor.close()
        db.close()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    return jsonify(
        {
            "success": True,
            "total_scans": total_scans,
            "total_vulnerabilities": int(total_vulns),
            "high_risk_scans": high_risk,
            "scans_this_week": week_scans,
        }
    )


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id: int):
    """Delete a scan from the authenticated user's history."""
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "DELETE FROM scans WHERE id=%s AND user_id=%s",
            (scan_id, payload["user_id"]),
        )
        deleted = cursor.rowcount
        cursor.close()
        db.close()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    if deleted and deleted > 0:
        return jsonify({"success": True, "deleted": scan_id}), 200
    return jsonify({"success": False, "error": "Not found"}), 404


@app.route('/api/scans/bulk-delete', methods=['POST'])
def bulk_delete_scans():
    """Delete multiple scans from the authenticated user's history."""
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    scan_ids = data.get("scan_ids")
    if not isinstance(scan_ids, list) or not scan_ids:
        return jsonify({"success": False, "error": "scan_ids must be a non-empty list"}), 400

    ids = []
    for v in scan_ids:
        try:
            iv = int(v)
        except Exception:
            continue
        if iv > 0:
            ids.append(iv)

    if not ids:
        return jsonify({"success": False, "error": "No valid scan ids provided"}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        placeholders = ",".join(["%s"] * len(ids))
        cursor.execute(
            f"DELETE FROM scans WHERE user_id=%s AND id IN ({placeholders})",
            tuple([payload["user_id"]] + ids),
        )
        deleted = cursor.rowcount
        cursor.close()
        db.close()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    return jsonify({"success": True, "deleted": int(deleted or 0)}), 200


@app.route('/api/scans', methods=['DELETE'])
def delete_all_scans():
    """Delete all scans for the authenticated user."""
    from routes.auth import verify_token

    payload = verify_token(request)
    if not payload:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "DELETE FROM scans WHERE user_id=%s",
            (payload["user_id"],),
        )
        deleted = cursor.rowcount
        cursor.close()
        db.close()
    except Exception:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    return jsonify({"success": True, "deleted": int(deleted or 0)}), 200


# API info route
@app.route('/api/info')
def api_info():
    return jsonify({
        "name": "SecureScan API",
        "version": "2.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "xss": "/api/xss/scan",
            "sqli": "/api/sqli/scan",
            "open_redirect": "/api/open-redirect/scan",
            "cors": "/api/cors/scan",
            "headers": "/api/headers/scan",
            "phishing": "/api/phishing/scan",
            "auth_register": "/api/auth/register",
            "auth_login": "/api/auth/login",
            "unified": "/api/scan/unified",
            "extension": "/api/extension/quick-scan",
        }
    })


@app.route('/api/debug/xss-batch-binding')
def debug_xss_batch_binding():
    """Temporary debug endpoint to verify what function is bound to /api/xss/scan/batch."""
    try:
        import routes.xss as xss_routes  # type: ignore
        view = app.view_functions.get('xss.scan_xss_batch')
        view_mod = getattr(view, '__module__', None)
        view_name = getattr(view, '__name__', None)

        batch_rules = []
        for r in app.url_map.iter_rules():
            if str(r.rule) == '/api/xss/scan/batch':
                batch_rules.append({
                    'rule': str(r.rule),
                    'endpoint': r.endpoint,
                    'methods': sorted([m for m in (r.methods or []) if m not in ('HEAD', 'OPTIONS')]),
                })

        return jsonify({
            'routes_xss_file': getattr(xss_routes, '__file__', None),
            'view_function': {
                'present': bool(view),
                'module': view_mod,
                'name': view_name,
            },
            'rules_for_api_xss_scan_batch': batch_rules,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Health check
@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404

# ── Serve Frontend ──────────────────────────────────────────────
@app.route('/landing.html')
def serve_legacy_landing():
    return redirect('/home', code=302)

@app.route('/')
def serve_index():
    return send_from_directory(FRONTEND_DIR, 'home.html')

# Explicit routes for most common pages
@app.route('/home')
def serve_home():
    return send_from_directory(FRONTEND_DIR, 'home.html')

@app.route('/login')
def serve_login():
    return send_from_directory(FRONTEND_DIR, 'login.html')

@app.route('/register')
def serve_register():
    return send_from_directory(FRONTEND_DIR, 'register.html')

@app.route('/dashboard')
@app.route('/index')
def serve_dashboard():
    return send_from_directory(FRONTEND_DIR, 'dashboard.html')

@app.route('/forgot_password')
def serve_forgot_password():
    return send_from_directory(FRONTEND_DIR, 'forgot_password.html')

@app.route('/otp_verification')
def serve_otp_verification():
    return send_from_directory(FRONTEND_DIR, 'otp_verification.html')

@app.route('/reset_password')
def serve_reset_password():
    return send_from_directory(FRONTEND_DIR, 'reset_password.html')

@app.route('/scan')
def serve_scan():
    return send_from_directory(FRONTEND_DIR, 'scan.html')

@app.route('/sql_injection')
def serve_sqli():
    return send_from_directory(FRONTEND_DIR, 'sql_injection.html')

@app.route('/open_redirect')
def serve_open_redirect():
    return send_from_directory(FRONTEND_DIR, 'open_redirect.html')

@app.route('/cors_scan')
def serve_cors_scan():
    return send_from_directory(FRONTEND_DIR, 'cors_scan.html')

@app.route('/header_scan')
def serve_header_scan():
    return send_from_directory(FRONTEND_DIR, 'header_scan.html')

@app.route('/phishing')
def serve_phishing():
    return send_from_directory(FRONTEND_DIR, 'phishing.html')

@app.route('/advanced_scan')
def serve_advanced_scan():
    return send_from_directory(FRONTEND_DIR, 'advanced_scan.html')

@app.route('/reports')
def serve_reports():
    return send_from_directory(FRONTEND_DIR, 'reports.html')

@app.route('/scan_all')
def serve_scan_all():
    return send_from_directory(FRONTEND_DIR, 'scan_all.html')

@app.route('/feedback')
def serve_feedback():
    return send_from_directory(FRONTEND_DIR, 'feedback.html')

@app.route('/help')
def serve_help():
    return send_from_directory(FRONTEND_DIR, 'help.html')

@app.route('/admin_login')
def serve_admin_login():
    return send_from_directory(FRONTEND_DIR, 'admin_login.html')

@app.route('/admin_dashboard')
def serve_admin_dashboard():
    return send_from_directory(FRONTEND_DIR, 'admin_dashboard.html')

@app.route('/<page>.html')
def redirect_html_ext(page):
    """Redirect .html URLs to clean URLs without extension."""
    return redirect(f'/{page}', 301)

@app.route('/<page>')
def serve_clean_page(page):
    """Serve HTML pages without the .html extension in URL (fallback for other pages)."""
    if page == 'api' or page.startswith('api/'):
        return jsonify({
            "success": False,
            "error": "Endpoint not found"
        }), 404
    
    html_file = f"{page}.html"
    full_path = os.path.join(FRONTEND_DIR, html_file)
    if os.path.isfile(full_path):
        return send_from_directory(FRONTEND_DIR, html_file)
    return send_from_directory(FRONTEND_DIR, 'home.html')

@app.route('/<path:path>')
def serve_frontend(path):
    """Serve frontend files with extensions (e.g., /static/css/main.css)."""
    if path == 'api' or path.startswith('api/'):
        return jsonify({
            "success": False,
            "error": "Endpoint not found"
        }), 404

    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, 'home.html')

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

if __name__ == '__main__':
    logger.info("Starting SecureScan API Server v2.0...")
    app.run(
        host='127.0.0.1',
        port=5555,
        debug=False,
        use_reloader=False
    )