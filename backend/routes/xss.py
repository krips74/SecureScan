from flask import Blueprint, request, jsonify
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import time

# Import custom scanner
from scanners.xss_scanner import XSSScanner
from scanners.dom_xss_scanner import DomXssScanner
from scanners.stored_xss_scanner import StoredXssScanner
from utils.payload_loader import load_payloads_from_file
from utils.scan_storage import save_scan_to_db, create_running_scan, finalize_scan, is_cancel_requested, create_running_scan, finalize_scan, is_cancel_requested

# Initialize scanner with payloads from file
payloads = load_payloads_from_file()
scanner = XSSScanner(payload_file=os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'scanners', 'xss-payload.txt'
))
print(f"[OK] Custom XSS Scanner initialized with {len(scanner.payloads)} payloads (routes.xss=v3 file={__file__})")

dom_scanner = DomXssScanner(headless=True)
stored_scanner = StoredXssScanner()

import logging

xss_bp = Blueprint('xss', __name__)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _scan_one_url(
    url: str,
    parameters=None,
    custom_payloads=None,
    timeout=None,
    max_duration=15,
    max_payloads=50,
    stop_on_first=True,
    include_dom=True,
    dom_timeout=12,
    include_stored=True,
    stored_timeout=8,
    stored_max_params=3,
    stored_mode: str = "heuristic_get",
    stored_allow_state_change: bool = False,
    stored_cookies=None,
    scan_id: Optional[int] = None,
):
    """Run a single URL scan using reflected + optional DOM + optional stored checks."""
    started = time.monotonic()

    if custom_payloads and isinstance(custom_payloads, list) and len(custom_payloads) > 0:
        result = scanner.scan_url_with_custom_payloads(
            url,
            parameters=parameters,
            custom_payloads=custom_payloads,
            timeout=timeout,
            max_duration=max_duration,
            max_payloads=max_payloads,
            stop_on_first=stop_on_first,
            scan_id=scan_id,
        )
    else:
        result = scanner.scan_url(
            url,
            parameters=parameters,
            timeout=timeout,
            max_duration=max_duration,
            max_payloads=max_payloads,
            stop_on_first=stop_on_first,
            scan_id=scan_id,
        )

    if not result.get('success'):
        return result

    # Check cancellation before additional phases
    if scan_id is not None and is_cancel_requested(scan_id):
        raise RuntimeError("Scan stopped by user")

    # DOM
    if include_dom:
        dom_result = dom_scanner.scan_url(
            url,
            timeout=dom_timeout,
            max_cases=12,
            stop_on_first=True,
            scan_id=scan_id,
        )
        if dom_result.get('success'):
            base_vulns = result.get('vulnerabilities')
            if not isinstance(base_vulns, list):
                base_vulns = []
            base_vulns.extend(dom_result.get('vulnerabilities') or [])
            result['vulnerabilities'] = base_vulns
            result['total_found'] = len(base_vulns)
        else:
            result.setdefault('notes', [])
            result['notes'].append(dom_result.get('error') or 'DOM XSS check failed')
            result['dom_check_error'] = dom_result.get('error')

    # Stored heuristic
    if include_stored:
        stored_result = stored_scanner.scan_url(
            url,
            timeout=stored_timeout,
            max_params=stored_max_params,
            stop_on_first=True,
            mode=stored_mode,
            allow_state_change=stored_allow_state_change,
            cookies=stored_cookies,
            scan_id=scan_id,
        )
        if stored_result.get('success'):
            base_vulns = result.get('vulnerabilities')
            if not isinstance(base_vulns, list):
                base_vulns = []
            base_vulns.extend(stored_result.get('vulnerabilities') or [])
            result['vulnerabilities'] = base_vulns
            result['total_found'] = len(base_vulns)
            if isinstance(stored_result.get('notes'), list) and stored_result.get('notes'):
                result.setdefault('notes', [])
                result['notes'].extend([str(x) for x in stored_result.get('notes')])
        else:
            result.setdefault('notes', [])
            result['notes'].append(stored_result.get('error') or 'Stored XSS check failed')
            result['stored_check_error'] = stored_result.get('error')

    # Check cancellation before finalizing
    if scan_id is not None and is_cancel_requested(scan_id):
        raise RuntimeError("Scan stopped by user")

    result.setdefault('truncated', False)
    result.setdefault('duration_seconds', round(time.monotonic() - started, 3))
    result.setdefault('payloads_tested', None)
    # Helps confirm which code path served this response.
    result.setdefault('engine', 'xss_v2_reflected+dom+stored')
    return result


@xss_bp.route('/scan', methods=['POST'])
def scan_xss():
    """
    Scan a URL for XSS vulnerabilities
    
    Request JSON:
    {
        "url": "https://example.com/search?q=test",
        "parameters": ["q", "search"],  // optional
        "custom_payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],  // optional
    }
    
    Response:
    {
        "success": true,
        "data": {
            "target": "...",
            "vulnerabilities": [...],
            "total_found": 3
        }
    }
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

        url = data.get('url')
        parameters = data.get('parameters', None)
        custom_payloads = data.get('custom_payloads', None)
        timeout = data.get('timeout', config.DEFAULT_TIMEOUT)
        max_duration = data.get('max_duration', 15)
        max_payloads = data.get('max_payloads', 50)
        stop_on_first = data.get('stop_on_first', True)
        include_dom = bool(data.get('include_dom', True))
        dom_timeout = data.get('dom_timeout', 12)
        include_stored = bool(data.get('include_stored', True))
        stored_timeout = data.get('stored_timeout', 8)
        stored_max_params = data.get('stored_max_params', 3)
        stored_mode = data.get('stored_mode', 'heuristic_get')
        stored_allow_state_change = bool(data.get('stored_allow_state_change', False))
        stored_cookies = data.get('stored_cookies', None)

        # Validate URL
        if not url:
            return jsonify({"success": False, "error": "URL is required"}), 400
        if not url.startswith(('http://', 'https://')):
            return jsonify({"success": False, "error": "Invalid URL format. Must start with http:// or https://"}), 400

        logger.info(f"Starting XSS scan for: {url}")

        # Create running scan record if authenticated
        scan_id = None
        if user_id:
            scan_id = create_running_scan(user_id, url, ["xss"])

        # Perform scan with cancellation support
        result = _scan_one_url(
            url=url,
            parameters=parameters,
            custom_payloads=custom_payloads,
            timeout=timeout,
            max_duration=max_duration,
            max_payloads=max_payloads,
            stop_on_first=stop_on_first,
            include_dom=include_dom,
            dom_timeout=dom_timeout,
            include_stored=include_stored,
            stored_timeout=stored_timeout,
            stored_max_params=stored_max_params,
            stored_mode=stored_mode,
            stored_allow_state_change=stored_allow_state_change,
            stored_cookies=stored_cookies,
            scan_id=scan_id,
        )

        if result.get('success'):
            logger.info(f"Scan completed. Found {result.get('total_found', 0)} vulnerabilities")
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["xss"], result, status="completed")
                result["scan_id"] = scan_id
            return jsonify({"success": True, "data": result}), 200
        else:
            logger.error(f"Scan failed: {result.get('error')}")
            msg = result.get('error', 'Unknown error')
            status_code = 500
            if isinstance(msg, str) and msg.startswith('Upstream returned HTTP'):
                status_code = 502
            if scan_id is not None:
                finalize_scan(scan_id, user_id, url, ["xss"], result, status="failed")
            return jsonify({"success": False, "error": msg}), status_code

    except Exception as e:
        logger.error(f"Exception during XSS scan: {str(e)}")
        if 'scan_id' in locals() and scan_id is not None and 'user_id' in locals() and user_id is not None:
            try:
                finalize_scan(scan_id, user_id, url if 'url' in locals() else '', ["xss"], {"success": False, "error": str(e)}, status="failed")
            except Exception:
                pass
        if "stopped by user" in (str(e) or "").lower():
            return jsonify({"success": False, "error": "Scan cancelled by user"}), 409
        return jsonify({"success": False, "error": f"Internal server error: {str(e)}"}), 500


@xss_bp.route('/scan/batch', methods=['POST'])
def scan_xss_batch():
    """
    Scan multiple URLs for XSS vulnerabilities
    
    Request JSON:
    {
        "urls": [
            "https://example.com/search?q=test",
            "https://example.com/login?redirect=home"
        ]
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "No JSON data provided"
            }), 400
        
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({
                "success": False,
                "error": "URLs array is required"
            }), 400
        
        if len(urls) > 50:
            return jsonify({
                "success": False,
                "error": "Maximum 50 URLs allowed per batch"
            }), 400
        
        parameters = data.get('parameters', None)
        custom_payloads = data.get('custom_payloads', None)
        timeout = data.get('timeout', config.DEFAULT_TIMEOUT)
        max_duration = data.get('max_duration', 15)
        max_payloads = data.get('max_payloads', 50)
        stop_on_first = data.get('stop_on_first', True)
        include_dom = bool(data.get('include_dom', True))
        dom_timeout = data.get('dom_timeout', 12)
        include_stored = bool(data.get('include_stored', True))
        stored_timeout = data.get('stored_timeout', 8)
        stored_max_params = data.get('stored_max_params', 3)
        stored_mode = data.get('stored_mode', 'heuristic_get')
        stored_allow_state_change = bool(data.get('stored_allow_state_change', False))
        stored_cookies = data.get('stored_cookies', None)

        logger.info(f"Starting batch XSS scan for {len(urls)} URLs")

        scans = []
        total_vulns = 0
        for u in urls:
            if not isinstance(u, str) or not u.startswith(('http://', 'https://')):
                scans.append({
                    "success": False,
                    "target": u,
                    "error": "Invalid URL format. Must start with http:// or https://",
                })
                continue

            one = _scan_one_url(
                url=u,
                parameters=parameters,
                custom_payloads=custom_payloads,
                timeout=timeout,
                max_duration=max_duration,
                max_payloads=max_payloads,
                stop_on_first=stop_on_first,
                include_dom=include_dom,
                dom_timeout=dom_timeout,
                include_stored=include_stored,
                stored_timeout=stored_timeout,
                stored_max_params=stored_max_params,
                stored_mode=stored_mode,
                stored_allow_state_change=stored_allow_state_change,
                stored_cookies=stored_cookies,
            )
            scans.append(one)
            if one.get('success'):
                try:
                    total_vulns += int(one.get('total_found', 0) or 0)
                except Exception:
                    pass

        result = {
            "total_scanned": len(urls),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "scans": scans,
            "total_vulnerabilities": total_vulns,
            "success_rate": (sum(1 for s in scans if s.get('success')) / len(urls) * 100.0) if urls else 0,
            "engine": "xss_batch_v2_reflected+dom+stored",
        }

        logger.info(f"Batch scan completed. Total vulnerabilities: {total_vulns}")

        return jsonify({"success": True, "data": result}), 200
        
    except Exception as e:
        logger.error(f"Exception during batch XSS scan: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


@xss_bp.route('/scan/file', methods=['POST'])
def scan_xss_file():
    """
    Scan URLs from a uploaded text file for XSS vulnerabilities
    
    Request: multipart/form-data with file field 'file' containing URLs (one per line)
    
    Response:
    {
        "success": true,
        "data": {...}
    }
    """
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({
                "success": False,
                "error": "No file uploaded. Please upload a .txt file with URLs (one per line)"
            }), 400
        
        file = request.files['file']
        
        # Check if a file was selected
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected"
            }), 400
        
        # Check file extension
        if not file.filename.lower().endswith('.txt'):
            return jsonify({
                "success": False,
                "error": "Only .txt files are allowed"
            }), 400
        
        # Read URLs from file
        content = file.read().decode('utf-8')
        urls = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not urls:
            return jsonify({
                "success": False,
                "error": "No URLs found in the file"
            }), 400
        
        if len(urls) > 50:
            return jsonify({
                "success": False,
                "error": "Maximum 50 URLs allowed per batch"
            }), 400
        
        logger.info(f"Starting batch XSS scan for {len(urls)} URLs from file: {file.filename}")
        
        # Perform batch scan
        result = scanner.scan_multiple_urls(urls)
        
        logger.info(f"Batch scan completed. Total vulnerabilities: {result.get('total_vulnerabilities', 0)}")
        
        return jsonify({
            "success": True,
            "data": result,
            "file_processed": file.filename,
            "urls_count": len(urls)
        }), 200
        
    except Exception as e:
        logger.error(f"Exception during file-based XSS scan: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}"
        }), 500


@xss_bp.route('/health', methods=['GET'])
def health_check():
    """
    Check if XSS scanner is available
    """
    return jsonify({
        "success": True,
        "status": "healthy",
        "scanner": "Custom XSS Scanner (Python)",
            "route_version": "2026-04-13-xss-route-v1",
            "route_file": __file__,
        "available": True,
        "payloads_loaded": len(scanner.payloads),
        "message": "Using custom Python-based XSS scanner"
    }), 200
