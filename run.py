#!/usr/bin/env python3
"""
SecureScan - Quick Start Script
Runs the Flask backend server with frontend serving
"""

import sys
import os
import socket
from contextlib import closing

# Set the working directory to backend for proper imports
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
sys.path.insert(0, os.getcwd())

import config
from app import app


def _try_bind(host: str, port: int) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        return True
    except OSError:
        return False


def _pick_port(host: str, preferred_port: int) -> int:
    # Try preferred first, then a small fallback range.
    candidates = []
    for p in (preferred_port, 5001, 5050, 8000, 8080):
        if p not in candidates:
            candidates.append(p)
    candidates.extend([p for p in range(max(1024, preferred_port), max(1024, preferred_port) + 50) if p not in candidates])

    for p in candidates:
        if _try_bind(host, p):
            return p
    # Last resort: let OS pick an ephemeral port
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])

if __name__ == '__main__':
    host = (os.getenv("HOST") or os.getenv("API_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    env_port = os.getenv("PORT") or os.getenv("API_PORT")
    preferred_port = int(env_port) if env_port and env_port.strip().isdigit() else int(getattr(config, "API_PORT", 5001))
    port = _pick_port(host, preferred_port)
    # Flask's reloader can break when this script `chdir`s into backend, so keep it off.
    debug = (os.getenv("DEBUG") or "").strip().lower() in ("1", "true", "yes")

    print(f"""
    ==========================================
    SecureScan v2.0  -  Multi-Scanner
    ==========================================

    Starting Flask API Server...

    Dashboard:  http://{host}:{port}/
    API Info:   http://{host}:{port}/api/info
    Health:     http://{host}:{port}/health

    Scanners: XSS, SQLi, Open Redirect
              Headers, Phishing

    For authorized security testing only!
    Press CTRL+C to stop
    """)

    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True,
        use_reloader=False,
    )