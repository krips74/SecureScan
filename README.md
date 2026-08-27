# 🛡️ SecureScan — Multi-Vulnerability Scanner

A comprehensive web security scanning platform with **6 scanner modules**, a unified Flask API, a browser-ready frontend, and a Chrome extension for real-time phishing detection.

---

## 🚀 Features

| Scanner | Description | CWE |
|---------|-------------|-----|
| **XSS** | Reflected XSS detection with 51 payloads | CWE-79 |
| **SQL Injection** | Error-based, boolean-blind, time-based, UNION (safe mode toggle) | CWE-89 |
| **Open Redirect** | Redirect parameter fuzzing with 45 payloads | CWE-601 |
| **Header Analysis** | 10 security headers graded A–F, info-leak detection | CWE-693 |
| **Phishing** | PhishTank + OpenPhish feed matching, heuristic scoring | CWE-451 |
| **Advanced (Unified)** | Run multiple scanners in one request | — |

**Plus:**

- 🔌 **Chrome Extension** — Real-time phishing/scam warning on every page visit
- 🔑 **Auth Module** — Form, Bearer, Basic, and custom-header login
- 📊 **Frontend Dashboard** — 12-page UI with scan forms, score gauges, reports
- 📄 **Report Storage** — JSON exports with localStorage history

---

## 📋 Prerequisites

- **Python 3.10+**
- **pip** (or any Python environment manager)
- **Node.js 18+** (required for email OTP via NodeMailer)

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/SecureScan.git
cd SecureScan

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -r backend/requirements.txt
```

---

## ▶️ Running the Server

```bash
# Start the server (serves both API and frontend)
python start_server.py
```

Open **http://127.0.0.1:5000** in your browser.

### Logging

By default, SecureScan logs to the console only (so it won’t keep generating log files inside the repo).

To enable file logging:

- Set `SECURESCAN_LOG_TO_FILE=true`
- (Optional) Set `SECURESCAN_LOGS_DIR` to choose a different log directory

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/info` | GET | API info + endpoint list |
| `/api/xss/scan` | POST | XSS scan |
| `/api/sqli/scan` | POST | SQL injection scan |
| `/api/open-redirect/scan` | POST | Open redirect scan |
| `/api/headers/scan` | POST | Header analysis |
| `/api/phishing/check` | POST | Phishing check |
| `/api/scan/unified` | POST | Multi-scanner unified scan |
| `/api/extension/quick-scan` | POST | Chrome extension quick check |

### Example API Call

```bash
# Header analysis
curl -X POST http://127.0.0.1:5000/api/headers/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Phishing check
curl -X POST http://127.0.0.1:5000/api/phishing/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-login-verify.example.com"}'

# SQL injection (safe mode)
curl -X POST http://127.0.0.1:5000/api/sqli/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://target.com/page?id=1", "safe_mode": true}'
```

---

## 🌐 Frontend Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Scanner cards with status badges |
| XSS Scan | `/scan.html` | XSS vulnerability scanner |
| SQL Injection | `/sql_injection.html` | SQLi with safe mode toggle |
| Open Redirect | `/open_redirect.html` | Redirect parameter fuzzer |
| Phishing | `/phishing.html` | URL phishing detection with score gauge |
| Headers | `/header_scan.html` | Security header grading (A–F) |
| Advanced | `/advanced_scan.html` | Multi-scanner with tabs |
| Reports | `/reports.html` | Saved scan history |
| Help | `/help.html` | Documentation |
| Feedback | `/feedback.html` | Feedback form |
| Forgot Password | `/forgot_password.html` | Request OTP for password reset |
| OTP Verification | `/otp_verification.html` | Verify OTP code |
| Reset Password | `/reset_password.html` | Create a new password |

---

## 🔁 Forgot Password (Email OTP)

SecureScan supports a password reset flow that sends a **6-digit OTP** to the user's email using **NodeMailer (Gmail)**.

### Setup

1. Install Node dependency:

```bash
npm install
```

2. Set these values in `.env`:

- `GMAIL_USER` (your Gmail address)
- `GMAIL_APP_PASSWORD` (a Google App Password)

### API Endpoints

- `POST /api/auth/password-reset/request`  `{ "email": "you@example.com" }`
- `POST /api/auth/password-reset/verify`   `{ "email": "you@example.com", "otp": "123456" }`
- `POST /api/auth/password-reset/confirm` `{ "email": "you@example.com", "reset_token": "...", "new_password": "..." }`

Notes: OTP expires in **10 minutes**; reset token expires in **15 minutes**.

---

## 🔌 Chrome Extension

The **SecureScan Guard** Chrome extension acts as a first-layer defense — it checks every page you visit for phishing indicators using client-side heuristics.

### Install (Developer Mode)

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** toggle (top right corner)
3. Click **Load unpacked**
4. Browse to the project and select the `extension/` folder
5. The 🛡️ **SecureScan Guard** icon will appear in your toolbar
6. *(Optional)* Pin the extension by clicking the puzzle-piece icon → Pin

> **Tip:** To enable Advanced Mode (server-backed deep analysis), click the extension icon → ⚙️ Settings → toggle **Enable Advanced Mode** and make sure the SecureScan server is running at `http://127.0.0.1:5000`.

### How It Works

1. You visit **any website** — the extension runs automatically, no action needed
2. `lib/heuristics.js` performs **10 client-side checks** on the URL (raw IP, suspicious TLD, brand impersonation, homoglyphs, etc.)
3. If the risk score exceeds the threshold (default 40), a **red warning banner** slides down at the top of the page
4. The banner shows the risk score, flag count, and top issues — you can click **Details**, **Dismiss**, or **Leave Site**
5. With **Advanced Mode** enabled, the background service worker also queries the local server (`/api/extension/quick-scan`) for phishing-feed matching and header analysis

### Features

- **Heuristic Analysis** — 10 client-side checks (raw IP, suspicious TLD, brand impersonation, homoglyphs, etc.)
- **Warning Banner** — Slide-down warning on suspicious pages
- **Popup** — Risk status, flags list, re-check button
- **Advanced Mode** — Connect to the local SecureScan server for deep analysis
- **Configurable** — Threshold slider, enable/disable, notification preferences

---

## 📁 Project Structure

```
SecureScan/
├── start_server.py              # Server startup script
├── backend/
│   ├── app.py                   # Flask app — routes, CORS, frontend serving
│   ├── config.py                # Centralized configuration
│   ├── requirements.txt         # Python dependencies
│   ├── scanners/                # Scanner modules
│   │   ├── xss_scanner.py       # XSS scanner (51 payloads)
│   │   ├── sqli_scanner.py      # SQLi scanner (95 payloads, safe mode)
│   │   ├── open_redirect_scanner.py
│   │   ├── header_scanner.py
│   │   └── phishing_scanner.py  # PhishTank + OpenPhish + heuristics
│   ├── routes/                  # API route blueprints
│   │   ├── xss.py
│   │   ├── sqli.py
│   │   ├── open_redirect.py
│   │   ├── header_scan.py
│   │   ├── phishing.py
│   │   └── auth.py
│   └── utils/
│       ├── payload_loader.py
│       └── wayback_fetcher.py
├── frontend/
│   ├── index.html               # Dashboard
│   ├── scan.html                # XSS scan
│   ├── sql_injection.html       # SQLi scan
│   ├── open_redirect.html       # Open redirect
│   ├── phishing.html            # Phishing detection
│   ├── header_scan.html         # Header analysis
│   ├── advanced_scan.html       # Unified multi-scanner
│   ├── reports.html             # Report history
│   ├── help.html / feedback.html
│   ├── components/sidebar.html  # Shared sidebar component
│   └── assets/
│       ├── css/main.css         # Styles (dark theme, purple primary)
│       └── js/
│           ├── common.js        # Shared API functions & UI helpers
│           └── scan.js          # XSS-specific scan logic
└── extension/                   # Chrome Extension (Manifest V3)
    ├── manifest.json
    ├── background.js            # Service worker
    ├── content.js / content.css # Page-level warning injection
    ├── lib/heuristics.js        # Client-side phishing heuristics
    ├── popup/                   # Extension popup
    ├── options/                 # Settings page
    └── icons/                   # Extension icons
```

---

## ⚙️ Configuration

Edit `backend/config.py` to change:

- `API_HOST` / `API_PORT` — Server bind address (default: `0.0.0.0:5000`)
- `SCAN_SAFE_MODE` — SQLi safe mode default (default: `True`)
- `DEFAULT_TIMEOUT` — HTTP request timeout (default: `10s`)
- `MAX_BATCH_SIZE` — Max URLs per batch scan (default: `50`)

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Only scan targets you have explicit permission to test. Unauthorized scanning may violate laws and regulations.

---

## 📄 License

MIT License
