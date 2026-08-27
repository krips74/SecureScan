import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Server
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 5001))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# CORS
CORS_ORIGINS = "*"

# MySQL
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DB = os.getenv("MYSQL_DB", "securescan")

# JWT
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_in_prod")

# Scanning
DEFAULT_TIMEOUT = 10
MAX_BATCH_SIZE = 50
SCAN_SAFE_MODE = True

# Paths
LOG_TO_FILE = os.getenv("SECURESCAN_LOG_TO_FILE", "0").strip().lower() in ("1", "true", "yes")
LOGS_DIR = os.getenv("SECURESCAN_LOGS_DIR", os.path.join(BASE_DIR, "logs"))
SCANNERS_DIR = os.path.join(BASE_DIR, "scanners")
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")

PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.json"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHING_CACHE_FILE = os.path.join(DATA_DIR, "phishing_cache.json")
PHISHING_FEED_REFRESH_HOURS = 6

dirs_to_create = [
	DATA_DIR,
	os.path.join(REPORTS_DIR, "json"),
	os.path.join(REPORTS_DIR, "html"),
	os.path.join(REPORTS_DIR, "pdf"),
]

if LOG_TO_FILE:
	dirs_to_create.append(LOGS_DIR)

for d in dirs_to_create:
	os.makedirs(d, exist_ok=True)
