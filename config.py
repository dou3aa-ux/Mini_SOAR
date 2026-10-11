import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DB_PATH = Path(os.getenv("DB_PATH", "data/ids.db"))
if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH

PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "15"))
PORT_SCAN_WINDOW_SECONDS = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "10"))

DNS_QUERY_THRESHOLD = int(os.getenv("DNS_QUERY_THRESHOLD", "20"))
DNS_QUERY_WINDOW_SECONDS = int(os.getenv("DNS_QUERY_WINDOW_SECONDS", "10"))

SSH_ATTEMPT_THRESHOLD = int(os.getenv("SSH_ATTEMPT_THRESHOLD", "5"))
SSH_WINDOW_SECONDS = int(os.getenv("SSH_WINDOW_SECONDS", "60"))

BEACON_MIN_CONNECTIONS = int(os.getenv("BEACON_MIN_CONNECTIONS", "5"))
BEACON_MAX_JITTER_RATIO = float(os.getenv("BEACON_MAX_JITTER_RATIO", "0.20"))

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")