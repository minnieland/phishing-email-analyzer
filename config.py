"""API key placeholders and scoring thresholds."""

import os

from dotenv import load_dotenv

load_dotenv()

# Threat intelligence API keys (set via environment or .env)
VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_API_KEY_HERE")

# VirusTotal API v3
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT_SECONDS = 30

# AbuseIPDB API
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_TIMEOUT_SECONDS = 30
ABUSEIPDB_MAX_AGE_DAYS = 90

# Risk scoring weights (0–100 total possible from these conditions)
SCORE_AUTH_FAILURE = 30
SCORE_ABUSEIPDB_HIGH = 25
SCORE_VT_DETECTIONS = 35
SCORE_SENDER_MISMATCH = 15

# Thresholds that trigger score increments
ABUSEIPDB_CONFIDENCE_THRESHOLD = 50
VT_DETECTION_THRESHOLD = 3

# Classification bands
CLASSIFICATION_LOW_MAX = 29
CLASSIFICATION_SUSPICIOUS_MAX = 60

# Output
DEFAULT_JSON_OUTPUT = "analysis_output.json"
