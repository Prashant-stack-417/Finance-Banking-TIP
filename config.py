import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = "threat_intelligence"
MONGO_COLLECTION_INDICATORS = "indicators"
MONGO_COLLECTION_LOGS = "enforcement_logs"

# API Keys (set in .env file)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# Elasticsearch / ELK
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX_INDICATORS = "threat-indicators"
ES_INDEX_LOGS = "enforcement-logs"

# Risk scoring thresholds
RISK_SCORE_HIGH = 70       # auto-block threshold
RISK_SCORE_MEDIUM = 40
RISK_SCORE_LOW = 10

# Policy enforcer
ENFORCER_POLL_INTERVAL = 60        # seconds between enforcement cycles
IPTABLES_CHAIN = "TIP_BLOCK"       # custom chain name (keeps rules isolated)
WHITELIST_IPS = [
    "127.0.0.1",
    "::1",
]

# Alerting (email)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
ALERT_RECIPIENTS = os.getenv("ALERT_RECIPIENTS", "").split(",")

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "logs/tip.log"
