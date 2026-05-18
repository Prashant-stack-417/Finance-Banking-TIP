"""
Indicator Normalizer & Risk Scorer
Cleans, validates, and scores all ingested threat indicators.
"""
import re
import ipaddress
from datetime import datetime
from loguru import logger
import config


# Private/reserved IP ranges that should never be blocked
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_REGEX.match(value)) and len(value) <= 253


def is_whitelisted(value: str) -> bool:
    return value in config.WHITELIST_IPS


def calculate_risk_score(indicator: dict) -> int:
    """
    Multi-factor risk scoring (0-100).
    Factors: source credibility, threat type, existing score, tags.
    """
    score = indicator.get("risk_score", 0)

    # Source credibility boost
    source_weights = {
        "URLhaus": 20,
        "AlienVault OTX": 15,
        "VirusTotal": 10,
    }
    score += source_weights.get(indicator.get("source", ""), 5)

    # Tag-based boosts
    high_risk_tags = {"malware", "botnet", "ransomware", "phishing", "exploit", "apt", "trojan"}
    tags = {t.lower() for t in indicator.get("tags", [])}
    if tags & high_risk_tags:
        score += 20

    # Type-based adjustment
    if indicator.get("type") == "ip":
        score += 5  # IPs are more immediately actionable

    # VT score override if present
    if "vt_score" in indicator:
        score = max(score, indicator["vt_score"])

    return min(100, score)


def normalize_indicator(raw: dict) -> dict | None:
    """
    Validate and normalize a raw indicator dict.
    Returns None if the indicator should be discarded.
    """
    value = raw.get("value", "").strip().lower()
    itype = raw.get("type", "").strip().lower()

    if not value or not itype:
        return None

    # Validate by type
    if itype == "ip":
        if not is_valid_ip(value):
            return None
        if is_private_ip(value):
            logger.debug(f"Skipping private IP: {value}")
            return None
        if is_whitelisted(value):
            logger.debug(f"Skipping whitelisted IP: {value}")
            return None

    elif itype == "domain":
        if not is_valid_domain(value):
            return None
        # Strip www prefix for deduplication
        if value.startswith("www."):
            value = value[4:]

    elif itype == "url":
        if not value.startswith(("http://", "https://")):
            return None

    elif itype == "hash":
        if not re.match(r"^[a-f0-9]{32,64}$", value):
            return None
    else:
        return None

    risk_score = calculate_risk_score({**raw, "value": value})

    return {
        "value": value,
        "type": itype,
        "source": raw.get("source", "unknown"),
        "tags": list(set(raw.get("tags", []))),
        "risk_score": risk_score,
        "threat": raw.get("threat", ""),
        "pulse": raw.get("pulse", ""),
        "seen_count": 1,
    }
