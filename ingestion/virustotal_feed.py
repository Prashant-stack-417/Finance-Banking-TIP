"""
VirusTotal OSINT Feed Ingester
Queries VirusTotal for known malicious IPs and domains.
"""
import requests
import time
from requests.adapters import HTTPAdapter
from loguru import logger
from urllib3.util.retry import Retry
import config
from database import upsert_indicator
from ingestion.normalizer import normalize_indicator


VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": config.VIRUSTOTAL_API_KEY}
VT_TIMEOUT = getattr(config, "VIRUSTOTAL_TIMEOUT", 30)

# Free API: 4 requests/minute
REQUEST_DELAY = 16  # seconds between requests on free tier


def _build_session() -> requests.Session:
    """Create a session with retry/backoff for transient VirusTotal failures."""
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = _build_session()


def query_ip(ip: str) -> dict | None:
    """Get VirusTotal analysis for an IP."""
    try:
        resp = SESSION.get(f"{VT_BASE}/ip_addresses/{ip}", headers=HEADERS, timeout=VT_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
        elif resp.status_code == 404:
            return None
        else:
            logger.warning(f"VT IP query {ip} returned {resp.status_code}")
            return None
    except Exception as e:
        logger.error(f"VT IP query error for {ip}: {e}")
        return None


def query_domain(domain: str) -> dict | None:
    """Get VirusTotal analysis for a domain."""
    try:
        resp = SESSION.get(f"{VT_BASE}/domains/{domain}", headers=HEADERS, timeout=VT_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {})
        return None
    except Exception as e:
        logger.error(f"VT domain query error for {domain}: {e}")
        return None


def calculate_vt_risk_score(attributes: dict) -> int:
    """
    Derive a 0-100 risk score from VirusTotal detection stats.
    Uses last_analysis_stats: malicious, suspicious counts.
    """
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    ratio = (malicious + suspicious * 0.5) / total
    return min(100, int(ratio * 100))


def enrich_existing_indicators(indicators: list) -> int:
    """
    Take a list of indicators from DB and enrich with VT data.
    Returns count enriched.
    """
    if not config.VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY not set — skipping VT enrichment")
        return 0

    enriched = 0
    for ind in indicators:
        itype = ind.get("type")
        value = ind.get("value")

        if itype == "ip":
            attrs = query_ip(value)
        elif itype == "domain":
            attrs = query_domain(value)
        else:
            continue

        if attrs:
            vt_score = calculate_vt_risk_score(attrs)
            # Merge VT score: take the higher of existing vs VT score
            merged_score = max(ind.get("risk_score", 0), vt_score)
            normalized = normalize_indicator({
                "value": value,
                "type": itype,
                "source": "VirusTotal",
                "tags": ["vt-enriched"],
                "vt_score": vt_score,
                "risk_score": merged_score,
            })
            if normalized:
                upsert_indicator(normalized)
                enriched += 1

        time.sleep(REQUEST_DELAY)

    return enriched


def run():
    """
    For direct use: query a small seed list.
    In production, this enriches indicators already in MongoDB.
    """
    logger.info("Starting VirusTotal enrichment run...")
    from database import get_indicators_collection
    col = get_indicators_collection()
    # Enrich indicators not yet VT-enriched
    candidates = list(
        col.find(
            {"type": {"$in": ["ip", "domain"]}, "source": {"$ne": "VirusTotal"}},
            {"_id": 0}
        ).limit(20)  # respect rate limits
    )
    count = enrich_existing_indicators(candidates)
    logger.info(f"VirusTotal enrichment complete: {count} indicators enriched")
    return count


if __name__ == "__main__":
    run()
