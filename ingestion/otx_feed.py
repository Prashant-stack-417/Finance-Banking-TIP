"""
AlienVault OTX OSINT Feed Ingester
Pulls malicious IPs and domains from OTX pulses.
"""
import requests
from requests.adapters import HTTPAdapter
from loguru import logger
from datetime import datetime, timedelta
from urllib3.util.retry import Retry
import config
from database import upsert_indicator
from ingestion.normalizer import normalize_indicator


OTX_BASE = "https://otx.alienvault.com/api/v1"
HEADERS = {"X-OTX-API-KEY": config.OTX_API_KEY}
OTX_TIMEOUT = getattr(config, "OTX_TIMEOUT", 30)


def _build_session() -> requests.Session:
    """Create a session with retry/backoff for transient OTX failures."""
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


def fetch_subscribed_pulses(days_back: int = 7) -> list:
    """Fetch pulses updated in the last N days."""
    since = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S")
    pulses = []
    url = f"{OTX_BASE}/pulses/subscribed?modified_since={since}&limit=50"
    session = _build_session()
    while url:
        try:
            resp = session.get(url, headers=HEADERS, timeout=OTX_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            pulses.extend(data.get("results", []))
            url = data.get("next")
        except requests.exceptions.Timeout:
            logger.error(f"OTX fetch timeout after {OTX_TIMEOUT}s: {url}")
            break
        except Exception as e:
            logger.error(f"OTX fetch error: {e}")
            break
    logger.info(f"OTX: fetched {len(pulses)} pulses")
    return pulses


def extract_indicators_from_pulses(pulses: list) -> list:
    """Extract IOCs from pulse list."""
    indicators = []
    for pulse in pulses:
        pulse_name = pulse.get("name", "unknown")
        tags = pulse.get("tags", [])
        for ioc in pulse.get("indicators", []):
            ioc_type = ioc.get("type", "").lower()
            value = ioc.get("indicator", "").strip()
            if not value:
                continue
            # Map OTX types to our normalized types
            if ioc_type in ("ipv4", "ipv6"):
                norm_type = "ip"
            elif ioc_type in ("domain", "hostname"):
                norm_type = "domain"
            elif ioc_type == "url":
                norm_type = "url"
            elif ioc_type in ("filehash-md5", "filehash-sha1", "filehash-sha256"):
                norm_type = "hash"
            else:
                continue
            indicators.append({
                "value": value,
                "type": norm_type,
                "source": "AlienVault OTX",
                "pulse": pulse_name,
                "tags": tags,
                "raw_type": ioc_type,
            })
    return indicators


def run():
    logger.info("Starting AlienVault OTX ingestion...")
    if not config.OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping OTX ingestion")
        return 0

    pulses = fetch_subscribed_pulses(days_back=7)
    raw_indicators = extract_indicators_from_pulses(pulses)

    new_count = 0
    for raw in raw_indicators:
        normalized = normalize_indicator(raw)
        if normalized:
            is_new = upsert_indicator(normalized)
            if is_new:
                new_count += 1

    logger.info(f"OTX ingestion complete: {len(raw_indicators)} processed, {new_count} new")
    return new_count


if __name__ == "__main__":
    run()
