"""
URLhaus OSINT Feed Ingester (abuse.ch)
Pulls malicious URLs and extracts IPs/domains — no API key required.
"""
import requests
import csv
import io
from loguru import logger
from database import upsert_indicator
from ingestion.normalizer import normalize_indicator


URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch_urlhaus_feed() -> list:
    """Download and parse the URLhaus recent CSV feed."""
    try:
        resp = requests.get(URLHAUS_CSV, timeout=30)
        resp.raise_for_status()
        content = resp.text

        # URLhaus CSV has comment lines starting with #
        lines = [l for l in content.splitlines() if not l.startswith("#")]
        reader = csv.DictReader(lines)
        rows = list(reader)
        logger.info(f"URLhaus: downloaded {len(rows)} raw entries")
        return rows
    except Exception as e:
        logger.error(f"URLhaus fetch error: {e}")
        return []


def parse_urlhaus_rows(rows: list) -> list:
    """Convert URLhaus rows into normalized indicator dicts."""
    indicators = []
    for row in rows:
        url = row.get("url", "").strip()
        host = row.get("host", "").strip()
        url_status = row.get("url_status", "").lower()
        threat = row.get("threat", "").strip()
        tags_raw = row.get("tags", "")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        if not host:
            continue

        # Assign base risk score: online = higher risk
        base_score = 85 if url_status == "online" else 55

        # Add URL indicator
        if url:
            indicators.append({
                "value": url,
                "type": "url",
                "source": "URLhaus",
                "threat": threat,
                "tags": tags + ["urlhaus"],
                "risk_score": base_score,
            })

        # Add host indicator (could be IP or domain)
        import re
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        host_type = "ip" if ip_pattern.match(host) else "domain"
        indicators.append({
            "value": host,
            "type": host_type,
            "source": "URLhaus",
            "threat": threat,
            "tags": tags + ["urlhaus"],
            "risk_score": base_score,
        })

    return indicators


def run():
    logger.info("Starting URLhaus ingestion...")
    rows = fetch_urlhaus_feed()
    if not rows:
        return 0

    raw_indicators = parse_urlhaus_rows(rows)
    new_count = 0
    for raw in raw_indicators:
        normalized = normalize_indicator(raw)
        if normalized:
            is_new = upsert_indicator(normalized)
            if is_new:
                new_count += 1

    logger.info(f"URLhaus ingestion complete: {len(raw_indicators)} processed, {new_count} new")
    return new_count


if __name__ == "__main__":
    run()
