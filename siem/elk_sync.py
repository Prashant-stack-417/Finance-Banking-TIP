"""
SIEM Integration — Elasticsearch / ELK Stack
Syncs MongoDB threat indicators into Elasticsearch for Kibana visualization.
"""
from elasticsearch import Elasticsearch, helpers
from loguru import logger
from datetime import datetime
import config
from database import get_indicators_collection, get_logs_collection


def get_es_client() -> Elasticsearch:
    return Elasticsearch(
        config.ES_HOST,
        headers={
            "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
            "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8",
        },
    )


def ensure_index(es: Elasticsearch, index: str, mapping: dict):
    """Create index with mapping if it doesn't exist.

    Returns True when the index exists or was created successfully, otherwise False.
    """
    exists = False
    try:
        exists = es.indices.exists(index=index)
    except Exception as e:
        logger.warning(f"Could not check Elasticsearch index '{index}': {e}")

    if exists:
        return True

    try:
        es.indices.create(index=index, mappings=mapping)
        logger.info(f"Created Elasticsearch index: {index}")
    except Exception as e:
        if "resource_already_exists_exception" in str(e):
            return True
        logger.warning(f"Could not create Elasticsearch index '{index}': {e}")
        return False
    return True


INDICATORS_MAPPING = {
    "properties": {
        "value":       {"type": "keyword"},
        "type":        {"type": "keyword"},
        "source":      {"type": "keyword"},
        "risk_score":  {"type": "integer"},
        "tags":        {"type": "keyword"},
        "threat":      {"type": "text"},
        "blocked":     {"type": "boolean"},
        "first_seen":  {"type": "date"},
        "last_seen":   {"type": "date"},
        "seen_count":  {"type": "integer"},
    }
}

LOGS_MAPPING = {
    "properties": {
        "action":      {"type": "keyword"},
        "value":       {"type": "keyword"},
        "type":        {"type": "keyword"},
        "rule_id":     {"type": "keyword"},
        "analyst":     {"type": "keyword"},
        "timestamp":   {"type": "date"},
        "reason":      {"type": "text"},
    }
}


def sync_indicators_to_es():
    """Bulk sync all indicators from MongoDB to Elasticsearch."""
    es = get_es_client()
    if not ensure_index(es, config.ES_INDEX_INDICATORS, INDICATORS_MAPPING):
        logger.warning(f"Skipping indicator sync because Elasticsearch index '{config.ES_INDEX_INDICATORS}' is unavailable")
        return 0

    col = get_indicators_collection()
    indicators = list(col.find({}, {"_id": 0}))

    if not indicators:
        logger.info("No indicators to sync to Elasticsearch")
        return 0

    def generate_actions():
        for ind in indicators:
            # Convert datetime objects to ISO strings
            for field in ("first_seen", "last_seen", "blocked_at", "unblocked_at"):
                if isinstance(ind.get(field), datetime):
                    ind[field] = ind[field].isoformat()
            yield {
                "_index": config.ES_INDEX_INDICATORS,
                "_id": f"{ind['type']}:{ind['value']}",
                "_source": ind,
            }

    try:
        success, errors = helpers.bulk(es, generate_actions(), raise_on_error=False)
        logger.info(f"ES sync: {success} indicators indexed, {len(errors)} errors")
        if errors:
            logger.debug(f"Bulk errors sample: {errors[:5]}")
        return success
    except Exception as e:
        logger.error(f"Elasticsearch bulk indexing failed: {e}")
        return 0


def sync_logs_to_es():
    """Sync enforcement logs from MongoDB to Elasticsearch."""
    es = get_es_client()
    if not ensure_index(es, config.ES_INDEX_LOGS, LOGS_MAPPING):
        logger.warning(f"Skipping log sync because Elasticsearch index '{config.ES_INDEX_LOGS}' is unavailable")
        return 0

    col = get_logs_collection()
    logs = list(col.find({}, {"_id": 0}))

    if not logs:
        return 0

    def generate_actions():
        for log in logs:
            if isinstance(log.get("timestamp"), datetime):
                log["timestamp"] = log["timestamp"].isoformat()
            yield {
                "_index": config.ES_INDEX_LOGS,
                "_source": log,
            }

    try:
        success, errors = helpers.bulk(es, generate_actions(), raise_on_error=False)
        logger.info(f"ES log sync: {success} logs indexed")
        return success
    except Exception as e:
        logger.error(f"Elasticsearch bulk logs indexing failed: {e}")
        return 0


def run():
    logger.info("Starting SIEM sync to Elasticsearch...")
    try:
        i = sync_indicators_to_es()
        l = sync_logs_to_es()
        logger.info(f"SIEM sync complete: {i} indicators, {l} logs")
    except Exception as e:
        logger.error(f"SIEM sync failed: {e}")


if __name__ == "__main__":
    run()
