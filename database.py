from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from datetime import datetime
from loguru import logger
import config


_client = None

def get_db():
    global _client
    if _client is None:
        _client = MongoClient(config.MONGO_URI)
    return _client[config.MONGO_DB]


def get_indicators_collection():
    db = get_db()
    col = db[config.MONGO_COLLECTION_INDICATORS]
    # Ensure unique index on (value, type) to prevent duplicates
    col.create_index([("value", ASCENDING), ("type", ASCENDING)], unique=True)
    col.create_index([("risk_score", DESCENDING)])
    col.create_index([("first_seen", DESCENDING)])
    return col


def get_logs_collection():
    db = get_db()
    return db[config.MONGO_COLLECTION_LOGS]


def upsert_indicator(indicator: dict) -> bool:
    """
    Insert or update a threat indicator.
    Returns True if new, False if updated existing.
    """
    col = get_indicators_collection()
    now = datetime.utcnow()
    try:
        col.insert_one({**indicator, "first_seen": now, "last_seen": now, "blocked": False})
        logger.debug(f"New indicator inserted: {indicator['value']}")
        return True
    except DuplicateKeyError:
        col.update_one(
            {"value": indicator["value"], "type": indicator["type"]},
            {
                "$set": {
                    "last_seen": now,
                    "risk_score": indicator.get("risk_score", 0),
                    "tags": indicator.get("tags", []),
                    "source": indicator.get("source"),
                },
                "$inc": {"seen_count": 1},
            },
        )
        return False


def get_high_risk_unblocked(threshold: int = None) -> list:
    """Return high-risk indicators not yet blocked."""
    if threshold is None:
        threshold = config.RISK_SCORE_HIGH
    col = get_indicators_collection()
    return list(
        col.find(
            {"risk_score": {"$gte": threshold}, "blocked": False},
            {"_id": 0},
        ).sort("risk_score", DESCENDING)
    )


def mark_as_blocked(value: str, itype: str, rule_id: str):
    col = get_indicators_collection()
    col.update_one(
        {"value": value, "type": itype},
        {"$set": {"blocked": True, "blocked_at": datetime.utcnow(), "rule_id": rule_id}},
    )


def mark_as_unblocked(value: str, itype: str):
    col = get_indicators_collection()
    col.update_one(
        {"value": value, "type": itype},
        {"$set": {"blocked": False, "unblocked_at": datetime.utcnow()}, "$unset": {"rule_id": ""}},
    )


def log_enforcement_action(action: dict):
    col = get_logs_collection()
    col.insert_one({**action, "timestamp": datetime.utcnow()})
