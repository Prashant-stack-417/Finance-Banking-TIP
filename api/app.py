"""
TIP REST API
Provides endpoints for the SOC dashboard:
    GET  /api/indicators       — list indicators with filters
    GET  /api/indicators/<val> — single indicator detail
    GET  /api/logs             — enforcement logs
    POST /api/rollback         — rollback a false positive
    GET  /api/stats            — summary stats
    GET  /api/high-risk-ips    — high-risk IPs with advanced filtering
    GET  /api/high-risk-stats  — statistics about high-risk IPs
    GET  /api/rules            — current iptables TIP rules
"""
from flask import Flask, jsonify, request, abort, render_template
from flask_cors import CORS
from loguru import logger
from datetime import datetime, timedelta
import config
from database import (
    get_indicators_collection,
    get_logs_collection,
    get_high_risk_unblocked,
)
from enforcer.policy_enforcer import rollback_indicator
from enforcer.iptables_manager import list_tip_rules

app = Flask(__name__)
CORS(app)


@app.route("/", methods=["GET"])
def home():
    """Serve the dashboard to browsers while preserving JSON for API clients."""
    wants_html = request.accept_mimetypes.accept_html and not request.accept_mimetypes.accept_json
    if wants_html:
        return render_template("dashboard.html")

    return jsonify({
        "status": "ok",
        "service": "Threat Intelligence Platform",
        "dashboard": "/",
        "endpoints": [
            "/api/indicators",
            "/api/logs",
            "/api/stats",
            "/api/high-risk-ips",
            "/api/high-risk-stats",
            "/api/rules",
            "/api/rollback",
        ],
    })


@app.route("/ui", methods=["GET"])
def dashboard():
    """Explicit UI route for the browser dashboard."""
    return render_template("dashboard.html")


def serialize(doc: dict) -> dict:
    """Convert MongoDB doc to JSON-serializable dict."""
    doc.pop("_id", None)
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


@app.route("/api/indicators", methods=["GET"])
def list_indicators():
    """
    Query params:
      type=ip|domain|url|hash
      blocked=true|false
      min_score=0-100
      limit=50
      source=URLhaus|AlienVault OTX|VirusTotal
    """
    col = get_indicators_collection()
    query = {}

    if request.args.get("type"):
        query["type"] = request.args["type"]
    if request.args.get("blocked") in ("true", "false"):
        query["blocked"] = request.args["blocked"] == "true"
    if request.args.get("min_score"):
        query["risk_score"] = {"$gte": int(request.args["min_score"])}
    if request.args.get("source"):
        query["source"] = request.args["source"]

    limit = min(int(request.args.get("limit", 100)), 500)
    docs = list(col.find(query, {"_id": 0}).sort("risk_score", -1).limit(limit))
    return jsonify([serialize(d) for d in docs])


@app.route("/api/indicators/<path:value>", methods=["GET"])
def get_indicator(value: str):
    col = get_indicators_collection()
    doc = col.find_one({"value": value}, {"_id": 0})
    if not doc:
        abort(404, description="Indicator not found")
    return jsonify(serialize(doc))


@app.route("/api/logs", methods=["GET"])
def list_logs():
    col = get_logs_collection()
    limit = min(int(request.args.get("limit", 100)), 1000)
    action_filter = request.args.get("action")
    query = {}
    if action_filter:
        query["action"] = action_filter.upper()
    docs = list(col.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return jsonify([serialize(d) for d in docs])


@app.route("/api/rollback", methods=["POST"])
def rollback():
    """
    Roll back a false positive block.
    Body: { "value": "1.2.3.4", "type": "ip", "rule_id": "abc12345", "analyst": "jsmith" }
    """
    data = request.get_json()
    if not data:
        abort(400, description="JSON body required")

    value = data.get("value", "").strip()
    itype = data.get("type", "").strip()
    rule_id = data.get("rule_id", "").strip()
    analyst = data.get("analyst", "SOC").strip()

    if not all([value, itype, rule_id]):
        abort(400, description="value, type, and rule_id are required")

    success = rollback_indicator(value, itype, rule_id, analyst)
    if success:
        logger.info(f"Rollback successful: {value} by {analyst}")
        return jsonify({"status": "success", "message": f"Unblocked {value}"})
    else:
        abort(500, description=f"Rollback failed for {value}")


@app.route("/api/stats", methods=["GET"])
def stats():
    col = get_indicators_collection()
    pipeline = [
        {"$group": {
            "_id": None,
            "total": {"$sum": 1},
            "blocked": {"$sum": {"$cond": ["$blocked", 1, 0]}},
            "high_risk": {"$sum": {"$cond": [{"$gte": ["$risk_score", config.RISK_SCORE_HIGH]}, 1, 0]}},
            "avg_score": {"$avg": "$risk_score"},
        }}
    ]
    result = list(col.aggregate(pipeline))
    if result:
        r = result[0]
        r.pop("_id", None)
        r["avg_score"] = round(r.get("avg_score", 0), 1)
    else:
        r = {"total": 0, "blocked": 0, "high_risk": 0, "avg_score": 0}

    # Type breakdown
    type_counts = list(col.aggregate([
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ]))
    r["by_type"] = {d["_id"]: d["count"] for d in type_counts}

    # Source breakdown
    source_counts = list(col.aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}}
    ]))
    r["by_source"] = {d["_id"]: d["count"] for d in source_counts}

    return jsonify(r)


@app.route("/api/high-risk-ips", methods=["GET"])
def high_risk_ips():
    """
    Get high-risk IPs with advanced filtering.
    
    Query params:
      filter=all|unblocked|blocked|critical  (default: unblocked)
      source=URLhaus|AlienVault OTX|VirusTotal
      tag=malware|botnet|ransomware|phishing|exploit|apt|trojan
      recent_hours=N        (IPs discovered in last N hours)
      threshold=0-100       (custom risk score threshold)
      limit=1-500           (default: 100)
    """
    col = get_indicators_collection()
    threshold = int(request.args.get("threshold", config.RISK_SCORE_HIGH))
    query = {
        "type": "ip",
        "risk_score": {"$gte": threshold}
    }
    
    # Filter type
    filter_type = request.args.get("filter", "unblocked")
    if filter_type == "blocked":
        query["blocked"] = True
    elif filter_type == "critical":
        query["risk_score"] = {"$gte": 90}
        query["blocked"] = False
    elif filter_type == "unblocked":
        query["blocked"] = False
    # "all" means no blocked filter
    
    # Source filter
    if request.args.get("source"):
        query["source"] = request.args["source"]
    
    # Tag filter
    if request.args.get("tag"):
        query["tags"] = request.args["tag"].lower()
    
    # Recent hours filter
    if request.args.get("recent_hours"):
        hours = int(request.args["recent_hours"])
        since = datetime.utcnow() - timedelta(hours=hours)
        query["first_seen"] = {"$gte": since}
    
    limit = min(int(request.args.get("limit", 100)), 500)
    docs = list(col.find(query, {"_id": 0}).sort("risk_score", -1).limit(limit))
    
    return jsonify({
        "count": len(docs),
        "threshold": threshold,
        "filter": filter_type,
        "ips": [serialize(d) for d in docs]
    })


@app.route("/api/high-risk-stats", methods=["GET"])
def high_risk_stats():
    """Get statistics specifically about high-risk IPs."""
    col = get_indicators_collection()
    threshold = int(request.args.get("threshold", config.RISK_SCORE_HIGH))
    
    query = {"type": "ip", "risk_score": {"$gte": threshold}}
    
    total = col.count_documents(query)
    blocked = col.count_documents({**query, "blocked": True})
    unblocked = col.count_documents({**query, "blocked": False})
    
    # Critical IPs (score >= 90)
    critical = col.count_documents({"type": "ip", "risk_score": {"$gte": 90}, "blocked": False})
    
    # By source
    source_breakdown = list(col.aggregate([
        {"$match": query},
        {"$group": {"_id": "$source", "count": {"$sum": 1}}}
    ]))
    
    # Top tags
    tag_breakdown = list(col.aggregate([
        {"$match": query},
        {"$unwind": "$tags"},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]))
    
    return jsonify({
        "total_high_risk": total,
        "blocked": blocked,
        "unblocked": unblocked,
        "critical_unblocked": critical,
        "threshold": threshold,
        "by_source": {d["_id"]: d["count"] for d in source_breakdown},
        "top_tags": {d["_id"]: d["count"] for d in tag_breakdown},
    })


@app.route("/api/rules", methods=["GET"])
def iptables_rules():
    """Return current TIP iptables rules (read-only)."""
    try:
        rules = list_tip_rules()
        return jsonify({"rules": rules})
    except Exception as e:
        return jsonify({"error": str(e), "rules": []})


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def error_handler(e):
    return jsonify({"error": str(e)}), e.code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
