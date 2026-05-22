"""
TIP Main Orchestrator
Schedules and runs all ingestion pipelines and SIEM sync.
Run this as a background process alongside the enforcer daemon.
"""
import schedule
import time
import threading
from loguru import logger
import config
from loguru import logger
import os


def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logger.add(
        config.LOG_FILE,
        rotation="10 MB",
        retention="30 days",
        level=config.LOG_LEVEL,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
    )


def run_ingestion():
    logger.info("=== Starting full ingestion cycle ===")
    try:
        from ingestion.otx_feed import run as otx_run
        otx_run()
    except Exception as e:
        logger.error(f"OTX ingestion failed: {e}")

    try:
        from ingestion.urlhaus_feed import run as urlhaus_run
        urlhaus_run()
    except Exception as e:
        logger.error(f"URLhaus ingestion failed: {e}")

    try:
        from ingestion.virustotal_feed import run as vt_run
        vt_run()
    except Exception as e:
        logger.error(f"VirusTotal enrichment failed: {e}")

    logger.info("=== Ingestion cycle complete ===")


def run_siem_sync():
    logger.info("Starting SIEM sync...")
    try:
        from siem.elk_sync import run as elk_run
        elk_run()
    except Exception as e:
        logger.error(f"SIEM sync failed: {e}")


def run_daily_summary():
    from database import get_indicators_collection
    from alerting.notifier import send_daily_summary
    col = get_indicators_collection()
    total = col.count_documents({})
    high_risk = col.count_documents({"risk_score": {"$gte": config.RISK_SCORE_HIGH}})
    from datetime import datetime, timedelta
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    blocked_today = col.count_documents({"blocked": True, "blocked_at": {"$gte": today_start}})
    send_daily_summary(blocked_today, total, high_risk)


def start_enforcer_daemon():
    """Start the policy enforcer in a background thread."""
    import sys
    if not sys.platform.startswith("linux"):
        logger.warning("Policy Enforcer requires Linux (iptables). Skipping enforcer on this platform.")
        return None

    from enforcer.policy_enforcer import run as enforcer_run
    t = threading.Thread(target=enforcer_run, daemon=True, name="PolicyEnforcer")
    t.start()
    logger.info("Policy Enforcer daemon started in background thread")
    return t


def start_api_server():
    """Start the Flask API in a background thread."""
    from api.app import app
    t = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False),
        daemon=True,
        name="APIServer",
    )
    t.start()
    logger.info("REST API server started on http://0.0.0.0:5000")
    return t


def main():
    setup_logging()
    logger.info("========================================")
    logger.info("  Threat Intelligence Platform Starting  ")
    logger.info("========================================")

    # Run ingestion immediately on startup
    run_ingestion()
    run_siem_sync()

    # Schedule recurring tasks
    schedule.every(1).hours.do(run_ingestion)
    schedule.every(30).minutes.do(run_siem_sync)
    schedule.every().day.at("08:00").do(run_daily_summary)

    # Start daemons
    start_enforcer_daemon()
    start_api_server()

    logger.info("Scheduler running. Press Ctrl+C to stop.")
    try:
        while True:
            schedule.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        logger.info("TIP shutting down.")


if __name__ == "__main__":
    main()
