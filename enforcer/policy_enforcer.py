"""
Dynamic Security Policy Enforcer Daemon
Continuously polls MongoDB for high-risk indicators and auto-enforces firewall rules.
"""
import time
import signal
import sys
import threading
import shutil
from datetime import datetime
from loguru import logger
from pymongo.errors import PyMongoError
import config
from database import (
    get_high_risk_unblocked,
    mark_as_blocked,
    mark_as_unblocked,
    log_enforcement_action,
)
from enforcer.iptables_manager import (
    ensure_tip_chain,
    block_ip,
    unblock_ip,
    block_domain_via_dns,
    unblock_domain_via_dns,
)
from alerting.notifier import send_block_alert


_running = True


def handle_signal(signum, frame):
    global _running
    logger.info(f"Received signal {signum} — shutting down enforcer gracefully")
    _running = False


def enforce_indicator(indicator: dict) -> bool:
    """
    Block a single indicator. Returns True on success.
    """
    value = indicator["value"]
    itype = indicator["type"]
    score = indicator.get("risk_score", 0)

    logger.info(f"Enforcing block: [{itype}] {value} (score={score})")

    try:
        if itype == "ip":
            rule_id = block_ip(value)
        elif itype == "domain":
            rule_id = block_domain_via_dns(value)
        else:
            # URLs and hashes can't be directly blocked by iptables
            logger.debug(f"Skipping non-blockable type: {itype}")
            return False

        mark_as_blocked(value, itype, rule_id)
        log_enforcement_action({
            "action": "BLOCK",
            "value": value,
            "type": itype,
            "rule_id": rule_id,
            "risk_score": score,
            "analyst": "DAEMON",
            "reason": "Auto-block: risk score exceeded threshold",
        })

        # Alert SOC
        send_block_alert(value, itype, score, rule_id)
        return True

    except Exception as e:
        logger.error(f"Failed to enforce block for {value}: {e}")
        return False


def rollback_indicator(value: str, itype: str, rule_id: str, analyst: str = "SOC") -> bool:
    """
    Rollback (unblock) a previously blocked indicator.
    Called by the API when a SOC analyst flags a false positive.
    """
    logger.info(f"Rolling back block: [{itype}] {value} rule_id={rule_id}")
    try:
        if itype == "ip":
            success = unblock_ip(value, rule_id)
        elif itype == "domain":
            success = unblock_domain_via_dns(value, rule_id)
        else:
            return False

        if success:
            mark_as_unblocked(value, itype)
            log_enforcement_action({
                "action": "UNBLOCK",
                "value": value,
                "type": itype,
                "rule_id": rule_id,
                "analyst": analyst,
                "reason": "Manual rollback — false positive",
            })
        return success
    except Exception as e:
        logger.error(f"Rollback failed for {value}: {e}")
        return False


def enforcement_cycle():
    """Single enforcement pass — check DB and block new high-risk indicators."""
    candidates = get_high_risk_unblocked(threshold=config.RISK_SCORE_HIGH)
    if not candidates:
        logger.debug("No new high-risk indicators to enforce")
        return 0

    logger.info(f"Enforcement cycle: {len(candidates)} candidates to block")
    blocked = 0
    for ind in candidates:
        if enforce_indicator(ind):
            blocked += 1

    if blocked:
        logger.info(f"Enforcement cycle complete: {blocked} new blocks applied")
    return blocked


def run():
    """Main daemon loop."""
    global _running

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
    else:
        logger.debug("Skipping signal registration outside the main thread")

    logger.info("Dynamic Policy Enforcer daemon starting...")
    logger.info(f"Poll interval: {config.ENFORCER_POLL_INTERVAL}s | Threshold: {config.RISK_SCORE_HIGH}")

    if not sys.platform.startswith("linux"):
        logger.warning("Policy enforcer requires Linux with iptables; skipping enforcement on this platform")
        return

    enforcer_enabled = True
    if shutil.which("iptables") is None:
        logger.warning("iptables is unavailable on this Linux host — running policy enforcer in observation-only mode")
        enforcer_enabled = False
    else:
        try:
            ensure_tip_chain()
        except Exception as e:
            logger.critical(f"Cannot initialize iptables chain: {e}")
            logger.warning("Disabling policy enforcer — running in observation-only mode")
            enforcer_enabled = False

    while _running:
        try:
            if enforcer_enabled:
                enforcement_cycle()
            else:
                logger.debug("Enforcer disabled — skipping enforcement cycle")
        except PyMongoError as e:
            logger.warning(f"MongoDB unavailable; skipping enforcement cycle: {e}")
        except Exception as e:
            logger.error(f"Enforcement cycle error: {e}")

        # Sleep in small increments so signal handling is responsive
        for _ in range(config.ENFORCER_POLL_INTERVAL):
            if not _running:
                break
            time.sleep(1)

    logger.info("Policy Enforcer daemon stopped.")


if __name__ == "__main__":
    run()
