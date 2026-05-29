"""
iptables Manager
Handles all system-level firewall rule creation, deletion, and chain management.
Requires root / sudo privileges.
"""
import shutil
import subprocess
import uuid
from loguru import logger
import config


def _run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute an iptables command safely."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            timeout=10,
        )
        if result.returncode != 0 and check:
            logger.error(f"iptables error: {result.stderr.strip()}")
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"iptables command timed out: {' '.join(cmd)}")
        raise
    except FileNotFoundError:
        logger.error("iptables not found. Are you running as root on Linux?")
        raise

def ensure_tip_chain():
    """
    Create the TIP_BLOCK custom chain and hook it into INPUT/FORWARD if not present.
    Using a dedicated chain keeps TIP rules isolated and easy to flush.
    """

    chain = config.IPTABLES_CHAIN

    # Check if chain exists
    result = _run(["iptables", "-L", chain, "-n"], check=False)

    if result.returncode != 0:
        _run(["iptables", "-N", chain])
        logger.info(f"Created iptables chain: {chain}")

    # Hook chain into INPUT if not already
    check_input = _run(["iptables", "-C", "INPUT", "-j", chain], check=False)

    if check_input.returncode != 0:
        _run(["iptables", "-I", "INPUT", "1", "-j", chain])
        logger.info(f"Hooked {chain} into INPUT chain")

    # Hook into FORWARD
    check_fwd = _run(["iptables", "-C", "FORWARD", "-j", chain], check=False)

    if check_fwd.returncode != 0:
        _run(["iptables", "-I", "FORWARD", "1", "-j", chain])
        logger.info(f"Hooked {chain} into FORWARD chain")
