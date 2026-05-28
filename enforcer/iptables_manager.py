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


