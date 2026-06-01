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

def block_ip(ip: str) -> str:
    """
    Add a DROP rule for a malicious IP.
    Returns a rule_id for later rollback.
    """

    rule_id = str(uuid.uuid4())[:8]
    comment = f"TIP-{rule_id}"
    chain = config.IPTABLES_CHAIN

    # Block inbound
    _run([
        "iptables", "-A", chain,
        "-s", ip,
        "-j", "DROP",
        "-m", "comment", "--comment", comment,
    ])

    # Block outbound
    _run([
        "iptables", "-A", chain,
        "-d", ip,
        "-j", "DROP",
        "-m", "comment", "--comment", comment,
    ])

    logger.info(f"Blocked IP {ip} (rule_id={rule_id})")

    return rule_id


def unblock_ip(ip: str, rule_id: str) -> bool:
    """
    Remove DROP rules for an IP by comment/rule_id.
    Returns True if rules were found and removed.
    """

    comment = f"TIP-{rule_id}"
    chain = config.IPTABLES_CHAIN
    removed = False

    for direction, flag in [("-s", ip), ("-d", ip)]:

        result = _run([
            "iptables", "-D", chain,
            direction, flag,
            "-j", "DROP",
            "-m", "comment", "--comment", comment,
        ], check=False)

        if result.returncode == 0:
            removed = True

    if removed:
        logger.info(f"Unblocked IP {ip} (rule_id={rule_id})")

    else:
        logger.warning(f"No iptables rules found for IP {ip} rule_id={rule_id}")

    return removed

def block_domain_via_dns(domain: str) -> str:
    """
    Block a domain by redirecting it to 0.0.0.0 via /etc/hosts.
    (iptables cannot filter by domain name directly.)
    Returns rule_id for rollback.
    """

    rule_id = str(uuid.uuid4())[:8]
    entry = f"0.0.0.0 {domain}  # TIP-{rule_id}\n"

    try:
        with open("/etc/hosts", "a") as f:
            f.write(entry)

        logger.info(f"Blocked domain {domain} via /etc/hosts (rule_id={rule_id})")

    except PermissionError:
        logger.error("Cannot write to /etc/hosts — need root privileges")
        raise

    return rule_id

def unblock_domain_via_dns(domain: str, rule_id: str) -> bool:
    """Remove a domain entry from /etc/hosts by rule_id."""

    marker = f"# TIP-{rule_id}"

    try:
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()

        new_lines = [l for l in lines if marker not in l]

        if len(new_lines) == len(lines):
            logger.warning(f"No /etc/hosts entry found for domain {domain} rule_id={rule_id}")
            return False

        with open("/etc/hosts", "w") as f:
            f.writelines(new_lines)

        logger.info(f"Unblocked domain {domain} from /etc/hosts (rule_id={rule_id})")

        return True

    except Exception as e:
        logger.error(f"Error unblocking domain {domain}: {e}")

        return False
