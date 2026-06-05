"""
Alerting & Notification Module
Sends email alerts to SOC team when indicators are auto-blocked.
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger
import config


def send_email(subject: str, body: str, recipients: list = None):
    """Send an email alert via SMTP."""
    if not config.SMTP_USER or not config.SMTP_PASS:
        logger.debug("SMTP credentials not configured — skipping email alert")
        return False

    if not recipients:
        recipients = [r for r in config.ALERT_RECIPIENTS if r]

    if not recipients:
        logger.debug("No alert recipients configured")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.SMTP_USER
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.sendmail(config.SMTP_USER, recipients, msg.as_string())
        logger.info(f"Alert sent to {recipients}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False

def send_block_alert(value: str, itype: str, risk_score: int, rule_id: str):
    """Alert SOC team when an indicator is auto-blocked."""
    subject = f"[TIP ALERT] Auto-blocked {itype.upper()}: {value}"
    body = f"""
    <html><body>
    <h2 style="color:#c0392b;">Threat Intelligence Platform — Auto-Block Alert</h2>
    <table border="1" cellpadding="8" style="border-collapse:collapse;">
      <tr><td><b>Indicator</b></td><td>{value}</td></tr>
      <tr><td><b>Type</b></td><td>{itype}</td></tr>
      <tr><td><b>Risk Score</b></td><td>{risk_score}/100</td></tr>
      <tr><td><b>Rule ID</b></td><td>{rule_id}</td></tr>
      <tr><td><b>Action</b></td><td>AUTO-BLOCKED via iptables / /etc/hosts</td></tr>
    </table>
    <p>To roll back this rule (false positive), use the TIP dashboard or API:</p>
    <pre>POST /api/rollback  body: {{"value": "{value}", "type": "{itype}", "rule_id": "{rule_id}"}}</pre>
    <p style="color:#888;">This is an automated message from the TIP Enforcer Daemon.</p>
    </body></html>
    """
    send_email(subject, body)

def send_daily_summary(blocked_today: int, total_indicators: int, high_risk_count: int):
    """Send a daily threat summary to the SOC team."""
    subject = "[TIP] Daily Threat Intelligence Summary"
    body = f"""
    <html><body>
    <h2>Daily Threat Intelligence Summary</h2>
    <table border="1" cellpadding="8" style="border-collapse:collapse;">
      <tr><td><b>New blocks today</b></td><td>{blocked_today}</td></tr>
      <tr><td><b>Total indicators in DB</b></td><td>{total_indicators}</td></tr>
      <tr><td><b>High-risk indicators</b></td><td>{high_risk_count}</td></tr>
    </table>
    <p>Log into Kibana to view the full threat landscape dashboard.</p>
    </body></html>
    """
    send_email(subject, body)
