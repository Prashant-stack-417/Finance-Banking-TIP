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
