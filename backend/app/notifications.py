"""
Email notifications for CRITICAL severity findings.
Uses aiosmtplib (async SMTP). Silently skips if SMTP is not configured.
"""

import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .config import settings


async def send_critical_alert(scan_id: str, critical_count: int, source_ref: str) -> None:
    if not all([settings.SMTP_USER, settings.SMTP_PASSWORD, settings.ALERT_EMAIL]):
        return

    subject = f"[CRITICAL] {critical_count} critical secret(s) detected — Secrets Scanner"
    body = f"""
    <h2>Critical Secrets Detected</h2>
    <p>Scan ID: <code>{scan_id}</code></p>
    <p>Source: <code>{source_ref}</code></p>
    <p><strong>{critical_count} CRITICAL severity finding(s)</strong> were detected.</p>
    <p>Review the full report: <a href="{settings.BACKEND_URL}/api/v1/scans/{scan_id}">
        {settings.BACKEND_URL}/api/v1/scans/{scan_id}
    </a></p>
    <hr>
    <p><small>Automated Secrets Scanner — DevSecOps Dashboard</small></p>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = settings.ALERT_EMAIL
    msg.attach(MIMEText(body, "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            start_tls=True,
        )
    except Exception:
        pass  # Notification failure must not crash the scan
