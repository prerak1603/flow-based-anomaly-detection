"""
Aegis AI v2 - Critical-severity alerting (Slack / email)
================================================================================

Fires when a completed /analyze call produced at least one CRITICAL-severity
detection, if the customer has opted in via /account/alert-settings. This is
deliberately best-effort and side-channel: every function here swallows its
own exceptions and only logs — a broken webhook URL or a Resend outage must
never affect the /analyze response the customer is waiting on. main.py calls
this via FastAPI's BackgroundTasks, after the response has already been
built, so it can't add latency either.
================================================================================
"""

import logging
import os

import requests

from app.db import Customer

logger = logging.getLogger("aegis")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
# resend.dev works with zero setup (no domain verification) but only ever
# delivers to the Resend account owner's own address — fine for testing,
# not for real customer alerts. Swap once a sending domain is verified.
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "Aegis AI <onboarding@resend.dev>")


def send_critical_alert(customer: Customer, critical_detections: list[dict]):
    """
    `critical_detections` is a list of plain dicts (not ORM objects — this
    runs in a background task after the DB session that created them may
    already be closed): {attack_type, confidence, narrative}.
    """
    if not critical_detections:
        return

    if customer.slack_webhook_url:
        try:
            _send_slack(customer, critical_detections)
        except Exception as e:
            logger.warning(f"Slack alert failed for customer {customer.id}: {e}")

    if customer.alert_email:
        try:
            _send_email(customer, critical_detections)
        except Exception as e:
            logger.warning(f"Email alert failed for customer {customer.id}: {e}")


def _send_slack(customer: Customer, detections: list[dict]):
    count = len(detections)
    top = detections[0]
    lines = [
        f"🚨 *{count} CRITICAL threat{'s' if count != 1 else ''} detected* in a new Aegis AI analysis",
        f">*{top['attack_type']}* — {top['confidence'] * 100:.1f}% confidence",
    ]
    if top.get("narrative"):
        snippet = top["narrative"][:300]
        lines.append(f">{snippet}{'…' if len(top['narrative']) > 300 else ''}")
    lines.append(f"<{FRONTEND_URL}/history|View full history>")

    resp = requests.post(
        customer.slack_webhook_url,
        json={"text": "\n".join(lines)},
        timeout=10,
    )
    resp.raise_for_status()


def _send_email(customer: Customer, detections: list[dict]):
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not configured — skipping email alert.")
        return

    count = len(detections)
    top = detections[0]
    rows = "".join(
        f"<tr><td style='padding:6px 12px;border-bottom:1px solid #2c3346;'>{d['attack_type']}</td>"
        f"<td style='padding:6px 12px;border-bottom:1px solid #2c3346;'>{d['confidence'] * 100:.1f}%</td></tr>"
        for d in detections[:10]
    )
    html = f"""
    <div style="font-family:sans-serif;background:#0a0d13;color:#e8eaf1;padding:24px;">
      <h2 style="color:#e8453b;">{count} CRITICAL threat{'s' if count != 1 else ''} detected</h2>
      <p style="color:#8891a3;">Aegis AI flagged {count} CRITICAL-severity flow{'s' if count != 1 else ''}
      in a new analysis on your account.</p>
      {f"<p>{top['narrative'][:400]}</p>" if top.get('narrative') else ''}
      <table style="border-collapse:collapse;width:100%;margin:16px 0;">{rows}</table>
      <a href="{FRONTEND_URL}/history"
         style="display:inline-block;padding:10px 20px;background:#7c8cf8;color:#0a0d13;
                border-radius:8px;text-decoration:none;font-weight:600;">View full history</a>
    </div>
    """

    resp = requests.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        json={
            "from": RESEND_FROM_EMAIL,
            "to": customer.alert_email,
            "subject": f"Aegis AI: {count} CRITICAL threat{'s' if count != 1 else ''} detected",
            "html": html,
        },
        timeout=10,
    )
    resp.raise_for_status()
