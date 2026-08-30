"""
Aegis AI v2 - Billing (Lemon Squeezy) & tier enforcement
================================================================================

Payment gateway: Lemon Squeezy, not Stripe. Stripe does not onboard
India-based individuals/businesses for standard accounts, so a merchant of
record was used instead — Lemon Squeezy legally sells on our behalf, which
means it also handles global sales tax/VAT/GST automatically and onboards
individual sellers with no registered company required. It was picked over
Razorpay (India-native, but doesn't do global tax compliance and is INR-first)
specifically because its API shape — server creates a checkout, gets back a
hosted URL, redirects the browser there; webhooks keep tier in sync; a
hosted portal URL handles self-serve billing — maps directly onto this
module's structure with no architectural rework.

Everything Lemon Squeezy-related lives here and nowhere else: the frontend
BFF never sees the API key, it only ever calls the /billing/* endpoints in
main.py, which call into this module. LEMONSQUEEZY_API_KEY lives on Render
only. There's no official Lemon Squeezy Python SDK worth depending on, so
this talks to their REST API directly with `requests` (already a
transitive dependency here, same as the existing Clerk webhook handler).
================================================================================
"""

import hashlib
import hmac
import logging
import os
from datetime import datetime

import requests
from fastapi import Depends, HTTPException
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.db import get_db, Customer
from app.auth import get_current_customer

logger = logging.getLogger("aegis")

# ==============================================================================
# CONFIG
# ==============================================================================

LEMONSQUEEZY_API_BASE = "https://api.lemonsqueezy.com/v1"
LEMONSQUEEZY_API_KEY = os.getenv("LEMONSQUEEZY_API_KEY")
LEMONSQUEEZY_STORE_ID = os.getenv("LEMONSQUEEZY_STORE_ID")
LEMONSQUEEZY_WEBHOOK_SECRET = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET")

# Where Lemon Squeezy should bounce the browser back to after checkout.
# Must be the deployed frontend origin in production.
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Variant ID env vars are set once the user creates the two subscription
# Variants in the Lemon Squeezy Dashboard (test mode first, then swapped to
# live IDs when ready to launch — same env var names either way).
LEMONSQUEEZY_VARIANT_STARTER = os.getenv("LEMONSQUEEZY_VARIANT_STARTER")
LEMONSQUEEZY_VARIANT_PRO = os.getenv("LEMONSQUEEZY_VARIANT_PRO")

# Monthly analysis caps per tier. "Free" needs no gateway involvement at all.
# Pro's extra `max_agent_analyses` raises how many flagged flows in a single
# /analyze call get a full agent narrative (see main.py) — everything else
# about the pipeline is identical across tiers.
TIER_LIMITS = {
    "free":    {"monthly_analyses": 5,    "max_agent_analyses": 8,  "label": "Free"},
    "starter": {"monthly_analyses": 100,  "max_agent_analyses": 8,  "label": "Starter"},
    "pro":     {"monthly_analyses": 1000, "max_agent_analyses": 15, "label": "Pro"},
}

# tier name -> Lemon Squeezy Variant ID, and the reverse, built once at
# import time. A tier whose variant env var isn't set yet (e.g. mid-setup)
# is simply unavailable for checkout rather than crashing the app.
_TIER_TO_VARIANT = {
    "starter": LEMONSQUEEZY_VARIANT_STARTER,
    "pro": LEMONSQUEEZY_VARIANT_PRO,
}
_VARIANT_TO_TIER = {variant: tier for tier, variant in _TIER_TO_VARIANT.items() if variant}


def next_billing_period(dt: datetime) -> datetime:
    """First moment of the following month — used as the rolling usage_reset_date."""
    if dt.month == 12:
        return dt.replace(year=dt.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return dt.replace(month=dt.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)


def _ls_headers() -> dict:
    return {
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
        "Authorization": f"Bearer {LEMONSQUEEZY_API_KEY}",
    }


# ==============================================================================
# TIER-CHECK DEPENDENCY — the gate on /analyze (gateway-agnostic: unchanged
# no matter which payment provider is behind it)
# ==============================================================================

def check_and_reserve_usage(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> Customer:
    """
    Drop-in replacement for `Depends(get_current_customer)` on /analyze only.
    Resolves the customer exactly as before, then:

      1. Lazily rolls the usage window forward if it's due (no cron needed).
      2. Rejects with 402 if the customer is already at their monthly cap.
      3. Atomically reserves one unit of usage via a conditional UPDATE —
         correct under concurrent requests on both Postgres (prod) and
         SQLite (dev), since the WHERE clause makes the increment a no-op
         (0 rows affected) instead of overshooting the cap in a race.

    Nothing downstream of this in /analyze needs to know any of this
    happened — it still just gets a `Customer` back.
    """
    limits = TIER_LIMITS.get(customer.tier, TIER_LIMITS["free"])
    cap = limits["monthly_analyses"]

    now = datetime.utcnow()
    if customer.usage_reset_date is None or now >= customer.usage_reset_date:
        customer.usage_count = 0
        customer.usage_reset_date = next_billing_period(now)
        db.add(customer)
        db.commit()
        db.refresh(customer)

    if customer.usage_count >= cap:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "usage_limit_reached",
                "message": (
                    f"You've used all {cap} analyses included in your "
                    f"{limits['label']} plan this month. Upgrade to keep going."
                ),
                "tier": customer.tier,
                "limit": cap,
                "usage_count": customer.usage_count,
                "reset_date": customer.usage_reset_date.isoformat(),
                "upgrade_url": "/pricing",
            },
        )

    result = db.execute(
        update(Customer)
        .where(Customer.id == customer.id, Customer.usage_count < cap)
        .values(usage_count=Customer.usage_count + 1)
    )
    db.commit()

    if result.rowcount == 0:
        # Lost the race for the last slot this period.
        raise HTTPException(
            status_code=402,
            detail={
                "error": "usage_limit_reached",
                "message": (
                    f"You've used all {cap} analyses included in your "
                    f"{limits['label']} plan this month. Upgrade to keep going."
                ),
                "tier": customer.tier,
                "limit": cap,
                "upgrade_url": "/pricing",
            },
        )

    db.refresh(customer)
    return customer


def max_agent_analyses_for(customer: Customer) -> int:
    """How many flagged flows in this /analyze call get a full agent narrative."""
    limits = TIER_LIMITS.get(customer.tier, TIER_LIMITS["free"])
    return limits["max_agent_analyses"]


# ==============================================================================
# LEMON SQUEEZY CHECKOUT / PORTAL
# ==============================================================================

def create_checkout_session(customer: Customer, tier: str) -> str:
    variant_id = _TIER_TO_VARIANT.get(tier)
    if not variant_id:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown or unconfigured tier '{tier}'. Valid tiers: {list(_TIER_TO_VARIANT)}",
        )

    if not LEMONSQUEEZY_API_KEY or not LEMONSQUEEZY_STORE_ID:
        raise HTTPException(
            status_code=500,
            detail="Billing is not configured (LEMONSQUEEZY_API_KEY / LEMONSQUEEZY_STORE_ID missing).",
        )

    payload = {
        "data": {
            "type": "checkouts",
            "attributes": {
                "checkout_data": {
                    "email": customer.email,
                    # This is how the webhook maps a completed checkout back
                    # to a customer row without any other lookup — Lemon
                    # Squeezy echoes `custom` back in every subscription
                    # webhook's meta.custom_data.
                    "custom": {"aegis_customer_id": customer.id, "tier": tier},
                },
                "product_options": {
                    "redirect_url": f"{FRONTEND_URL}/account?checkout=success",
                },
            },
            "relationships": {
                "store": {"data": {"type": "stores", "id": str(LEMONSQUEEZY_STORE_ID)}},
                "variant": {"data": {"type": "variants", "id": str(variant_id)}},
            },
        }
    }

    try:
        resp = requests.post(
            f"{LEMONSQUEEZY_API_BASE}/checkouts",
            json=payload,
            headers=_ls_headers(),
            timeout=15,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Lemon Squeezy checkout creation failed for customer {customer.id}: {e}")
        raise HTTPException(status_code=502, detail="Could not start checkout. Please try again in a moment.")

    return resp.json()["data"]["attributes"]["url"]


def create_portal_session(customer: Customer) -> str:
    """
    Lemon Squeezy doesn't have a single "create a portal session" endpoint
    like Stripe's Billing Portal — each subscription carries its own
    `urls.customer_portal` link. Fetch the subscription fresh so the link
    is current rather than caching a possibly-stale one from webhook time.
    """
    if not customer.ls_subscription_id:
        raise HTTPException(
            status_code=400,
            detail="No billing account yet — subscribe to a paid plan first.",
        )

    if not LEMONSQUEEZY_API_KEY:
        raise HTTPException(status_code=500, detail="Billing is not configured (LEMONSQUEEZY_API_KEY missing).")

    try:
        resp = requests.get(
            f"{LEMONSQUEEZY_API_BASE}/subscriptions/{customer.ls_subscription_id}",
            headers=_ls_headers(),
            timeout=15,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Lemon Squeezy portal lookup failed for customer {customer.id}: {e}")
        raise HTTPException(status_code=502, detail="Could not open the billing portal. Please try again in a moment.")

    url = resp.json()["data"]["attributes"]["urls"]["customer_portal"]
    return url


def tier_for_variant_id(variant_id) -> str | None:
    return _VARIANT_TO_TIER.get(str(variant_id))


def verify_webhook_signature(raw_body: bytes, signature_header: str | None) -> bool:
    """
    Lemon Squeezy signs webhooks as an HMAC-SHA256 hex digest of the raw
    body using the store's signing secret, sent in the X-Signature header.
    """
    if not LEMONSQUEEZY_WEBHOOK_SECRET or not signature_header:
        return False
    digest = hmac.new(LEMONSQUEEZY_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature_header)
