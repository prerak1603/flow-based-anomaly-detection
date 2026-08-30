"""
Aegis AI v2 - Billing (Gumroad) & tier enforcement
================================================================================

Payment gateway: Gumroad, the third one this project has landed on.
Stripe doesn't onboard India-based individuals. Lemon Squeezy was the next
choice (same merchant-of-record category — handles global VAT/GST
automatically, no registered company required) but its store-creation
signup was returning persistent 429s with no ETA on a fix. Gumroad is the
same merchant-of-record category, with the lowest-friction signup of the
options considered.

Gumroad's API is deliberately simple compared to Stripe/Lemon Squeezy,
which shapes a few real differences here:
  - Each tier (Starter, Pro) is its own Gumroad *product*, not a variant/
    price under one product — so a sale's product id tells us the tier
    directly, no custom-data round-trip needed.
  - "Creating a checkout session" is just building a URL
    (https://<seller>.gumroad.com/l/<permalink>?email=...&wanted=true) —
    there's no server-side session object, so no network call and nothing
    that can fail with a gateway error the way Stripe/LS checkout could.
  - Gumroad has no documented "create a billing portal session" API the
    way Stripe/LS do. A subscriber manages/cancels via the link in their
    purchase receipt email, or by signing into https://gumroad.com/library
    with the email they purchased with. create_portal_session() below
    returns that generic library URL — it is NOT a personalized deep link,
    which is a real, acknowledged gap versus the Stripe/LS experience.
  - Gumroad's webhook ("ping") signing isn't documented with the same
    rigor as Stripe/LS's. Rather than trust the ping payload, every
    webhook here re-fetches the sale from Gumroad's authenticated API
    using our own access token before acting on it — that authenticated
    fetch, not the ping signature, is the actual trust boundary. See
    app/webhooks.py.
================================================================================
"""

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

GUMROAD_API_BASE = "https://api.gumroad.com/v2"
GUMROAD_ACCESS_TOKEN = os.getenv("GUMROAD_ACCESS_TOKEN")
# Set from Gumroad's own webhook config if/when they issue one; verification
# is skipped (not spoofable-safe on its own) when unset — see the module
# docstring on why the real trust boundary is the authenticated API fetch.
GUMROAD_WEBHOOK_SECRET = os.getenv("GUMROAD_WEBHOOK_SECRET")
# The seller's Gumroad subdomain, e.g. "aegis" for aegis.gumroad.com.
GUMROAD_SELLER_SUBDOMAIN = os.getenv("GUMROAD_SELLER_SUBDOMAIN")

# Where the browser lands after checkout. Gumroad doesn't support a
# redirect-on-success URL per checkout the way Stripe/LS do (there's a
# per-*product* "custom receipt / redirect" setting in the Gumroad
# dashboard instead) - FRONTEND_URL is still used for the portal link.
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Product permalink (the part after /l/ in the product URL) for each paid
# tier - set once the two Gumroad products exist.
GUMROAD_PRODUCT_STARTER = os.getenv("GUMROAD_PRODUCT_STARTER")
GUMROAD_PRODUCT_PRO = os.getenv("GUMROAD_PRODUCT_PRO")

# Monthly analysis caps per tier. "Free" needs no gateway involvement at all.
# Pro's extra `max_agent_analyses` raises how many flagged flows in a single
# /analyze call get a full agent narrative (see main.py) — everything else
# about the pipeline is identical across tiers.
TIER_LIMITS = {
    "free":    {"monthly_analyses": 5,    "max_agent_analyses": 8,  "label": "Free"},
    "starter": {"monthly_analyses": 100,  "max_agent_analyses": 8,  "label": "Starter"},
    "pro":     {"monthly_analyses": 1000, "max_agent_analyses": 15, "label": "Pro"},
}

# tier name -> Gumroad product permalink, and the reverse, built once at
# import time. A tier whose product env var isn't set yet (e.g. mid-setup)
# is simply unavailable for checkout rather than crashing the app.
_TIER_TO_PRODUCT = {
    "starter": GUMROAD_PRODUCT_STARTER,
    "pro": GUMROAD_PRODUCT_PRO,
}
_PRODUCT_TO_TIER = {product: tier for tier, product in _TIER_TO_PRODUCT.items() if product}


def next_billing_period(dt: datetime) -> datetime:
    """First moment of the following month — used as the rolling usage_reset_date."""
    if dt.month == 12:
        return dt.replace(year=dt.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return dt.replace(month=dt.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)


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
# GUMROAD CHECKOUT / "PORTAL"
# ==============================================================================

def create_checkout_session(customer: Customer, tier: str) -> str:
    """
    No API call — a Gumroad checkout is just a URL. `wanted=true` sends the
    browser straight to the payment form instead of the product landing
    page; `email=` prefills (not locks) the buyer's email, which is how
    the webhook later matches the sale back to this customer (see
    app/webhooks.py) — if they change the email at checkout, the match
    will fail and the upgrade won't apply, which is a known tradeoff of
    Gumroad's simpler checkout model.
    """
    permalink = _TIER_TO_PRODUCT.get(tier)
    if not permalink:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown or unconfigured tier '{tier}'. Valid tiers: {list(_TIER_TO_PRODUCT)}",
        )

    if not GUMROAD_SELLER_SUBDOMAIN:
        raise HTTPException(status_code=500, detail="Billing is not configured (GUMROAD_SELLER_SUBDOMAIN missing).")

    from urllib.parse import quote

    return (
        f"https://{GUMROAD_SELLER_SUBDOMAIN}.gumroad.com/l/{permalink}"
        f"?email={quote(customer.email)}&wanted=true"
    )


def create_portal_session(customer: Customer) -> str:
    """
    Gumroad has no API for a personalized "manage billing" deep link.
    Subscribers manage/cancel from the link in their purchase receipt
    email, or by signing into gumroad.com/library with the email they
    bought with — this returns that generic library URL, not a session
    scoped to this specific customer.
    """
    if not customer.gumroad_subscription_id:
        raise HTTPException(
            status_code=400,
            detail="No billing account yet — subscribe to a paid plan first.",
        )

    return "https://app.gumroad.com/library"


def tier_for_product(product_id: str | None, product_permalink: str | None) -> str | None:
    """Products are matched by permalink (what GUMROAD_PRODUCT_* holds) with
    a product_id fallback, since either may show up depending on the
    Gumroad API response shape for a given field."""
    if product_permalink and product_permalink in _PRODUCT_TO_TIER:
        return _PRODUCT_TO_TIER[product_permalink]
    if product_id and product_id in _PRODUCT_TO_TIER:
        return _PRODUCT_TO_TIER[product_id]
    return None


def fetch_verified_sale(sale_id: str) -> dict | None:
    """
    The actual trust boundary for the Gumroad webhook: re-fetch the sale
    from Gumroad's authenticated API using our own access token, rather
    than trusting whatever the ping payload claims. Returns the verified
    sale dict, or None if it doesn't exist / isn't ours / the call fails.
    """
    if not GUMROAD_ACCESS_TOKEN:
        logger.error("GUMROAD_ACCESS_TOKEN not configured — cannot verify webhook, refusing to trust it blindly.")
        return None

    try:
        resp = requests.get(
            f"{GUMROAD_API_BASE}/sales/{sale_id}",
            params={"access_token": GUMROAD_ACCESS_TOKEN},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning(f"Gumroad sale verification failed for sale_id={sale_id}: HTTP {resp.status_code}")
            return None
        data = resp.json()
        if not data.get("success"):
            logger.warning(f"Gumroad sale verification returned success=false for sale_id={sale_id}")
            return None
        return data.get("purchase") or data.get("sale") or data
    except requests.RequestException as e:
        logger.error(f"Gumroad sale verification request failed for sale_id={sale_id}: {e}")
        return None


def fetch_verified_subscription_sale(subscription_id: str) -> dict | None:
    """
    Same trust boundary as fetch_verified_sale(), for pings that only carry
    a subscription_id (cancellation/subscription_ended/subscription_restarted
    don't come with a fresh sale_id) — used to re-derive which product/tier
    a subscription belongs to, e.g. on subscription_restarted.
    """
    if not GUMROAD_ACCESS_TOKEN:
        logger.error("GUMROAD_ACCESS_TOKEN not configured — cannot verify webhook, refusing to trust it blindly.")
        return None

    try:
        resp = requests.get(
            f"{GUMROAD_API_BASE}/sales",
            params={"access_token": GUMROAD_ACCESS_TOKEN, "subscription_id": subscription_id},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning(f"Gumroad subscription lookup failed for subscription_id={subscription_id}: HTTP {resp.status_code}")
            return None
        data = resp.json()
        sales = data.get("sales") or []
        return sales[0] if sales else None
    except requests.RequestException as e:
        logger.error(f"Gumroad subscription lookup request failed for subscription_id={subscription_id}: {e}")
        return None
