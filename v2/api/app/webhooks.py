"""
Clerk webhook handler — automatically provisions a real Aegis customer
account the moment someone signs up on the frontend, and writes their
generated API key back into Clerk's private user metadata so the
frontend can look it up server-side without ever exposing it to the
browser.
"""

import json
import logging
import os
from datetime import datetime

import requests
from fastapi import APIRouter, Request, HTTPException, Header
from svix.webhooks import Webhook, WebhookVerificationError

from app.db import SessionLocal, Customer
from app.billing import verify_webhook_signature, tier_for_variant_id, next_billing_period, TIER_LIMITS

# Subscription statuses that mean "not a paying customer right now" — any
# of these on a subscription.updated event downgrades to free immediately.
# This is a deliberate simplification: it doesn't honor a paid-until-
# period-end grace window on cancellation, it downgrades right away.
_INACTIVE_STATUSES = {"cancelled", "expired", "unpaid", "paused"}

router = APIRouter()
logger = logging.getLogger("aegis")

CLERK_WEBHOOK_SECRET = os.getenv("CLERK_WEBHOOK_SECRET")
CLERK_SECRET_KEY = os.getenv("CLERK_SECRET_KEY")


@router.post("/webhooks/clerk")
async def clerk_webhook(
    request: Request,
    svix_id: str = Header(None, alias="svix-id"),
    svix_timestamp: str = Header(None, alias="svix-timestamp"),
    svix_signature: str = Header(None, alias="svix-signature"),
):
    if not CLERK_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="CLERK_WEBHOOK_SECRET not configured")

    payload = await request.body()

    try:
        wh = Webhook(CLERK_WEBHOOK_SECRET)
        event = wh.verify(
            payload,
            {
                "svix-id": svix_id,
                "svix-timestamp": svix_timestamp,
                "svix-signature": svix_signature,
            },
        )
    except WebhookVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    if event.get("type") != "user.created":
        return {"status": "ignored", "type": event.get("type")}

    data = event["data"]
    clerk_user_id = data["id"]
    email = data["email_addresses"][0]["email_address"]
    first_name = data.get("first_name") or ""
    last_name = data.get("last_name") or ""
    name = f"{first_name} {last_name}".strip() or email

    db = SessionLocal()
    try:
        existing = db.query(Customer).filter(Customer.email == email).first()
        customer = existing
        if not customer:
            customer = Customer(name=name, email=email)
            db.add(customer)
            db.commit()
            db.refresh(customer)

        resp = requests.patch(
            f"https://api.clerk.com/v1/users/{clerk_user_id}/metadata",
            headers={
                "Authorization": f"Bearer {CLERK_SECRET_KEY}",
                "Content-Type": "application/json",
            },
            json={"private_metadata": {"aegis_api_key": customer.api_key}},
            timeout=10,
        )
        resp.raise_for_status()

        return {"status": "customer_provisioned", "customer_id": customer.id}
    finally:
        db.close()


# ==============================================================================
# LEMON SQUEEZY WEBHOOK — keeps Customer.tier in sync with whatever's
# actually happening on the subscription, including changes made through
# Lemon Squeezy's own customer portal (upgrade/downgrade/cancel) that never
# touch our API at all.
# ==============================================================================

@router.post("/webhooks/lemonsqueezy")
async def lemonsqueezy_webhook(
    request: Request,
    x_signature: str = Header(None, alias="X-Signature"),
):
    payload = await request.body()

    if not verify_webhook_signature(payload, x_signature):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    event = json.loads(payload)
    event_type = (event.get("meta") or {}).get("event_name")
    custom_data = ((event.get("meta") or {}).get("custom_data")) or {}
    data = (event.get("data") or {}).get("attributes") or {}
    ls_subscription_id = (event.get("data") or {}).get("id")

    db = SessionLocal()
    try:
        if event_type == "subscription_created":
            customer_id = custom_data.get("aegis_customer_id")
            tier = custom_data.get("tier")
            ls_customer_id = data.get("customer_id")
            variant_id = data.get("variant_id")

            customer = db.query(Customer).filter(Customer.id == customer_id).first()
            if not customer:
                logger.warning(f"Lemon Squeezy subscription_created for unknown customer_id={customer_id}")
                return {"status": "ignored", "reason": "unknown customer"}

            if tier not in TIER_LIMITS:
                # Fall back to resolving the tier from the variant, in case
                # custom_data ever gets dropped by an intermediate proxy.
                tier = tier_for_variant_id(variant_id)
            if tier not in TIER_LIMITS:
                logger.warning(f"Lemon Squeezy subscription_created with unrecognized tier (variant={variant_id})")
                return {"status": "ignored", "reason": "unrecognized tier"}

            customer.tier = tier
            customer.ls_customer_id = str(ls_customer_id) if ls_customer_id is not None else None
            customer.ls_subscription_id = str(ls_subscription_id) if ls_subscription_id is not None else None
            # Fresh paid period starts now, regardless of where they were
            # in their free-tier usage window.
            customer.usage_count = 0
            customer.usage_reset_date = next_billing_period(datetime.utcnow())
            db.add(customer)
            db.commit()
            logger.info(f"Customer {customer.id} upgraded to '{tier}' via Lemon Squeezy checkout")

        elif event_type in ("subscription_updated", "subscription_cancelled", "subscription_expired"):
            customer = (
                db.query(Customer)
                .filter(Customer.ls_subscription_id == str(ls_subscription_id))
                .first()
            )
            if not customer:
                logger.warning(f"Lemon Squeezy {event_type} for unknown ls_subscription_id={ls_subscription_id}")
                return {"status": "ignored", "reason": "unknown customer"}

            status = data.get("status")
            if event_type != "subscription_updated" or status in _INACTIVE_STATUSES:
                customer.tier = "free"
            else:
                variant_id = data.get("variant_id")
                new_tier = tier_for_variant_id(variant_id) if variant_id else None
                if new_tier:
                    customer.tier = new_tier
            db.add(customer)
            db.commit()
            logger.info(f"Customer {customer.id} subscription {event_type} -> tier={customer.tier} (status={status})")

        else:
            return {"status": "ignored", "type": event_type}

        return {"status": "processed", "type": event_type}
    finally:
        db.close()