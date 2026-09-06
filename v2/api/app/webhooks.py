"""
Clerk webhook handler — automatically provisions a real Aegis customer
account the moment someone signs up on the frontend, and writes their
generated API key back into Clerk's private user metadata so the
frontend can look it up server-side without ever exposing it to the
browser.
"""

import hashlib
import hmac
import logging
import os
from datetime import datetime
from urllib.parse import parse_qsl

import requests
from fastapi import APIRouter, Request, HTTPException, Header
from svix.webhooks import Webhook, WebhookVerificationError

from app.db import SessionLocal, Customer
from app.billing import (
    GUMROAD_WEBHOOK_SECRET,
    tier_for_product,
    fetch_verified_sale,
    fetch_verified_subscription_sale,
    next_billing_period,
)

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
# GUMROAD WEBHOOK ("ping") — keeps Customer.tier in sync with whatever's
# actually happening on the subscription (new sale, cancellation, expiry,
# restart). Gumroad's ping signing isn't documented with the rigor Stripe/
# Lemon Squeezy's is, so this does NOT trust the ping payload for anything
# that changes a tier — every ping is a trigger to re-fetch the sale from
# Gumroad's authenticated API (see billing.fetch_verified_sale /
# fetch_verified_subscription_sale) and only the verified response is acted
# on. The `event` query param (not a body field) says which of Gumroad's
# resource_subscriptions fired — each must be registered against this same
# URL with a distinct `?event=...` suffix (see the setup notes this was
# built with) since Gumroad's ping body doesn't reliably self-identify.
# ==============================================================================

_GUMROAD_EVENTS = {"sale", "cancellation", "subscription_ended", "subscription_restarted"}


@router.post("/webhooks/gumroad")
async def gumroad_webhook(request: Request, event: str = None):
    if event not in _GUMROAD_EVENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Missing/unknown ?event= query param. Expected one of {sorted(_GUMROAD_EVENTS)} "
                   f"— each Gumroad resource_subscription must post to this URL with its own ?event=.",
        )

    raw_body = await request.body()

    # Best-effort signature check — NOT the trust boundary (see docstring
    # above and app/billing.py). Only enforced when a secret is actually
    # configured; a mismatch when it IS configured is still a hard reject.
    if GUMROAD_WEBHOOK_SECRET:
        signature = request.headers.get("x-gumroad-signature")
        if signature:
            expected = hmac.new(GUMROAD_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise HTTPException(status_code=400, detail="Invalid webhook signature")

    form = dict(parse_qsl(raw_body.decode("utf-8", errors="replace")))
    sale_id = form.get("sale_id") or form.get("id")
    subscription_id = form.get("subscription_id")

    db = SessionLocal()
    try:
        if event == "sale":
            if not sale_id:
                return {"status": "ignored", "reason": "no sale_id in ping"}

            verified = fetch_verified_sale(sale_id)
            if not verified:
                logger.warning(f"Gumroad sale ping for sale_id={sale_id} could not be verified — ignoring")
                return {"status": "ignored", "reason": "could not verify sale"}

            if verified.get("refunded") or verified.get("chargebacked"):
                return {"status": "ignored", "reason": "refunded/chargebacked sale"}

            tier = tier_for_product(verified.get("product_id"), verified.get("product_permalink"))
            if not tier:
                logger.warning(
                    f"Gumroad verified sale {sale_id} for unrecognized product "
                    f"(id={verified.get('product_id')}, permalink={verified.get('product_permalink')})"
                )
                return {"status": "ignored", "reason": "unrecognized product"}

            email = verified.get("email")
            customer = db.query(Customer).filter(Customer.email == email).first() if email else None
            if not customer:
                logger.warning(f"Gumroad verified sale {sale_id} for unknown customer email={email}")
                return {"status": "ignored", "reason": "unknown customer"}

            customer.tier = tier
            verified_sub_id = verified.get("subscription_id")
            customer.gumroad_subscription_id = str(verified_sub_id) if verified_sub_id else str(sale_id)
            # Fresh paid period starts now, regardless of where they were
            # in their free-tier usage window.
            customer.usage_count = 0
            customer.usage_reset_date = next_billing_period(datetime.utcnow())
            db.add(customer)
            db.commit()
            logger.info(f"Customer {customer.id} upgraded to '{tier}' via verified Gumroad sale {sale_id}")

        elif event in ("cancellation", "subscription_ended"):
            if not subscription_id:
                return {"status": "ignored", "reason": "no subscription_id in ping"}

            customer = (
                db.query(Customer)
                .filter(Customer.gumroad_subscription_id == str(subscription_id))
                .first()
            )
            if not customer:
                logger.warning(f"Gumroad {event} for unknown subscription_id={subscription_id}")
                return {"status": "ignored", "reason": "unknown customer"}

            # Deliberate simplification (same as this project's earlier
            # gateway attempts): downgrades immediately rather than honoring
            # a paid-until-period-end grace window.
            customer.tier = "free"
            db.add(customer)
            db.commit()
            logger.info(f"Customer {customer.id} subscription {event} -> downgraded to free")

        elif event == "subscription_restarted":
            if not subscription_id:
                return {"status": "ignored", "reason": "no subscription_id in ping"}

            customer = (
                db.query(Customer)
                .filter(Customer.gumroad_subscription_id == str(subscription_id))
                .first()
            )
            if not customer:
                logger.warning(f"Gumroad subscription_restarted for unknown subscription_id={subscription_id}")
                return {"status": "ignored", "reason": "unknown customer"}

            verified = fetch_verified_subscription_sale(subscription_id)
            tier = tier_for_product(
                verified.get("product_id") if verified else None,
                verified.get("product_permalink") if verified else None,
            )
            if not tier:
                logger.warning(f"Gumroad subscription_restarted for {subscription_id} — could not re-verify tier")
                return {"status": "ignored", "reason": "could not verify restarted subscription's product"}

            customer.tier = tier
            db.add(customer)
            db.commit()
            logger.info(f"Customer {customer.id} subscription restarted -> tier={tier}")

        return {"status": "processed", "event": event}
    finally:
        db.close()