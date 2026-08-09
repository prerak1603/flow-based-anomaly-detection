"""
Clerk webhook handler — automatically provisions a real Aegis customer
account the moment someone signs up on the frontend, and writes their
generated API key back into Clerk's private user metadata so the
frontend can look it up server-side without ever exposing it to the
browser.
"""

import os
import requests
from fastapi import APIRouter, Request, HTTPException, Header
from svix.webhooks import Webhook, WebhookVerificationError

from app.db import SessionLocal, Customer

router = APIRouter()

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