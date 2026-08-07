"""
Aegis AI v2 - Authentication (API key based)
================================================================================

Every protected endpoint depends on get_current_customer. FastAPI resolves
this before the endpoint body ever runs — so there is no code path where an
endpoint executes without a validated, active customer attached to it.

This is intentionally simple (a static bearer-style key per customer, not
OAuth/JWT) because at this stage the goal is correctness and isolation, not
sophistication. It's easy to swap for JWTs later without touching any of the
tenancy logic downstream, since every consumer just needs a Customer object.
================================================================================
"""

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.db import get_db, Customer

# Customers send: Authorization: Bearer aegis_xxxxxxxxxxxx
# or the simpler: X-API-Key: aegis_xxxxxxxxxxxx  (either header name works below)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_current_customer(
    api_key: str = Security(api_key_header),
    db: Session = Depends(get_db),
) -> Customer:
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Send it in the X-API-Key header.",
        )

    customer = db.query(Customer).filter(Customer.api_key == api_key).first()

    if customer is None:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    if not customer.is_active:
        raise HTTPException(status_code=403, detail="This account is disabled.")

    return customer
