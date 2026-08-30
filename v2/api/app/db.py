"""
Aegis AI v2 - Database layer (multi-tenancy foundation)
================================================================================

Every table below carries a customer_id. There is no query anywhere in this
app that is allowed to read/write a row without going through a customer_id
filter — that's the entire mechanism that keeps tenants isolated on shared
infrastructure.

Local dev:   uses SQLite (aegis.db in the working directory) with zero setup.
Production:  set DATABASE_URL to a Postgres connection string, e.g.
             postgresql://user:password@host:5432/aegis
             and this switches over automatically — no code change needed.
================================================================================
"""

import os
import secrets
import uuid
from datetime import datetime

from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean,
    DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aegis.db")

# SQLite needs this connect_arg for use with FastAPI's threaded workers;
# Postgres doesn't, so only add it conditionally.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def generate_api_key() -> str:
    """Generate a long, random, unguessable API key."""
    return "aegis_" + secrets.token_urlsafe(32)


def generate_id() -> str:
    return str(uuid.uuid4())


# ==============================================================================
# MODELS
# ==============================================================================

class Customer(Base):
    """
    One row per paying tenant. This is the root of the tenancy tree —
    every other table hangs off customer_id.
    """
    __tablename__ = "customers"

    id = Column(String, primary_key=True, default=generate_id)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    api_key = Column(String, nullable=False, unique=True, index=True, default=generate_api_key)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # --- Billing / tier enforcement -------------------------------------
    # tier is the source of truth for what a customer can do; it's kept in
    # sync with Lemon Squeezy via the /webhooks/lemonsqueezy handler, not
    # read from the gateway on every request.
    tier = Column(String, nullable=False, default="free")
    usage_count = Column(Integer, nullable=False, default=0)
    # First "period end" a brand-new customer sees; the tier-check
    # dependency lazily rolls this forward (and zeroes usage_count) once
    # `now >= usage_reset_date`, so no cron job is required.
    usage_reset_date = Column(DateTime, default=datetime.utcnow)
    # Lemon Squeezy (merchant of record — see app/billing.py for why).
    ls_customer_id = Column(String, nullable=True, index=True)
    ls_subscription_id = Column(String, nullable=True)

    # --- Alerting (per-customer opt-in, set from /account) ---------------
    slack_webhook_url = Column(String, nullable=True)
    alert_email = Column(String, nullable=True)

    uploads = relationship("Upload", back_populates="customer")
    detections = relationship("Detection", back_populates="customer")


class Upload(Base):
    """One row per file a customer submitted to /analyze."""
    __tablename__ = "uploads"

    id = Column(String, primary_key=True, default=generate_id)
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)

    filename = Column(String, nullable=False)
    detected_format = Column(String, nullable=True)
    total_flows = Column(Integer, default=0)
    total_attacks = Column(Integer, default=0)
    status = Column(String, default="analysis_complete")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    customer = relationship("Customer", back_populates="uploads")
    detections = relationship("Detection", back_populates="upload")


class Detection(Base):
    """
    One row per attack flow detected within an upload.
    customer_id is denormalized here (in addition to living on Upload)
    so every detection query can filter directly without a join —
    that's a deliberate belt-and-suspenders against ever accidentally
    leaking cross-tenant rows.
    """
    __tablename__ = "detections"

    id = Column(String, primary_key=True, default=generate_id)
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False, index=True)

    row_index = Column(Integer, nullable=False)
    attack_type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    severity = Column(String, nullable=True)
    narrative = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    raw_report = Column(JSON, nullable=True)  # full agent report, for audit/debug
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    customer = relationship("Customer", back_populates="detections")
    upload = relationship("Upload", back_populates="detections")


def init_db():
    """Create all tables. Safe to call repeatedly — no-ops if they exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency — yields a session, always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
