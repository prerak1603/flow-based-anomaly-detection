"""
Aegis AI v2 - Lightweight schema migration
================================================================================

There's no Alembic in this project — `db.py` only ever did
`Base.metadata.create_all`, which creates missing *tables* but never adds
missing *columns* to a table that already exists (which is exactly what
happened to `customers` when the billing/alerting columns were added).

This module is a minimal, idempotent stand-in: for each table, look at what
columns actually exist (via SQLAlchemy's inspector, which works the same way
against Neon Postgres in prod and SQLite in local dev) and `ALTER TABLE ...
ADD COLUMN` whatever is missing from the model. Safe to call on every
startup — a column that's already there is simply skipped.

If this ever needs to do more than add nullable columns with simple
defaults (renames, backfills, drops), it's time to bring in Alembic instead
of growing this file further.
================================================================================
"""

import logging

from sqlalchemy import inspect, text

from app.db import engine, Base, Customer  # noqa: F401 (import registers models)

logger = logging.getLogger("aegis")

# Column -> SQL type used only for ALTER TABLE ADD COLUMN. Keep these in
# sync with the nullable, no-server-default columns added to Customer for
# billing/alerting — every one of them is safe to add as NULL-able on an
# existing table with existing rows.
_CUSTOMER_COLUMNS_SQL = {
    "tier": "VARCHAR DEFAULT 'free'",
    "usage_count": "INTEGER DEFAULT 0",
    "usage_reset_date": "TIMESTAMP",
    "ls_customer_id": "VARCHAR",
    "ls_subscription_id": "VARCHAR",
    "slack_webhook_url": "VARCHAR",
    "alert_email": "VARCHAR",
}


def run_migrations():
    """Create any missing tables, then add any missing columns."""
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    existing_columns = {col["name"] for col in inspector.get_columns("customers")}

    with engine.begin() as conn:
        for column, sql_type in _CUSTOMER_COLUMNS_SQL.items():
            if column in existing_columns:
                continue
            logger.info(f"Migration: adding customers.{column} ({sql_type})")
            conn.execute(text(f"ALTER TABLE customers ADD COLUMN {column} {sql_type}"))

    logger.info("Schema migrations up to date.")
