"""
Create a new customer (tenant) and print their API key.

Usage:
    python scripts/create_customer.py "Acme Corp" "security@acme.com"

Run this once per new customer you sign up. The printed API key is shown
ONLY ONCE here — store it somewhere safe and send it to the customer;
the database only ever stores it once, there's no "forgot my key" recovery
by design (you'd revoke and issue a new one instead).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.db import SessionLocal, Customer, init_db


def create_customer(name: str, email: str):
    init_db()
    db = SessionLocal()
    try:
        existing = db.query(Customer).filter(Customer.email == email).first()
        if existing:
            print(f"Customer with email {email} already exists.")
            print(f"  id:      {existing.id}")
            print(f"  api_key: {existing.api_key}")
            return

        customer = Customer(name=name, email=email)
        db.add(customer)
        db.commit()
        db.refresh(customer)

        print("Customer created.")
        print(f"  id:      {customer.id}")
        print(f"  name:    {customer.name}")
        print(f"  email:   {customer.email}")
        print(f"  api_key: {customer.api_key}")
        print()
        print("Give the customer this header to use in every request:")
        print(f'  X-API-Key: {customer.api_key}')
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/create_customer.py \"Customer Name\" \"email@example.com\"")
        sys.exit(1)

    create_customer(sys.argv[1], sys.argv[2])
