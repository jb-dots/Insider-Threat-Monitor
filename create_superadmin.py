"""CLI utility to create or update the system super-admin account from environment variables.

This script is run once from the terminal. No web page can create or elevate a super-admin.
"""

import os
import sys
import uuid
from datetime import datetime

from db import User, get_session, hash_password, init_db


def create_or_update_superadmin():
    email = os.environ.get("SUPERADMIN_EMAIL")
    password = os.environ.get("SUPERADMIN_PASSWORD")
    name = os.environ.get("SUPERADMIN_NAME", "Platform Super Admin")

    if not email or not password:
        print("=" * 70)
        print("ERROR: SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD environment variables are required.")
        print("=" * 70)
        print("Usage Example (PowerShell):")
        print("  $env:SUPERADMIN_EMAIL = 'admin@yourdomain.com'")
        print("  $env:SUPERADMIN_PASSWORD = '<your-secure-password>'")
        print("  $env:SUPERADMIN_NAME = 'Platform Super Admin'  # Optional")
        print("  .\\venv\\Scripts\\python.exe create_superadmin.py")
        sys.exit(1)

    clean_email = email.strip().lower()
    clean_name = name.strip()

    if len(password) < 8:
        print("ERROR: SUPERADMIN_PASSWORD must contain at least 8 characters.")
        sys.exit(1)

    init_db()

    with get_session() as session:
        user = session.query(User).filter_by(email=clean_email).first()
        hashed = hash_password(password)

        if user:
            user.full_name = clean_name
            user.password_hash = hashed
            user.is_super_admin = True
            user.status = "active"
            session.commit()
            print("=" * 70)
            print(f"SUCCESS: Super-admin account '{clean_email}' updated successfully.")
            print(f"  User ID:        {user.user_id}")
            print(f"  Full Name:      {user.full_name}")
            print(f"  Account Status: {user.status}")
            print(f"  Super-Admin:    {user.is_super_admin}")
            print("=" * 70)
        else:
            user_id = f"usr_{uuid.uuid4().hex[:8]}"
            new_user = User(
                user_id=user_id,
                email=clean_email,
                password_hash=hashed,
                full_name=clean_name,
                status="active",
                is_super_admin=True,
                created_at=datetime.utcnow(),
            )
            session.add(new_user)
            session.commit()
            print("=" * 70)
            print(f"SUCCESS: Super-admin account '{clean_email}' created successfully.")
            print(f"  User ID:        {user_id}")
            print(f"  Full Name:      {clean_name}")
            print(f"  Account Status: active")
            print(f"  Super-Admin:    True")
            print("=" * 70)


if __name__ == "__main__":
    create_or_update_superadmin()

