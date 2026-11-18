"""Test suite for Step 5: Multi-tenant organization creation, data isolation, and suspension."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from datetime import datetime
from db import (
    Alert,
    Organization,
    create_organization,
    get_active_org_context,
    get_org_alert_by_id,
    get_org_alerts,
    get_session,
    init_db,
    register_user,
)

def run_tests():
    print("=" * 70)
    print("STEP 5 VERIFICATION: MULTI-TENANT ISOLATION & ACCESS CONTROL TEST SUITE")
    print("=" * 70)

    init_db()

    # 1. Create User A and Organization A (Acme Corp)
    print("\n[TEST 1] Creating User A & Organization A (Acme Corp)...")
    user_a, _ = register_user("Alice Admin", "alice_admin@acme.com", "PasswordAcme123!")
    if not user_a:
        from db import authenticate_user
        user_a, _ = authenticate_user("alice_admin@acme.com", "PasswordAcme123!")
    user_a_id = user_a["user_id"]

    org_a, err_a = create_organization("Acme Corp", "Financial Services", "standard", user_a_id)
    assert err_a is None, f"Failed to create Org A: {err_a}"
    assert org_a is not None
    org_a_id = org_a["org_id"]
    print(f"  Organization A Created: {org_a['name']} (ID: {org_a_id})")
    print(f"  Org A Random Salt:      {org_a['org_salt']}")
    print(f"  Creator Membership:     User {user_a_id} -> {org_a['role']}")

    # 2. Create User B and Organization B (Globex Industries)
    print("\n[TEST 2] Creating User B & Organization B (Globex Industries)...")
    user_b, _ = register_user("Bob Director", "bob_admin@globex.com", "PasswordGlobex123!")
    if not user_b:
        from db import authenticate_user
        user_b, _ = authenticate_user("bob_admin@globex.com", "PasswordGlobex123!")
    user_b_id = user_b["user_id"]

    org_b, err_b = create_organization("Globex Industries", "Technology & SaaS", "free", user_b_id)
    assert err_b is None, f"Failed to create Org B: {err_b}"
    assert org_b is not None
    org_b_id = org_b["org_id"]
    print(f"  Organization B Created: {org_b['name']} (ID: {org_b_id})")
    print(f"  Org B Random Salt:      {org_b['org_salt']}")
    print(f"  Creator Membership:     User {user_b_id} -> {org_b['role']}")

    # Verify salts are distinct random tokens
    assert org_a["org_salt"] != org_b["org_salt"], "Security violation: organization salts must be unique!"

    # 3. Add Alert 1 to Org A, and Alert 2 to Org B
    print("\n[TEST 3] Inserting test alerts into Organization A and Organization B...")
    with get_session() as s:
        # Clear existing test alerts if re-running
        s.query(Alert).filter(Alert.alert_id.in_(["alt_acme_001", "alt_globex_002"])).delete()
        s.commit()

        alert_a = Alert(
            alert_id="alt_acme_001",
            org_id=org_a_id,
            rule_id="bulk_access",
            severity="high",
            user_pseudonym="USER-ACME-99",
            event_ids="ev_acme_1,ev_acme_2",
            reason="Acme insider anomaly: Bulk transfer detected",
            status="new",
            created_at=datetime.utcnow(),
        )
        alert_b = Alert(
            alert_id="alt_globex_002",
            org_id=org_b_id,
            rule_id="atypical_download",
            severity="critical",
            user_pseudonym="USER-GLOBEX-44",
            event_ids="ev_globex_1",
            reason="Globex insider anomaly: Unauthorized cloud export",
            status="new",
            created_at=datetime.utcnow(),
        )
        s.add_all([alert_a, alert_b])
        s.commit()
    print("  Inserted 'alt_acme_001' into Acme Corp.")
    print("  Inserted 'alt_globex_002' into Globex Industries.")

    # 4. Strict Isolation Test: List Queries
    print("\n[TEST 4] Verifying list query isolation (get_org_alerts)...")
    acme_alerts = get_org_alerts(org_a_id)
    acme_alert_ids = [a["alert_id"] for a in acme_alerts]
    print(f"  Acme Corp query returned {len(acme_alerts)} alert(s): {acme_alert_ids}")
    assert "alt_acme_001" in acme_alert_ids, "Acme Corp must see its own alert!"
    assert "alt_globex_002" not in acme_alert_ids, "CRITICAL: Acme Corp can see Globex alert!"

    globex_alerts = get_org_alerts(org_b_id)
    globex_alert_ids = [a["alert_id"] for a in globex_alerts]
    print(f"  Globex Industries query returned {len(globex_alerts)} alert(s): {globex_alert_ids}")
    assert "alt_globex_002" in globex_alert_ids, "Globex must see its own alert!"
    assert "alt_acme_001" not in globex_alert_ids, "CRITICAL: Globex can see Acme alert!"
    print("  Success: Organization A cannot list Organization B's alerts.")

    # 5. Strict Isolation Test: Direct ID Queries
    print("\n[TEST 5] Verifying single alert direct ID isolation (get_org_alert_by_id)...")
    # Acme tries to read Globex alert by ID
    leak_attempt = get_org_alert_by_id("alt_globex_002", org_id=org_a_id)
    assert leak_attempt is None, f"CRITICAL LEAK: Acme accessed Globex alert: {leak_attempt}"
    print("  Success: User in Organization A querying Globex Alert ID returns None.")

    # Globex tries to read Acme alert by ID
    leak_attempt2 = get_org_alert_by_id("alt_acme_001", org_id=org_b_id)
    assert leak_attempt2 is None, f"CRITICAL LEAK: Globex accessed Acme alert: {leak_attempt2}"
    print("  Success: User in Organization B querying Acme Alert ID returns None.")

    # 6. Test Organization Suspension Enforcement
    print("\n[TEST 6] Testing suspended organization blocking via get_active_org_context...")
    with get_session() as s:
        org_record = s.query(Organization).filter_by(org_id=org_a_id).first()
        org_record.status = "suspended"
        s.commit()

    context, susp_err = get_active_org_context(user_a_id)
    expected_susp_msg = "This organization has been suspended. Access to its data and console is blocked."
    assert susp_err == expected_susp_msg, f"Expected '{expected_susp_msg}', got '{susp_err}'"
    print(f"  Success: Suspended organization correctly blocked with message:\n    '{susp_err}'")

    # Restore status to active
    with get_session() as s:
        org_record = s.query(Organization).filter_by(org_id=org_a_id).first()
        org_record.status = "active"
        s.commit()

    print("\n" + "=" * 70)
    print("ALL STEP 5 MULTI-TENANT ISOLATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()

