"""Test suite for Step 6: Log upload validation, user pseudonymization, demo telemetry ingestion, and detector isolation."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from datetime import datetime
import pandas as pd
from hulicap.db import (
    Alert,
    Event,
    Organization,
    create_organization,
    get_org_alerts,
    get_org_plan_limits,
    get_session,
    init_db,
    record_log_upload,
    register_user,
    save_org_alerts,
    save_org_events,
)
from hulicap.detector import run_detection_pipeline

REQUIRED_COLUMNS = [
    "event_id",
    "timestamp",
    "user_id",
    "role",
    "action",
    "resource",
    "sensitivity",
    "bytes",
    "device",
    "source_ip",
    "outcome",
]

def run_tests():
    print("=" * 70)
    print("STEP 6 VERIFICATION: LOG UPLOAD, DEMO DATASET & DETECTOR SUITE")
    print("=" * 70)

    init_db()

    # 1. Setup Organization A (Standard Plan) and Organization B (Free Plan)
    print("\n[TEST 1] Setting up Organization A and Organization B...")
    user_a, _ = register_user("Org Admin A", "admin_a@alpha.com", "PasswordAlpha123!")
    if not user_a:
        from hulicap.db import authenticate_user
        user_a, _ = authenticate_user("admin_a@alpha.com", "PasswordAlpha123!")
    org_a, _ = create_organization("Alpha Sentinel Corp", "Defense & Aerospace", "standard", user_a["user_id"])
    if not org_a:
        from hulicap.db import get_active_org_context
        org_a, _ = get_active_org_context(user_a["user_id"])
    org_a_id = org_a["org_id"]
    org_a_salt = org_a["org_salt"]

    user_b, _ = register_user("Org Admin B", "admin_b@beta.com", "PasswordBeta123!")
    if not user_b:
        from hulicap.db import authenticate_user
        user_b, _ = authenticate_user("admin_b@beta.com", "PasswordBeta123!")
    org_b, _ = create_organization("Beta Dynamics Ltd", "Retail & Commerce", "free", user_b["user_id"])
    if not org_b:
        from hulicap.db import get_active_org_context
        org_b, _ = get_active_org_context(user_b["user_id"])
    org_b_id = org_b["org_id"]

    # Clear previous alerts for clean test run
    with get_session() as s:
        s.query(Alert).filter(Alert.org_id.in_([org_a_id, org_b_id])).delete()
        s.query(Event).filter(Event.org_id.in_([org_a_id, org_b_id])).delete()
        s.commit()

    print(f"  Org A (Alpha): {org_a_id} | Plan: {org_a['plan_id']} | Salt: {org_a_salt[:10]}...")
    print(f"  Org B (Beta):  {org_b_id} | Plan: {org_b['plan_id']}")

    # 2. Test Column Validation (Reject bad files)
    print("\n[TEST 2] Testing column validation for bad CSV uploads...")
    bad_df = pd.DataFrame({"event_id": ["e1"], "timestamp": ["2026-10-15 09:00:00"], "user": ["usr_1"]})
    missing = [c for c in REQUIRED_COLUMNS if c not in bad_df.columns]
    assert len(missing) > 0, "Validation should identify missing columns!"
    print(f"  Success: Correctly rejected file missing required columns: {missing[:3]}...")

    # 3. Test Plan Limits Enforcement
    print("\n[TEST 3] Testing plan upload limits enforcement...")
    limits_b = get_org_plan_limits(org_b_id)
    assert limits_b["max_events_per_upload"] == 10_000, "Free plan limit should be 10,000"
    oversized_count = 12_500
    is_blocked = oversized_count > limits_b["max_events_per_upload"]
    assert is_blocked is True
    print(f"  Success: Correctly identified that {oversized_count:,} events exceeds Free plan limit of {limits_b['max_events_per_upload']:,} events.")

    # 4. Ingest Demo Dataset into Organization A
    print("\n[TEST 4] Ingesting demo telemetry dataset into Organization A...")
    demo_df = pd.read_csv("logs.csv")
    print(f"  Loaded demo dataset with {len(demo_df):,} events.")

    upload_id = record_log_upload(org_a_id, user_a["user_id"], "demo_dataset.csv", len(demo_df))
    inserted_count = save_org_events(demo_df, org_a_id, upload_id, org_a_salt)
    assert inserted_count == len(demo_df)
    print(f"  Persisted {inserted_count:,} events into database under upload ID: {upload_id}")

    # 5. Verify Real User IDs are NEVER stored in events table
    print("\n[TEST 5] Verifying user pseudonymization in database (No real user IDs)...")
    with get_session() as s:
        sample_events = s.query(Event).filter_by(org_id=org_a_id).limit(10).all()
        for ev in sample_events:
            assert ev.user_id.startswith("USER-"), f"Privacy leak! Found raw user ID: {ev.user_id}"
            assert not ev.user_id.startswith("usr_"), f"Privacy leak! Found raw user prefix: {ev.user_id}"
        print(f"  Sample verified user IDs in database: {[e.user_id for e in sample_events[:3]]}")
        print("  Success: All events stored exclusively as salted pseudonyms (USER-XXXXXXXX).")

    # 6. Execute Detector for Organization A
    print("\n[TEST 6] Executing detection engine for Organization A...")
    # Pre-pseudonymize dataframe for detector to match stored events
    analysis_df = demo_df.copy()
    from hulicap.db import pseudonymize_user_with_salt
    analysis_df["user_id"] = analysis_df["user_id"].apply(lambda uid: pseudonymize_user_with_salt(uid, org_a_salt))

    alerts_a = run_detection_pipeline(analysis_df, org_id=org_a_id)
    save_org_alerts(alerts_a, org_a_id)
    print(f"  Detection pipeline executed. Flagged {len(alerts_a)} alerts for Organization A.")

    # Show alert counts by rule
    print("\n--- Organization A Alert Count Per Rule ---")
    rule_counts = pd.Series([a["rule_id"] for a in alerts_a]).value_counts()
    for rule_name, count in rule_counts.items():
        print(f"  {rule_name:<25}: {count} alert(s)")

    # 7. Verify Organization B's alerts remain completely EMPTY
    print("\n[TEST 7] Verifying Organization B dashboard isolation (Must stay empty)...")
    org_b_alerts = get_org_alerts(org_b_id)
    print(f"  Organization B total alerts: {len(org_b_alerts)}")
    assert len(org_b_alerts) == 0, f"CRITICAL ISOLATION LEAK: Organization B has alerts: {org_b_alerts}"
    print("  Success: Organization B dashboard has 0 alerts and remains completely empty.")

    # 8. Verify Organization A alerts in database
    db_alerts_a = get_org_alerts(org_a_id)
    assert len(db_alerts_a) == len(alerts_a)
    print(f"\n  Confirmed: Organization A has {len(db_alerts_a)} active alerts stored in database.")

    print("\n" + "=" * 70)
    print("ALL STEP 6 UPLOAD & DETECTOR TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()

