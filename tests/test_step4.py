"""Test suite for Step 4: Subscription plans and community guidelines acceptance."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from pathlib import Path
from db import (
    GuidelineAcceptance,
    get_available_plans,
    get_session,
    has_accepted_guidelines,
    init_db,
    record_guideline_acceptance,
    register_user,
)

def run_tests():
    print("=" * 65)
    print("STEP 4 VERIFICATION: SUBSCRIPTION PLANS & GUIDELINES TEST SUITE")
    print("=" * 65)

    init_db()

    # 1. Verify guidelines.md exists and contains required rules
    print("\n[TEST 1] Verifying guidelines.md contents...")
    doc_path = Path("guidelines.md")
    assert doc_path.exists(), "guidelines.md not found!"
    doc_text = doc_path.read_text(encoding="utf-8").lower()

    required_phrases = [
        "synthetic or approved",
        "personal data",
        "file contents",
        "other organization",
        "suspended",
    ]
    for phrase in required_phrases:
        assert phrase in doc_text, f"Missing required guideline phrase: '{phrase}'"
        print(f"  Verified requirement: contains '{phrase}'")

    # 2. Verify plans from database
    print("\n[TEST 2] Verifying simulated plans and limits from database...")
    plans = get_available_plans()
    assert len(plans) >= 2, f"Expected at least 2 plans, found: {len(plans)}"
    for p in plans:
        print(f"  Plan: {p['name']:<10} | Max Events/Upload: {p['max_events_per_upload']:,} | Max Staff: {p['max_staff']}")

    # 3. Register a fresh test user
    print("\n[TEST 3] Creating new user for onboarding flow...")
    user, err = register_user("David Compliance", "david@enterprise.com", "Password456!")
    if err and "already exists" in err:
        from db import authenticate_user
        user, _ = authenticate_user("david@enterprise.com", "Password456!")
    assert user is not None
    user_id = user["user_id"]
    print(f"  User created: {user['full_name']} ({user['email']}) -> ID: {user_id}")

    # 4. Check initial acceptance status (must be False)
    print("\n[TEST 4] Checking initial guidelines acceptance status...")
    with get_session() as s:
        # Clean up any existing acceptance for this user for pristine test
        s.query(GuidelineAcceptance).filter_by(user_id=user_id).delete()
        s.commit()

    is_accepted_initial = has_accepted_guidelines(user_id, version="v1.0")
    assert is_accepted_initial is False, "Initial status must be False before user accepts!"
    print(f"  has_accepted_guidelines() returned: {is_accepted_initial} (Access to dashboard is BLOCKED)")

    # 5. Record Guideline Acceptance (Simulating clicking Continue with checkbox enabled)
    print("\n[TEST 5] Simulating user checking box and submitting acceptance...")
    record_guideline_acceptance(user_id, version="v1.0")

    is_accepted_post = has_accepted_guidelines(user_id, version="v1.0")
    assert is_accepted_post is True, "Status must be True after recording acceptance!"
    print(f"  has_accepted_guidelines() returned: {is_accepted_post} (Access to dashboard GRANTED)")

    # 6. Verify row in database
    print("\n[TEST 6] Inspecting guideline_acceptances table row...")
    with get_session() as s:
        record = s.query(GuidelineAcceptance).filter_by(user_id=user_id, version="v1.0").first()
        assert record is not None
        print(f"  Database Record ID: {record.id}")
        print(f"  User ID:            {record.user_id}")
        print(f"  Version:            {record.version}")
        print(f"  Accepted At (UTC):  {record.accepted_at}")

    print("\n" + "=" * 65)
    print("ALL STEP 4 ONBOARDING & GUIDELINE CHECKS PASSED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()

