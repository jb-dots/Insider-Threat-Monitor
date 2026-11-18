"""Test script for Step 8: Staff management, one-time invite codes, plan limit enforcement, and isolation."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


import sys
import uuid

from db import (
    accept_invite_code,
    add_or_invite_staff,
    cancel_pending_invite,
    check_permission,
    create_organization,
    get_org_pending_invites,
    get_org_plan_limits,
    get_org_staff,
    init_db,
    register_user,
    remove_staff_member,
)


def run_tests():
    print("=" * 78)
    print("STEP 8 VERIFICATION: STAFF MANAGEMENT, ONE-TIME CODES & PLAN LIMITS")
    print("=" * 78)

    init_db()

    # Unique test IDs
    test_run = uuid.uuid4().hex[:6]
    admin_a_email = f"admin_{test_run}@org-alpha.com"
    existing_user_email = f"analyst_{test_run}@org-alpha.com"
    newbie_invite_email = f"newbie_{test_run}@org-alpha.com"
    overflow_user_email = f"overflow_{test_run}@org-alpha.com"

    # Other org admin
    admin_b_email = f"admin_{test_run}@org-beta.com"

    # [TEST 1] Setup Organization Alpha on Free Plan (max_staff = 3)
    print("\n[TEST 1] Setting up Organization Alpha on Free Plan (max_staff = 3)...")
    user_admin_a, _ = register_user("Alpha Admin", admin_a_email, "SecurePassword123!")
    org_a, err = create_organization("Alpha Cyber Defense", "Government / Defense", "free", user_admin_a["user_id"])
    assert err is None, f"Failed to create Org Alpha: {err}"
    org_a_id = org_a["org_id"]

    limits = get_org_plan_limits(org_a_id)
    print(f"  Org Alpha ID: {org_a_id} | Plan: {limits['name']} | Max Staff Seats: {limits['max_staff']}")

    staff_initial = get_org_staff(org_a_id, role="org_admin")
    assert len(staff_initial) == 1, f"Expected 1 initial creator staff member, got {len(staff_initial)}"
    print(f"  Initial Staff Count: {len(staff_initial)} (Creator: {staff_initial[0]['email']} as {staff_initial[0]['role']})")

    # [TEST 2] Add an existing user by email as 'analyst'
    print("\n[TEST 2] Adding an existing registered user by email as 'analyst'...")
    user_analyst, _ = register_user("Sam Analyst", existing_user_email, "AnalystPassword123!")

    res_add, err_add = add_or_invite_staff(
        org_id=org_a_id,
        email=existing_user_email,
        assign_role="analyst",
        admin_role="org_admin",
    )
    assert err_add is None, f"Failed to add existing user: {err_add}"
    assert res_add["type"] == "added", f"Expected type 'added', got {res_add['type']}"
    print(f"  Success: User '{existing_user_email}' directly attached to organization as '{res_add['role']}'.")

    staff_after_add = get_org_staff(org_a_id, role="org_admin")
    assert len(staff_after_add) == 2, f"Expected 2 staff members, got {len(staff_after_add)}"
    print(f"  Current Active Staff: {len(staff_after_add)} / {limits['max_staff']}")

    # [TEST 3] Invite a non-existent email as 'reviewer' (generates one-time code)
    print("\n[TEST 3] Inviting non-existing user email to generate one-time invite code...")
    res_inv, err_inv = add_or_invite_staff(
        org_id=org_a_id,
        email=newbie_invite_email,
        assign_role="reviewer",
        admin_role="org_admin",
    )
    assert err_inv is None, f"Failed to invite new email: {err_inv}"
    assert res_inv["type"] == "invited", f"Expected type 'invited', got {res_inv['type']}"
    invite_code = res_inv["code"]
    print(f"  Success: Generated one-time invite code: {invite_code} for '{res_inv['email']}' (Role: {res_inv['role']})")

    pending_invites = get_org_pending_invites(org_a_id, role="org_admin")
    assert len(pending_invites) == 1, f"Expected 1 pending invite, got {len(pending_invites)}"
    print(f"  Verified pending invite in database: Email='{pending_invites[0]['email']}', Code='{pending_invites[0]['code']}'")

    # [TEST 4] Enforce plan max_staff limit (3 seats total: 2 active + 1 pending)
    print("\n[TEST 4] Enforcing plan max_staff limit (Attempting to add 4th seat on Free Plan)...")
    res_overflow, err_overflow = add_or_invite_staff(
        org_id=org_a_id,
        email=overflow_user_email,
        assign_role="analyst",
        admin_role="org_admin",
    )
    assert res_overflow is None, "Plan limit violation: overflow addition should have been rejected!"
    assert "Plan limit reached" in err_overflow, f"Unexpected error message: {err_overflow}"
    print(f"  Success: Correctly blocked addition beyond plan limit of {limits['max_staff']}.")
    print(f"  System Message: {err_overflow}")

    # [TEST 5] Register new user with one-time invite code
    print("\n[TEST 5] Registering new user using one-time invite code...")
    user_newbie, _ = register_user("Taylor Reviewer", newbie_invite_email, "ReviewerPassword123!")
    accept_res, accept_err = accept_invite_code(
        code=invite_code,
        user_id=user_newbie["user_id"],
        user_email=newbie_invite_email,
    )
    assert accept_err is None, f"Failed to redeem invite code: {accept_err}"
    assert accept_res["org_id"] == org_a_id
    assert accept_res["role"] == "reviewer"
    print(f"  Success: User registered and redeemed code! Attached to Org '{org_a_id}' as '{accept_res['role']}'.")

    # Verify pending invite is now accepted / no longer pending
    pending_after_accept = get_org_pending_invites(org_a_id, role="org_admin")
    assert len(pending_after_accept) == 0, f"Expected 0 pending invites, got {len(pending_after_accept)}"
    print("  Verified: Pending invite marked as accepted and removed from pending queue.")

    staff_all_active = get_org_staff(org_a_id, role="org_admin")
    assert len(staff_all_active) == 3, f"Expected 3 active staff members, got {len(staff_all_active)}"
    print(f"  Active Staff count is now {len(staff_all_active)}: {[s['email'] for s in staff_all_active]}")

    # [TEST 6] Remove staff member from own organization only
    print("\n[TEST 6] Removing staff member from own organization...")
    # Admin tries to remove themselves (Must be blocked)
    ok_self, err_self = remove_staff_member(
        org_id=org_a_id,
        target_user_id=user_admin_a["user_id"],
        requesting_user_id=user_admin_a["user_id"],
        admin_role="org_admin",
    )
    assert not ok_self, "Admin should not be able to remove themselves!"
    print(f"  Self-removal check: Blocked as expected ({err_self})")

    # Setup Organization Beta with its own user
    user_admin_b, _ = register_user("Beta Admin", admin_b_email, "SecurePassword123!")
    org_b, _ = create_organization("Beta Technologies", "Retail", "free", user_admin_b["user_id"])
    org_b_id = org_b["org_id"]

    # Admin of Org A tries to remove Admin of Org B (Cross-tenant removal check)
    ok_cross, err_cross = remove_staff_member(
        org_id=org_a_id,
        target_user_id=user_admin_b["user_id"],
        requesting_user_id=user_admin_a["user_id"],
        admin_role="org_admin",
    )
    assert not ok_cross, "Cross-tenant staff removal must be blocked!"
    print(f"  Cross-tenant removal check: Blocked as expected ({err_cross})")

    # Admin of Org A removes the analyst from Org A
    ok_rem, err_rem = remove_staff_member(
        org_id=org_a_id,
        target_user_id=user_analyst["user_id"],
        requesting_user_id=user_admin_a["user_id"],
        admin_role="org_admin",
    )
    assert ok_rem, f"Failed to remove staff member: {err_rem}"
    print(f"  Success: Removed staff member '{existing_user_email}' from Org Alpha.")

    staff_after_remove = get_org_staff(org_a_id, role="org_admin")
    assert len(staff_after_remove) == 2, f"Expected 2 staff members after removal, got {len(staff_after_remove)}"
    print(f"  Active Staff count now {len(staff_after_remove)} (A seat has been freed).")

    # [TEST 7] Non-admin roles (analyst, reviewer) blocked from managing staff
    print("\n[TEST 7] Verifying non-admin roles are blocked from staff operations...")
    for r in ["analyst", "reviewer"]:
        try:
            add_or_invite_staff(org_a_id, "test@test.com", "analyst", admin_role=r)
            print(f"  FAILURE: Role '{r}' was able to invite staff!")
            sys.exit(1)
        except PermissionError as e:
            print(f"  Success: Role '{r}' blocked from adding staff ({e})")

        try:
            remove_staff_member(org_a_id, user_newbie["user_id"], "req_user", admin_role=r)
            print(f"  FAILURE: Role '{r}' was able to remove staff!")
            sys.exit(1)
        except PermissionError as e:
            print(f"  Success: Role '{r}' blocked from removing staff ({e})")

    print("\n" + "=" * 78)
    print("ALL STEP 8 STAFF MANAGEMENT & ISOLATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 78)


if __name__ == "__main__":
    run_tests()

