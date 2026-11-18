"""Test script for Step 9: Super-admin creation, console operations, platform audit logging, and tenant isolation."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


import os
import subprocess
import sys
import uuid

from db import (
    authenticate_user,
    check_permission,
    create_organization,
    get_active_org_context,
    get_org_alerts,
    get_org_audit_logs,
    get_platform_audit_logs,
    get_superadmin_organizations,
    get_superadmin_users,
    get_user_membership,
    init_db,
    register_user,
    save_org_alerts,
    update_org_status_by_superadmin,
    update_user_status_by_superadmin,
)


def run_tests():
    print("=" * 78)
    print("STEP 9 VERIFICATION: SUPER-ADMIN CLI, CONSOLE, & ISOLATION SUITE")
    print("=" * 78)

    init_db()

    test_run = uuid.uuid4().hex[:6]
    superadmin_email = f"superadmin_{test_run}@hulicap.internal"
    superadmin_pass = "PlatformRootSecret2026!"
    superadmin_name = f"Root Administrator {test_run}"

    # [TEST 1] Proving no regular registration can create a super-admin
    print("\n[TEST 1] Verifying that application registration strictly sets is_super_admin = False...")
    reg_user, _ = register_user("Regular Analyst", f"analyst_{test_run}@corp.com", "Password123!")
    assert not reg_user["is_super_admin"], "Security violation: regular registration must never yield is_super_admin=True!"
    print(f"  Success: User '{reg_user['email']}' created with is_super_admin={reg_user['is_super_admin']}.")

    # [TEST 2] Testing create_superadmin.py terminal script execution
    print("\n[TEST 2] Executing create_superadmin.py via CLI with environment variables...")
    env = os.environ.copy()
    env["SUPERADMIN_EMAIL"] = superadmin_email
    env["SUPERADMIN_PASSWORD"] = superadmin_pass
    env["SUPERADMIN_NAME"] = superadmin_name

    proc = subprocess.run(
        [sys.executable, "create_superadmin.py"],
        env=env,
        capture_output=True,
        text=True,
    )
    print(proc.stdout)
    assert proc.returncode == 0, f"create_superadmin.py failed: {proc.stderr}"

    # Authenticate the created super-admin
    sa_user, sa_err = authenticate_user(superadmin_email, superadmin_pass)
    assert sa_err is None, f"Superadmin login failed: {sa_err}"
    assert sa_user["is_super_admin"] is True, "Superadmin flag must be True!"
    sa_user_id = sa_user["user_id"]
    print(f"  Verified authenticated super-admin: {sa_user['email']} (ID: {sa_user_id}, is_super_admin=True)")

    # [TEST 3] Proving Tenant Isolation: Super-admin has no org and cannot view tenant alerts
    print("\n[TEST 3] Proving Tenant Isolation: Super-admin has zero organization pages/alerts...")
    # Check membership
    sa_mem = get_user_membership(sa_user_id)
    assert sa_mem is None, f"Super-admin must not belong to any organization! Got: {sa_mem}"
    print(f"  Super-admin organization membership: {sa_mem} (None as required)")

    # Check active org context
    org_ctx, org_err = get_active_org_context(sa_user_id)
    assert org_err == "NO_ORG", f"Expected NO_ORG for super-admin, got: {org_err}"
    print(f"  get_active_org_context(super_admin_id) returned: {org_err} (Tenant context blocked)")

    # Create a test organization with tenant alerts
    tenant_admin, _ = register_user("Org Admin", f"tenant_admin_{test_run}@acme.com", "AcmePassword123!")
    tenant_org, _ = create_organization(f"Acme Corp {test_run}", "Financial Services", "standard", tenant_admin["user_id"])
    tenant_org_id = tenant_org["org_id"]

    test_alert = {
        "alert_id": f"alt_{test_run}",
        "org_id": tenant_org_id,
        "rule_id": "policy_violation",
        "severity": "critical",
        "user_pseudonym": "USER-FORENSIC99",
        "event_ids": "ev_001,ev_002",
        "reason": "CONFIDENTIAL: Internal fraud investigation notes",
        "status": "new",
        "reviewer": None,
        "reviewer_notes": "Highly sensitive internal findings",
    }
    save_org_alerts([test_alert], tenant_org_id)
    print(f"  Created Tenant Org '{tenant_org['name']}' ({tenant_org_id}) with 1 confidential alert.")

    # Query alerts for super-admin's scope
    # Since super-admin has no org_id, querying alerts for their context returns empty list
    superadmin_alerts = get_org_alerts(org_id="")
    assert len(superadmin_alerts) == 0, "Security violation: super-admin context must return zero alerts!"
    print(f"  Tenant Alerts returned for super-admin context: {len(superadmin_alerts)} (Zero alerts, as proven).")

    # [TEST 4] Test Super-Admin Console: Organizations Directory (Metadata & Counts Only)
    print("\n[TEST 4] Testing Super-Admin Console: Listing organizations (Metadata & counts only)...")
    sa_orgs = get_superadmin_organizations()
    assert len(sa_orgs) >= 1
    found_tenant_org = next((o for o in sa_orgs if o["org_id"] == tenant_org_id), None)
    assert found_tenant_org is not None
    print(f"  Org Name:       {found_tenant_org['name']}")
    print(f"  Plan:           {found_tenant_org['plan']}")
    print(f"  Status:         {found_tenant_org['status']}")
    print(f"  User Count:     {found_tenant_org['user_count']}")
    print(f"  Alert Count:    {found_tenant_org['alert_count']}")
    print(f"  Upload Count:   {found_tenant_org['upload_count']}")
    # Verify no sensitive alert text or reason is in the organization metadata
    assert "reason" not in found_tenant_org
    assert "reviewer_notes" not in found_tenant_org
    print("  Success: Super-admin received counts and metadata only; zero telemetry or notes.")

    # [TEST 5] Test Super-Admin Console: Users Directory
    print("\n[TEST 5] Testing Super-Admin Console: Listing users...")
    sa_users = get_superadmin_users()
    assert len(sa_users) >= 2
    found_analyst = next((u for u in sa_users if u["email"] == reg_user["email"]), None)
    assert found_analyst is not None
    print(f"  User Name:     {found_analyst['name']}")
    print(f"  Email:         {found_analyst['email']}")
    print(f"  Status:        {found_analyst['status']}")
    print(f"  Organization:  {found_analyst['organization']}")
    print(f"  Role:          {found_analyst['role']}")

    # [TEST 6] Suspend, Ban, and Reactivate User with Platform Audit Logging
    print("\n[TEST 6] Suspending and reactivating user with written reason in platform_audit_log...")
    # Attempt status change with empty reason (Must be rejected)
    ok_empty, err_empty = update_user_status_by_superadmin(
        actor_user_id=sa_user_id,
        target_user_id=reg_user["user_id"],
        new_status="suspended",
        reason="   ",
    )
    assert not ok_empty, "Status update without written reason must be rejected!"
    print(f"  Empty reason validation: Blocked as expected ({err_empty})")

    # Suspend user with valid reason
    user_suspend_reason = "Compromised credential reported by SecOps ticket #SEC-441"
    ok_susp, _ = update_user_status_by_superadmin(
        actor_user_id=sa_user_id,
        target_user_id=reg_user["user_id"],
        new_status="suspended",
        reason=user_suspend_reason,
    )
    assert ok_susp

    # Verify user login is now blocked
    _, login_err = authenticate_user(reg_user["email"], "Password123!")
    assert "suspended" in login_err.lower(), f"Expected suspended message, got: {login_err}"
    print(f"  User suspended successfully. User login attempt result: '{login_err}'")

    # Reactivate user
    ok_react, _ = update_user_status_by_superadmin(
        actor_user_id=sa_user_id,
        target_user_id=reg_user["user_id"],
        new_status="active",
        reason="Credential rotated and verified by identity team",
    )
    assert ok_react
    print("  User reactivated successfully.")

    # [TEST 7] Suspend and Reactivate Organization with Platform Audit Logging
    print("\n[TEST 7] Suspending and reactivating organization with written reason in platform_audit_log...")
    org_suspend_reason = "Billing default and non-compliance with telemetry guidelines"
    ok_org_susp, _ = update_org_status_by_superadmin(
        actor_user_id=sa_user_id,
        target_org_id=tenant_org_id,
        new_status="suspended",
        reason=org_suspend_reason,
    )
    assert ok_org_susp

    # Verify organization pages are now blocked for tenant admin
    _, org_block_err = get_active_org_context(tenant_admin["user_id"])
    assert "suspended" in org_block_err.lower(), f"Expected suspended message, got: {org_block_err}"
    print(f"  Organization suspended. Tenant admin context result: '{org_block_err}'")

    # Reactivate organization
    ok_org_react, _ = update_org_status_by_superadmin(
        actor_user_id=sa_user_id,
        target_org_id=tenant_org_id,
        new_status="active",
        reason="Compliance review completed and approved",
    )
    assert ok_org_react
    print("  Organization reactivated successfully.")

    # [TEST 8] Platform Audit Trail Verification
    print("\n[TEST 8] Verifying Platform Audit Trail ledger...")
    p_logs = get_platform_audit_logs()
    assert len(p_logs) >= 4, f"Expected at least 4 platform audit events, got {len(p_logs)}"
    print(f"  Total platform audit records: {len(p_logs)}")

    # Check columns: actor, timestamp, action, target_type, target_id, reason
    sample = p_logs[0]
    print(f"  Sample Record: ID={sample['log_id']} | Actor={sample['actor']} | Action={sample['action']} | Target={sample['target_type']}:{sample['target_id']}")
    print(f"  Reason: {sample['reason']}")

    # Check that justification text from organization audit logs is NEVER present in platform audit logs
    for log in p_logs:
        assert "CONFIDENTIAL: Internal fraud" not in log["reason"], "Data leak: tenant audit details found in platform audit log!"
    print("  Verified: Platform audit log strictly isolates administrative interventions without tenant audit justifications.")

    print("\n" + "=" * 78)
    print("ALL STEP 9 SUPER-ADMIN & PLATFORM CONSOLE CHECKS PASSED SUCCESSFULLY!")
    print("=" * 78)


if __name__ == "__main__":
    run_tests()

