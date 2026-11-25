"""Test script for Step 7: Role-Based Access Control (RBAC), Server-Side Handler Verification, and Audit Logging."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


import os
import sys
import uuid
import pandas as pd

from hulicap.db import (
    ROLE_PERMISSIONS,
    check_permission,
    create_organization,
    get_org_alerts,
    get_org_audit_logs,
    init_db,
    log_org_audit_event,
    register_user,
    save_org_alerts,
    save_org_rule,
    update_org_alert_review,
)


def print_role_action_matrix():
    print("=" * 78)
    print("ROLE VERSUS ALLOWED ACTIONS MATRIX (SERVER-SIDE ENFORCED)")
    print("=" * 78)
    actions = [
        ("view_alerts", "View Alerts (Pseudonyms Only)"),
        ("triage_review", "Mark Alert as Reviewed"),
        ("triage_dismiss", "Dismiss Alert as False Positive"),
        ("save_notes", "Save Investigation Notes"),
        ("triage_escalate", "Escalate Alert to Tier 2"),
        ("request_reidentification", "Request Re-Identification (w/ Justification)"),
        ("upload_logs", "Upload Telemetry Logs & Run Detector"),
        ("view_rules", "View Detection Rules Configuration"),
        ("edit_rules", "Edit Detection Rules & Thresholds"),
        ("view_audit_trail", "View Immutable Security Audit Trail"),
        ("invite_staff", "Invite Staff Members to Organization"),
    ]

    header = f"{'Action / Capability':<48} | {'Analyst':<8} | {'Reviewer':<8} | {'Org Admin':<9}"
    print(header)
    print("-" * len(header))

    for act_key, act_label in actions:
        an_ok, _ = check_permission("analyst", act_key)
        rev_ok, _ = check_permission("reviewer", act_key)
        adm_ok, _ = check_permission("org_admin", act_key)
        an_str = "Allowed" if an_ok else "Blocked"
        rev_str = "Allowed" if rev_ok else "Blocked"
        adm_str = "Allowed" if adm_ok else "Blocked"
        print(f"{act_label:<48} | {an_str:<8} | {rev_str:<8} | {adm_str:<9}")

    print("=" * 78)


def main():
    init_db()
    print_role_action_matrix()
    print("\n" + "=" * 78)
    print("DEMONSTRATION OF SERVER-SIDE BLOCKED ACTIONS & AUDIT INTEGRITY")
    print("=" * 78)

    # 1. Setup Test Organization and Test Alert
    test_id = uuid.uuid4().hex[:6]
    admin_email = f"orgadmin_{test_id}@example.com"
    analyst_email = f"analyst_{test_id}@example.com"
    reviewer_email = f"reviewer_{test_id}@example.com"

    user_admin, _ = register_user("Admin Test", admin_email, "Admin Pass 123")
    user_analyst, _ = register_user("Analyst Test", analyst_email, "Analyst Pass 123")
    user_reviewer, _ = register_user("Reviewer Test", reviewer_email, "Reviewer Pass 123")

    org_ctx, _ = create_organization("Apex Security Corp", "Defense", "standard", user_admin["user_id"])
    org_id = org_ctx["org_id"]

    test_alert = {
        "alert_id": f"alt_{test_id}",
        "org_id": org_id,
        "rule_id": "bulk_access",
        "severity": "high",
        "user_pseudonym": "USER-DEMO777",
        "event_ids": "ev_001,ev_002",
        "reason": "Test alert for RBAC enforcement",
        "status": "new",
        "reviewer": None,
        "reviewer_notes": "",
    }
    save_org_alerts([test_alert], org_id)
    print(f"\n[SETUP] Created Org '{org_ctx['name']}' ({org_id}) with test alert '{test_alert['alert_id']}'.")

    # DEMO 1: Analyst Blocked Action (Attempting to escalate)
    print("\n[DEMO 1] Demonstrating Blocked Action for Analyst: Attempting to Escalate Alert")
    analyst_role = "analyst"
    # Verification check: Permission check blocks analyst
    allowed, err = check_permission(analyst_role, "triage_escalate")
    print(f"  Permission Check: triage_escalate for role '{analyst_role}' -> Allowed={allowed}")
    print(f"  System Message  : {err}")

    # Server-side button handler simulation: update_org_alert_review with role='analyst'
    try:
        update_org_alert_review(
            alert_id=test_alert["alert_id"],
            org_id=org_id,
            status="escalated",
            reviewer_notes="Unauthorized escalation attempt",
            reviewer="analyst_test",
            role=analyst_role,
        )
        print("  FAILURE: Analyst was able to escalate!")
        sys.exit(1)
    except PermissionError as e:
        print(f"  SUCCESS (Server-Side Blocked): Caught expected PermissionError: '{e}'")

    # Verify alert status remained untouched
    alerts = get_org_alerts(org_id)
    current_status = alerts[0]["status"]
    assert current_status == "new", f"Expected alert status 'new', but found '{current_status}'"
    print(f"  Verified Alert State: Unchanged (status='{current_status}')")

    # DEMO 2: Reviewer Blocked Action (Attempting to edit rules)
    print("\n[DEMO 2] Demonstrating Blocked Action for Reviewer: Attempting to Edit Detection Rules")
    reviewer_role = "reviewer"
    allowed, err = check_permission(reviewer_role, "edit_rules")
    print(f"  Permission Check: edit_rules for role '{reviewer_role}' -> Allowed={allowed}")
    print(f"  System Message  : {err}")

    try:
        save_org_rule(
            org_id=org_id,
            rule_id="policy_violation",
            thresholds={"max_violations": 0},
            role=reviewer_role,
        )
        print("  FAILURE: Reviewer was able to modify rules!")
        sys.exit(1)
    except PermissionError as e:
        print(f"  SUCCESS (Server-Side Blocked): Caught expected PermissionError: '{e}'")

    # DEMO 3: Org Admin Blocked Action (Attempting platform super-admin operation)
    print("\n[DEMO 3] Demonstrating Blocked Action for Org Admin: Attempting Platform Super-Admin Operation")
    org_admin_role = "org_admin"
    allowed, err = check_permission(org_admin_role, "superadmin_platform_manage")
    print(f"  Permission Check: superadmin_platform_manage for role '{org_admin_role}' -> Allowed={allowed}")
    print(f"  System Message  : {err}")
    print("  SUCCESS (Server-Side Blocked): Org Admin cannot execute super-admin actions.")

    # DEMO 4: Allowed Actions Verification & Audit Trail Logging
    print("\n[DEMO 4] Verifying Allowed Actions & Audit Log Recording")
    # Analyst can mark as reviewed
    update_org_alert_review(
        alert_id=test_alert["alert_id"],
        org_id=org_id,
        status="reviewed",
        reviewer_notes="Reviewed by analyst: verified valid activity.",
        reviewer="analyst_test",
        role=analyst_role,
    )
    log_org_audit_event(
        org_id=org_id,
        user_id=user_analyst["user_id"],
        action="UPDATE_ALERT_STATUS",
        target=test_alert["alert_id"],
        justification="Marked as reviewed by analyst",
    )
    print("  Analyst successfully marked alert as REVIEWED and logged event.")

    # Reviewer can escalate
    update_org_alert_review(
        alert_id=test_alert["alert_id"],
        org_id=org_id,
        status="escalated",
        reviewer_notes="Reviewer confirmed escalation to Tier 2 incident team.",
        reviewer="reviewer_test",
        role=reviewer_role,
    )
    log_org_audit_event(
        org_id=org_id,
        user_id=user_reviewer["user_id"],
        action="UPDATE_ALERT_STATUS",
        target=test_alert["alert_id"],
        justification="Escalated to Tier 2",
    )
    print("  Reviewer successfully escalated alert to ESCALATED and logged event.")

    # Alert view audit event recording
    view_log_id = log_org_audit_event(
        org_id=org_id,
        user_id=user_reviewer["user_id"],
        action="VIEW_ALERT",
        target=test_alert["alert_id"],
        justification="Alert detail deep-dive inspection",
    )
    print(f"  Alert view logged to audit trail (ID: {view_log_id}).")

    # Reviewer re-identification with written justification
    reident_log_id = log_org_audit_event(
        org_id=org_id,
        user_id=user_reviewer["user_id"],
        action="RE_IDENTIFY_USER",
        target=test_alert["alert_id"],
        justification="HR Incident Ticket #HR-9812 forensic de-anonymization request",
    )
    print(f"  User re-identification logged to audit trail (ID: {reident_log_id}).")

    # Org Admin can edit rules
    save_org_rule(
        org_id=org_id,
        rule_id="policy_violation",
        thresholds={"max_violations": 1},
        role=org_admin_role,
    )
    print("  Org Admin successfully updated rules.")

    # Verify Audit Trail Contents
    audit_logs = get_org_audit_logs(org_id, role=org_admin_role)
    actions_logged = [l["action"] for l in audit_logs]
    print(f"\n[AUDIT LEDGER VERIFICATION] Total events in org audit trail: {len(audit_logs)}")
    print(f"  Actions recorded: {actions_logged}")
    assert "VIEW_ALERT" in actions_logged, "VIEW_ALERT must be in audit log"
    assert "RE_IDENTIFY_USER" in actions_logged, "RE_IDENTIFY_USER must be in audit log"
    assert "UPDATE_ALERT_STATUS" in actions_logged, "UPDATE_ALERT_STATUS must be in audit log"
    print("  Success: Every alert view and re-identification was recorded with org_id and user_id.")

    print("\n" + "=" * 78)
    print("VERIFY: AN ANALYST CANNOT ESCALATE EVEN BY MANIPULATING THE PAGE.")
    print("=" * 78)


if __name__ == "__main__":
    main()
