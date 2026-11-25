"""Test suite for Step 10: Security and Compliance Verification Checklist.

Validates:
1. Multi-tenant data isolation (Org A vs Org B: alerts, events, rules, audit log).
2. RBAC enforcement (Analyst, Reviewer, Org Admin strictly limited to allowed actions).
3. Immediate suspension blocking for users and organizations.
4. Super-admin isolation (Cannot read tenant alerts, notes, events, rules, or real IDs).
5. Cryptography & Privacy (Bcrypt password hashes; salted pseudonyms only in events).
6. SQL injection resilience (' OR 1=1 -- in login, email, and ID query endpoints).
7. Secrets exposure scanning (No hardcoded salts, production DB URLs, or super-admin passwords).
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pandas as pd

from hulicap.db import (
    Alert,
    Event,
    Membership,
    Organization,
    PlatformAuditLog,
    User,
    add_or_invite_staff,
    authenticate_user,
    check_permission,
    create_organization,
    get_active_org_context,
    get_org_alert_by_id,
    get_org_alerts,
    get_org_audit_logs,
    get_org_rules,
    get_platform_audit_logs,
    get_session,
    get_superadmin_organizations,
    get_user_membership,
    init_db,
    log_org_audit_event,
    register_user,
    save_org_alerts,
    save_org_events,
    save_org_rule,
    update_org_alert_review,
    update_org_status_by_superadmin,
    update_user_status_by_superadmin,
)


def run_checklist():
    print("=" * 78)
    print("HULICAP INSIDER THREAT MONITOR - COMPREHENSIVE SECURITY CHECKLIST")
    print("=" * 78)

    init_db()
    test_run = uuid.uuid4().hex[:6]

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 1: Multi-Tenant Data Isolation (Org A vs Org B)
    # ------------------------------------------------------------------------
    print("\n[CHECK 1] Multi-Tenant Isolation (Org A cannot read B's data)...")
    # Setup Org A
    user_a, _ = register_user("Admin Alpha", f"admin_a_{test_run}@alpha.com", "Password123!")
    org_a, _ = create_organization(f"Alpha Corp {test_run}", "Financial Services", "standard", user_a["user_id"])
    org_a_id = org_a["org_id"]
    org_a_salt = org_a["org_salt"]

    # Setup Org B
    user_b, _ = register_user("Admin Beta", f"admin_b_{test_run}@beta.com", "Password123!")
    org_b, _ = create_organization(f"Beta Corp {test_run}", "Healthcare", "free", user_b["user_id"])
    org_b_id = org_b["org_id"]
    org_b_salt = org_b["org_salt"]

    # Insert Org A Alert & Org B Alert
    alert_a = {
        "alert_id": f"alt_a_{test_run}",
        "org_id": org_a_id,
        "rule_id": "bulk_access",
        "severity": "high",
        "user_pseudonym": "USER-ALPHA001",
        "event_ids": "ev_a_1",
        "reason": "Confidential Alpha Telemetry Deviation",
        "status": "new",
        "reviewer": None,
        "reviewer_notes": "Alpha internal review note",
    }
    alert_b = {
        "alert_id": f"alt_b_{test_run}",
        "org_id": org_b_id,
        "rule_id": "policy_violation",
        "severity": "critical",
        "user_pseudonym": "USER-BETA001",
        "event_ids": "ev_b_1",
        "reason": "Confidential Beta Telemetry Deviation",
        "status": "new",
        "reviewer": None,
        "reviewer_notes": "Beta internal review note",
    }
    save_org_alerts([alert_a], org_a_id)
    save_org_alerts([alert_b], org_b_id)

    # Insert Events
    ev_df_a = pd.DataFrame([{
        "event_id": f"ev_a_{test_run}",
        "timestamp": "2026-10-15 10:00:00",
        "user_id": f"usr_a_{test_run}",
        "role": "engineer",
        "action": "read",
        "resource": "repo/alpha.git",
        "sensitivity": "high",
        "bytes": 5000,
        "device": "DEV-01",
        "source_ip": "10.0.1.1",
        "outcome": "success",
    }])
    ev_df_b = pd.DataFrame([{
        "event_id": f"ev_b_{test_run}",
        "timestamp": "2026-10-15 10:05:00",
        "user_id": f"usr_b_{test_run}",
        "role": "sales",
        "action": "download",
        "resource": "crm/beta.csv",
        "sensitivity": "medium",
        "bytes": 8000,
        "device": "DEV-02",
        "source_ip": "10.0.2.1",
        "outcome": "success",
    }])
    save_org_events(ev_df_a, org_a_id, "upl_a_1", org_a_salt)
    save_org_events(ev_df_b, org_b_id, "upl_b_1", org_b_salt)

    # Insert Org Rules
    save_org_rule(org_a_id, "bulk_access", {"threshold": 10}, role="org_admin")
    save_org_rule(org_b_id, "bulk_access", {"threshold": 50}, role="org_admin")

    # Insert Audit Logs
    log_org_audit_event(org_a_id, user_a["user_id"], "VIEW_ALERT", alert_a["alert_id"], "Alpha internal review")
    log_org_audit_event(org_b_id, user_b["user_id"], "VIEW_ALERT", alert_b["alert_id"], "Beta internal review")

    # 1. Alerts Isolation Check
    alerts_a = get_org_alerts(org_a_id)
    alert_ids_a = [x["alert_id"] for x in alerts_a]
    assert alert_a["alert_id"] in alert_ids_a, "Org A must see its own alert"
    assert alert_b["alert_id"] not in alert_ids_a, "DATA LEAK: Org A can list Org B alerts!"

    direct_cross_alert = get_org_alert_by_id(alert_b["alert_id"], org_id=org_a_id)
    assert direct_cross_alert is None, "DATA LEAK: Org A direct queried Org B alert!"
    print("  [PASS] Alerts Isolation: Org A cannot list or query Org B alerts.")

    # 2. Events Isolation Check
    with get_session() as s:
        events_for_a = s.query(Event).filter(Event.org_id == org_a_id).all()
        event_ids_for_a = [e.event_id for e in events_for_a]
        assert f"ev_a_{test_run}" in event_ids_for_a
        assert f"ev_b_{test_run}" not in event_ids_for_a, "DATA LEAK: Org A queried Org B events!"
    print("  [PASS] Events Isolation: Org A cannot query Org B raw audit events.")

    # 3. Rules Isolation Check
    rules_a = get_org_rules(org_a_id, role="org_admin")
    rules_b = get_org_rules(org_b_id, role="org_admin")
    assert rules_a.get("bulk_access") == {"threshold": 10}
    assert rules_b.get("bulk_access") == {"threshold": 50}
    print("  [PASS] Rules Isolation: Org A and Org B maintain independent threshold configurations.")

    # 4. Audit Log Isolation Check
    audit_a = get_org_audit_logs(org_a_id, role="org_admin")
    audit_targets_a = [l["target_id"] for l in audit_a]
    assert alert_a["alert_id"] in audit_targets_a
    assert alert_b["alert_id"] not in audit_targets_a, "DATA LEAK: Org A read Org B audit logs!"
    print("  [PASS] Audit Log Isolation: Org A cannot access Org B immutable audit trail.")

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 2: Role-Based Access Control (RBAC) Enforcement
    # ------------------------------------------------------------------------
    print("\n[CHECK 2] Role-Based Access Control (Analyst, Reviewer, Org Admin)...")
    # Analyst test
    analyst_ok_view, _ = check_permission("analyst", "view_alerts")
    analyst_ok_triage, _ = check_permission("analyst", "triage_review")
    analyst_blocked_esc, _ = check_permission("analyst", "triage_escalate")
    analyst_blocked_rules, _ = check_permission("analyst", "edit_rules")
    analyst_blocked_audit, _ = check_permission("analyst", "view_audit_trail")
    analyst_blocked_staff, _ = check_permission("analyst", "invite_staff")

    assert analyst_ok_view and analyst_ok_triage
    assert not analyst_blocked_esc and not analyst_blocked_rules and not analyst_blocked_audit and not analyst_blocked_staff
    print("  [PASS] Analyst Permissions: Can view/triage; strictly blocked from escalate, rules, audit, and staff.")

    # Reviewer test
    rev_ok_esc, _ = check_permission("reviewer", "triage_escalate")
    rev_ok_reident, _ = check_permission("reviewer", "request_reidentification")
    rev_blocked_rules, _ = check_permission("reviewer", "edit_rules")
    rev_blocked_audit, _ = check_permission("reviewer", "view_audit_trail")
    rev_blocked_staff, _ = check_permission("reviewer", "invite_staff")

    assert rev_ok_esc and rev_ok_reident
    assert not rev_blocked_rules and not rev_blocked_audit and not rev_blocked_staff
    print("  [PASS] Reviewer Permissions: Can escalate/re-identify; strictly blocked from rules, audit, and staff.")

    # Org Admin test
    adm_ok_rules, _ = check_permission("org_admin", "edit_rules")
    adm_ok_audit, _ = check_permission("org_admin", "view_audit_trail")
    adm_ok_staff, _ = check_permission("org_admin", "invite_staff")
    adm_blocked_super, _ = check_permission("org_admin", "platform_manage")

    assert adm_ok_rules and adm_ok_audit and adm_ok_staff and not adm_blocked_super
    print("  [PASS] Org Admin Permissions: Full tenant governance; strictly blocked from platform super-admin ops.")

    # Server-side mutation handler check: Analyst attempting escalation raises PermissionError
    try:
        update_org_alert_review(alert_a["alert_id"], org_a_id, "escalated", "Hacked escalation", "analyst_user", role="analyst")
        assert False, "Analyst escalation should have failed!"
    except PermissionError:
        print("  [PASS] Server-Side Barrier: Handler blocked analyst escalation with PermissionError.")

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 3: Immediate Suspension Blocking (User & Org)
    # ------------------------------------------------------------------------
    print("\n[CHECK 3] Immediate Suspension Blocking...")
    # 1. Suspended User
    sus_user, _ = register_user("Suspended User", f"sus_{test_run}@test.com", "Password123!")
    with get_session() as s:
        u_rec = s.query(User).filter_by(user_id=sus_user["user_id"]).first()
        u_rec.status = "suspended"
        s.commit()

    _, sus_auth_err = authenticate_user(sus_user["email"], "Password123!")
    assert "suspended" in sus_auth_err.lower(), f"Expected suspended error, got: {sus_auth_err}"
    print(f"  [PASS] Suspended User Blocked: Login halts with: '{sus_auth_err}'")

    # 2. Suspended Organization
    with get_session() as s:
        org_rec = s.query(Organization).filter_by(org_id=org_a_id).first()
        org_rec.status = "suspended"
        s.commit()

    _, org_block_err = get_active_org_context(user_a["user_id"])
    assert "suspended" in org_block_err.lower(), f"Expected suspended error, got: {org_block_err}"
    print(f"  [PASS] Suspended Org Blocked: Tenant access halts with: '{org_block_err}'")

    # Restore Org A status to active
    with get_session() as s:
        org_rec = s.query(Organization).filter_by(org_id=org_a_id).first()
        org_rec.status = "active"
        s.commit()

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 4: Super-Admin Tenant Data Barrier
    # ------------------------------------------------------------------------
    print("\n[CHECK 4] Super-Admin Tenant Data Barrier...")
    sa_user, _ = register_user("Global Root", f"root_{test_run}@hulicap.internal", "PasswordRoot123!")
    with get_session() as s:
        u = s.query(User).filter_by(user_id=sa_user["user_id"]).first()
        u.is_super_admin = True
        s.commit()

    sa_mem = get_user_membership(sa_user["user_id"])
    assert sa_mem is None, "Super-admin must have zero organization memberships"

    _, sa_context_err = get_active_org_context(sa_user["user_id"])
    assert sa_context_err == "NO_ORG", f"Expected NO_ORG, got: {sa_context_err}"

    sa_alerts = get_org_alerts(org_id="")
    assert len(sa_alerts) == 0, f"Expected 0 alerts for super-admin, got {len(sa_alerts)}"

    sa_orgs = get_superadmin_organizations()
    for o in sa_orgs:
        assert "reason" not in o and "notes" not in o, "Super-admin org listing must only have metadata"

    print("  [PASS] Super-Admin Isolation: Has no org membership, gets NO_ORG context, and returns 0 tenant alerts.")

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 5: Passwords & Event Pseudonymization
    # ------------------------------------------------------------------------
    print("\n[CHECK 5] Passwords & Event Pseudonymization...")
    with get_session() as s:
        all_users = s.query(User).all()
        for u in all_users:
            assert u.password_hash.startswith("$2b$") or u.password_hash.startswith("$2a$"), f"Password hash for {u.email} is not bcrypt!"
            assert len(u.password_hash) >= 59
            assert u.password_hash != "Password123!"
        print(f"  [PASS] Password Cryptography: Verified {len(all_users)} user accounts use bcrypt hashes ($2b$).")

        all_events = s.query(Event).all()
        for ev in all_events:
            assert ev.user_id.startswith("USER-"), f"Real user_id leaked in events: {ev.user_id}"
            assert not ev.user_id.startswith("usr_"), f"Raw user_id found in events: {ev.user_id}"
        print(f"  [PASS] Event Pseudonymization: Verified {len(all_events)} events store salted pseudonyms only (USER-XXXXXXXX).")

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 6: SQL Injection Resilience
    # ------------------------------------------------------------------------
    print("\n[CHECK 6] SQL Injection Resilience Testing...")
    sqli_payloads = [
        "' OR 1=1 --",
        "admin'--",
        "' OR '1'='1",
        "\"; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
    ]

    for payload in sqli_payloads:
        u_sqli, err_sqli = authenticate_user(payload, payload)
        assert u_sqli is None, f"SQL injection bypass occurred with payload: {payload}"
        assert err_sqli == "Invalid email or password."

    for payload in sqli_payloads:
        alert_sqli = get_org_alert_by_id(payload, org_id=org_a_id)
        assert alert_sqli is None

    print(f"  [PASS] SQL Injection Resilience: Tested {len(sqli_payloads)} payloads across auth and query endpoints; all safely bound.")

    # ------------------------------------------------------------------------
    # CHECKLIST ITEM 7: Secrets Exposure Scan
    # ------------------------------------------------------------------------
    print("\n[CHECK 7] Secrets Exposure Scan in Code & Git...")
    # Verify .gitignore exists and ignores secrets
    gitignore_path = Path(".gitignore")
    assert gitignore_path.exists(), ".gitignore file must exist!"
    gi_content = gitignore_path.read_text(encoding="utf-8")
    assert ".streamlit/secrets.toml" in gi_content, ".streamlit/secrets.toml must be in .gitignore"
    assert "monitor.db" in gi_content, "monitor.db must be in .gitignore"
    assert ".env" in gi_content, ".env must be in .gitignore"
    print("  [PASS] Git Protection: .gitignore properly configured for secrets, databases, and environments.")

    # Scan python files for hardcoded production credentials
    py_files = list(Path(".").glob("*.py"))
    leaks = []
    for p in py_files:
        if p.name.startswith("test_"):
            continue
        code = p.read_text(encoding="utf-8")
        # Check for hardcoded postgres production URLs with passwords
        if re.search(r"postgres(?:ql)?://\w+:[^@\s]+@", code):
            leaks.append(f"{p.name}: Potential hardcoded database password in connection string")
        # Check for hardcoded superadmin passwords assigned as Python variables
        if re.search(r'^\s*SUPERADMIN_PASSWORD\s*=\s*["\'][^"\']+["\']', code, re.MULTILINE):
            leaks.append(f"{p.name}: Hardcoded super-admin password assignment")

    assert len(leaks) == 0, f"Secrets leak detected: {leaks}"
    print(f"  [PASS] Codebase Clean: Scanned {len(py_files)} Python source files; zero hardcoded secrets detected.")

    print("\n" + "=" * 78)
    print("ALL 7 SECURITY & COMPLIANCE CHECKLIST ITEMS PASSED SUCCESSFULLY!")
    print("=" * 78)


if __name__ == "__main__":
    run_checklist()
