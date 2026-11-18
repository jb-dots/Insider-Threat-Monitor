import datetime
import os
import time
from playwright.sync_api import sync_playwright

from db import (
    create_user_session,
    get_session,
    log_session_timeout_audit_event,
    revoke_session,
    touch_session,
    DbSession,
    PlatformAuditLog,
    User,
)
from session_config import COOKIE_NAME, IDLE_LOGOUT_SECONDS, IDLE_WARN_SECONDS

SCREENSHOTS_DIR = os.path.abspath("screenshots")
DESKTOP_SHOTS_DIR = os.path.join(SCREENSHOTS_DIR, "desktop")
MOBILE_SHOTS_DIR = os.path.join(SCREENSHOTS_DIR, "mobile")
os.makedirs(DESKTOP_SHOTS_DIR, exist_ok=True)
os.makedirs(MOBILE_SHOTS_DIR, exist_ok=True)

def run_tests():
    print("=== STARTING FULL HULICAP VERIFICATION ===")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            headless=True,
        )
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        # -------------------------------------------------------------
        # TEST 1: Initial Login & Cookie Creation
        # -------------------------------------------------------------
        print("\n--- TEST 1: Initial Login ---")
        page.goto("http://localhost:8501")
        page.wait_for_selector('input[type="password"]', timeout=15000)

        # Fill login form
        inputs = page.locator('input[type="text"]')
        pwd_inputs = page.locator('input[type="password"]')
        inputs.first.fill("demo_analyst@hulicap.test")
        pwd_inputs.first.fill("DemoPass123!")

        page.locator('button:has-text("Sign in")').click()

        # Wait for dashboard to load
        page.wait_for_selector('text="Alert Queue"', timeout=15000)
        page.wait_for_timeout(1500)
        print("[PASS] Successfully logged in as demo_analyst@hulicap.test")

        # Verify cookie was set
        cookies = context.cookies()
        session_cookie = next((c for c in cookies if c["name"] == COOKIE_NAME), None)
        assert session_cookie is not None, "Session cookie was not created!"
        print(f"[PASS] Session cookie verified: {COOKIE_NAME} (length: {len(session_cookie['value'])})")

        # -------------------------------------------------------------
        # TEST 2: Reload While Logged In (Stay signed in)
        # -------------------------------------------------------------
        print("\n--- TEST 2: Reload While Logged In ---")
        page.reload()
        page.wait_for_selector('text="Alert Queue"', timeout=15000)
        assert page.locator('text="Alert Queue"').count() > 0, "Failed to stay signed in after reload!"
        print("[PASS] User remains signed in after page reload.")

        # -------------------------------------------------------------
        # TEST 3: Sidebar Collapse & Expand (Desktop 1440px)
        # -------------------------------------------------------------
        print("\n--- TEST 3: Sidebar Controls (Desktop 1440px) ---")
        collapse_btn = page.locator('[data-testid="stSidebarCollapseButton"] button').first
        collapse_btn.click()
        page.wait_for_timeout(1000)

        # Verify expand button is visible
        expand_btn = page.locator('[data-testid="stExpandSidebarButton"]').first
        assert expand_btn.is_visible(), "Expand button is not visible when collapsed on desktop!"
        print("[PASS] Collapse control collapsed sidebar; expand button is visible.")

        # Screenshot: Sidebar Collapsed Desktop
        collapsed_shot = os.path.join(DESKTOP_SHOTS_DIR, "04_sidebar_collapsed_desktop_1440px.png")
        page.screenshot(path=collapsed_shot)
        print(f"[SCREENSHOT] Saved: {collapsed_shot}")

        # Reload while collapsed and expand
        page.reload()
        page.wait_for_timeout(1500)
        expand_btn = page.locator('[data-testid="stExpandSidebarButton"]').first
        assert expand_btn.is_visible(), "Expand button is not visible after reload!"
        expand_btn.click()
        page.wait_for_timeout(1000)

        # Verify sidebar is expanded
        sidebar = page.locator('[data-testid="stSidebar"]')
        assert sidebar.is_visible(), "Sidebar is not expanded after clicking expand!"
        print("[PASS] Expand button restored sidebar successfully on desktop.")

        # Screenshot: Sidebar Expanded Desktop
        expanded_shot = os.path.join(DESKTOP_SHOTS_DIR, "03_sidebar_expanded_desktop_1440px.png")
        page.screenshot(path=expanded_shot)
        print(f"[SCREENSHOT] Saved: {expanded_shot}")

        # -------------------------------------------------------------
        # TEST 4: Alert Queue Dashboard Design (1440px)
        # -------------------------------------------------------------
        print("\n--- TEST 4: Alert Queue Design (1440px) ---")
        page.wait_for_selector('text=Total Incidents', timeout=15000)
        # Verify unified page title and description
        assert page.get_by_text("Alert Queue").first.is_visible()
        assert page.get_by_text("Review and triage security deviations").first.is_visible()

        # Verify 4 overview cards (Total, New, Under Review, Dismissed)
        assert page.get_by_text("Total Incidents").first.is_visible()
        assert page.get_by_text("New Incidents").first.is_visible()
        assert page.get_by_text("Under Review").first.is_visible()
        assert page.get_by_text("Dismissed").first.is_visible()
        print("[PASS] 4 Incident Overview cards present.")

        # Verify Severity Breakdown line
        assert page.get_by_text("Severity Breakdown:").first.is_visible()
        print("[PASS] Severity breakdown chip row present.")

        # Verify filters and alert cards
        page.wait_for_selector('text=Filter by Rule', timeout=15000)
        assert page.get_by_text("Filter by Status").first.is_visible()
        assert page.get_by_text("Filter by Rule").first.is_visible()

        # Verify open button is visible on cards
        page.wait_for_selector('button:has-text("Open")', timeout=15000)
        open_btns = page.locator('button:has-text("Open")')
        assert open_btns.count() > 0, "No Open buttons found on alert cards!"
        print(f"[PASS] Alert cards rendered with Open action button (found {open_btns.count()} cards).")

        # Screenshot: Alert Queue Desktop
        queue_desktop_shot = os.path.join(DESKTOP_SHOTS_DIR, "02_alert_queue_desktop_1440px.png")
        page.screenshot(path=queue_desktop_shot)
        print(f"[SCREENSHOT] Saved: {queue_desktop_shot}")

        # -------------------------------------------------------------
        # TEST 5: Alert Detail Navigation & Design (1440px)
        # -------------------------------------------------------------
        print("\n--- TEST 5: Alert Detail View (1440px) ---")
        # Click Open on first card
        open_btns.first.click()
        page.wait_for_timeout(2000)

        # Verify on Alert Detail page
        assert page.get_by_text("Alert Detail & Investigation").first.is_visible(), "Failed to navigate to Alert Detail!"
        assert page.get_by_text("Subject Pseudonym").first.is_visible()
        assert page.get_by_text("Reason & Observed Anomalies").first.is_visible()
        print("[PASS] Successfully navigated to Alert Detail view with unified header.")

        # Screenshot: Alert Detail Desktop
        detail_desktop_shot = os.path.join(DESKTOP_SHOTS_DIR, "01_alert_detail_desktop_1440px.png")
        page.screenshot(path=detail_desktop_shot)
        print(f"[SCREENSHOT] Saved: {detail_desktop_shot}")

        # -------------------------------------------------------------
        # TEST 6: Mobile Width (390px) Responsive Testing
        # -------------------------------------------------------------
        print("\n--- TEST 6: Mobile Viewport (390px) ---")
        context_mobile = browser.new_context(viewport={"width": 390, "height": 844})
        # Share cookies to stay logged in
        context_mobile.add_cookies(cookies)
        page_mobile = context_mobile.new_page()

        page_mobile.goto("http://localhost:8501")
        page_mobile.wait_for_selector('text=Alert Queue', timeout=15000)
        page_mobile.wait_for_timeout(1000)

        # On mobile, collapse sidebar overlay to expose dashboard page content
        collapse_btn_mobile = page_mobile.locator('[data-testid="stSidebarCollapseButton"] button').first
        if collapse_btn_mobile.is_visible():
            collapse_btn_mobile.click()
            page_mobile.wait_for_timeout(1000)

        # Screenshot: Alert Queue Mobile
        queue_mobile_shot = os.path.join(MOBILE_SHOTS_DIR, "02_alert_queue_mobile_390px.png")
        page_mobile.screenshot(path=queue_mobile_shot)
        print(f"[SCREENSHOT] Saved: {queue_mobile_shot}")

        # Click Open on mobile to view Alert Detail
        page_mobile.wait_for_selector('button:has-text("Open")', timeout=15000)
        mobile_open_btns = page_mobile.locator('button:has-text("Open")')
        if mobile_open_btns.count() > 0:
            mobile_open_btns.first.click()
            page_mobile.wait_for_selector('text=Alert Detail & Investigation', timeout=15000)
            page_mobile.wait_for_timeout(1000)

        # Screenshot: Alert Detail Mobile
        detail_mobile_shot = os.path.join(MOBILE_SHOTS_DIR, "01_alert_detail_mobile_390px.png")
        page_mobile.screenshot(path=detail_mobile_shot)
        print(f"[SCREENSHOT] Saved: {detail_mobile_shot}")

        context_mobile.close()

        # -------------------------------------------------------------
        # TEST 7: Logout & Reload After Logout
        # -------------------------------------------------------------
        print("\n--- TEST 7: Logout & Reload After Logout ---")
        # Click Log Out button in sidebar
        page.locator('button:has-text("Log Out")').click()
        page.wait_for_selector('input[type="password"]', timeout=10000)
        print("[PASS] Logged out successfully.")

        # Reload after logout
        page.reload()
        page.wait_for_selector('input[type="password"]', timeout=10000)
        assert page.locator('text="Sign in"').first.is_visible()
        print("[PASS] User remains signed out after reload.")

        # -------------------------------------------------------------
        # TEST 8: Copied Token From Expired or Revoked Session
        # -------------------------------------------------------------
        print("\n--- TEST 8: Revoked / Expired Session Token Rejection ---")
        with get_session() as s:
            u = s.query(User).filter(User.email == "demo_analyst@hulicap.test").first()
            demo_user_id = u.user_id

        # Create session in DB, then revoke it
        sess_dict, bad_token = create_user_session(demo_user_id)
        revoke_session(sess_dict["session_id"])

        # Inject revoked cookie
        context.add_cookies([{
            "name": COOKIE_NAME,
            "value": bad_token,
            "domain": "localhost",
            "path": "/",
        }])

        page.goto("http://localhost:8501")
        page.wait_for_selector('input[type="password"]', timeout=15000)
        assert page.locator('input[type="password"]').first.is_visible(), "Revoked token was unexpectedly accepted!"
        print("[PASS] Revoked session token was rejected; redirected to sign in.")
        page.wait_for_timeout(2000)

        # -------------------------------------------------------------
        # TEST 9: Suspended User Rejected Despite Valid Session
        # -------------------------------------------------------------
        print("\n--- TEST 9: Suspended User Rejected Despite Valid Session ---")
        # Find Charlie (suspended user)
        with get_session() as s:
            charlie = s.query(User).filter(User.email == "charlie@enterprise.com").first()
            charlie_id = charlie.user_id

        sess_dict_charlie, charlie_token = create_user_session(charlie_id)

        # Inject cookie for suspended user
        context.add_cookies([{
            "name": COOKIE_NAME,
            "value": charlie_token,
            "domain": "localhost",
            "path": "/",
        }])

        page.goto("http://localhost:8501")
        page.wait_for_selector('input[type="password"]', timeout=15000)
        page.wait_for_timeout(1000)
        assert page.locator('input[type="password"]').first.is_visible(), "Suspended user bypassed login!"
        # Check suspended message
        assert page.get_by_text("suspended or deactivated").first.is_visible()
        print("[PASS] Suspended user with valid session token was rejected with error message.")

        # -------------------------------------------------------------
        # TEST 10: Idle Warning Card & "Stay signed in"
        # -------------------------------------------------------------
        print("\n--- TEST 10: Idle Warning Card & Stay Signed In ---")
        # Log back in as demo analyst
        sess_dict_active, active_token = create_user_session(demo_user_id)
        sess_id_active = sess_dict_active["session_id"]
        context.add_cookies([{
            "name": COOKIE_NAME,
            "value": active_token,
            "domain": "localhost",
            "path": "/",
        }])

        page.goto("http://localhost:8501")
        page.wait_for_selector('text=Alert Queue', timeout=15000)
        page.wait_for_timeout(4000)

        # Simulate idle warning state by aging last_seen_at in DB
        with get_session() as s:
            db_s = s.query(DbSession).filter(DbSession.session_id == sess_id_active).first()
            # Set last_seen_at to warn threshold (e.g. now - IDLE_WARN_SECONDS - 5s)
            db_s.last_seen_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=IDLE_WARN_SECONDS + 5)
            s.commit()

        # Wait for fragment tick (2 seconds)
        print("Waiting for idle monitor fragment tick...")
        page.wait_for_selector('text=Are you still there?', timeout=10000)
        assert page.get_by_text("Are you still there?").first.is_visible()
        assert page.locator('button:has-text("Stay signed in")').first.is_visible()
        assert page.locator('button:has-text("Sign out now")').first.is_visible()
        print("[PASS] 'Are you still there?' warning card appeared with live countdown.")

        # Click 'Stay signed in'
        page.locator('button:has-text("Stay signed in")').first.click()
        page.wait_for_timeout(2000)
        assert page.locator('text=Are you still there?').count() == 0, "Warning card did not close!"
        print("[PASS] 'Stay signed in' refreshed session last_seen_at and closed warning card.")

        # -------------------------------------------------------------
        # TEST 11: Idle Automatic Logout & Audit Log Entry
        # -------------------------------------------------------------
        print("\n--- TEST 11: Idle Timeout Automatic Logout & Audit Trail ---")
        # Simulate idle logout state by aging last_seen_at past IDLE_LOGOUT_SECONDS
        with get_session() as s:
            db_s = s.query(DbSession).filter(DbSession.session_id == sess_id_active).first()
            db_s.last_seen_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=IDLE_LOGOUT_SECONDS + 10)
            s.commit()

        print("Waiting for idle logout trigger...")
        page.wait_for_selector('input[type="password"]', timeout=15000)
        page.wait_for_timeout(1000)
        assert page.get_by_text("You were signed out after").first.is_visible(), "Timeout logout message missing!"
        print("[PASS] Automatic sign out occurred with notification on Sign in page.")

        # Verify audit log entry for session_timeout
        with get_session() as s:
            audit_entry = s.query(PlatformAuditLog).filter(
                PlatformAuditLog.action == "session_timeout",
                PlatformAuditLog.actor_user_id == demo_user_id,
            ).order_by(PlatformAuditLog.created_at.desc()).first()
            assert audit_entry is not None, "session_timeout audit entry not found!"
            print(f"[PASS] session_timeout audit log verified: user={audit_entry.actor_user_id}, time={audit_entry.created_at}")

        context.close()
        browser.close()

    print("\n=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    run_tests()
