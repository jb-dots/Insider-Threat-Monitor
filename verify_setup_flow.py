"""End-to-end Playwright verification of the 3-step 'Set up your account' flow and tenant isolation."""

import socket
import subprocess
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

from db import get_session, Organization, AuditLog, get_org_alerts

OUT_DIR = Path("setup_screenshots")
OUT_DIR.mkdir(exist_ok=True)

def is_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0

def run():
    proc = None
    port = 8505
    if not is_port_open(port):
        proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", str(port), "--server.headless", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(30):
            if is_port_open(port):
                break
            time.sleep(0.5)

    ts = int(time.time())
    email1 = f"setup_org1_{ts}@test.com"
    org1_name = f"Alpha Cyber Defense {ts}"
    email2 = f"setup_org2_{ts}@test.com"
    org2_name = f"Beta Health Systems {ts}"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)

            # -----------------------------------------------------------------
            # ORG 1: Register -> Setup Steps 1, 2, 3 -> Dashboard
            # -----------------------------------------------------------------
            ctx1 = browser.new_context(viewport={"width": 1440, "height": 900})
            page = ctx1.new_page()
            page.goto(f"http://localhost:{port}?auth=register")
            page.wait_for_selector('[data-testid="stForm"]')
            time.sleep(1.5)
            page.screenshot(path=str(OUT_DIR / "01_register_page.png"))
            print("Captured: 01_register_page.png")

            page.fill('input[aria-label="Full Name"]', "Alice Setup One")
            page.fill('input[aria-label="Email Address"]', email1)
            page.fill('input[aria-label="Password (minimum 8 characters)"]', "Password123!")
            page.locator('button:has-text("Register Account")').click()

            # Should land on "Set up your account" Step 1
            page.wait_for_selector('text="Set up your account"', timeout=20000)
            page.wait_for_selector('text="1. Organization Details"', timeout=10000)
            time.sleep(1.0)

            # Security test: try changing URL to skip setup
            page.goto(f"http://localhost:{port}/?page=Alert+Queue")
            page.wait_for_selector('text="Set up your account"', timeout=15000)
            page.wait_for_selector('button:has-text("Next")', timeout=15000)
            time.sleep(1.0)
            print("PASS: URL bypass blocked, still on Set up your account.")

            page.screenshot(path=str(OUT_DIR / "02_setup_step1_org.png"))
            print("Captured: 02_setup_step1_org.png")

            # Fill Step 1
            page.fill('input[aria-label="Organization Name (2 to 80 characters)"]', org1_name)
            page.locator('[data-testid="stSelectbox"] input').click()
            page.keyboard.type("Finance")
            page.keyboard.press("Enter")
            time.sleep(0.3)
            page.locator('button:has-text("Next")').click()

            # Step 2: Guidelines
            page.wait_for_selector('text="2. Community Guidelines"', timeout=15000)
            time.sleep(1.0)
            page.screenshot(path=str(OUT_DIR / "03_setup_step2_guidelines.png"))
            print("Captured: 03_setup_step2_guidelines.png")

            next_btn = page.locator('button:has-text("Next")')
            assert next_btn.is_disabled(), "Next should be disabled until checkbox is checked!"
            page.locator('label:has-text("I understand this app is for synthetic or approved demo data only")').click()
            time.sleep(0.5)
            page.locator('button:has-text("Next")').click()

            # Step 3: Data
            page.wait_for_selector('text="3. Initial Telemetry Data"', timeout=15000)
            time.sleep(1.0)
            page.screenshot(path=str(OUT_DIR / "04_setup_step3_data.png"))
            print("Captured: 04_setup_step3_data.png")

            # "Load demo data" is selected by default; click "Finish setup"
            page.locator('button:has-text("Finish setup")').click()

            # Wait for dashboard (Alert Queue)
            page.wait_for_selector('text="Alert Queue"', timeout=45000)
            time.sleep(2.0)
            page.screenshot(path=str(OUT_DIR / "05_dashboard_after_finish.png"))
            print("Captured: 05_dashboard_after_finish.png")

            ctx1.close()

            # -----------------------------------------------------------------
            # ORG 2: Register second org (upload later) & verify tenant isolation
            # -----------------------------------------------------------------
            ctx2 = browser.new_context(viewport={"width": 1440, "height": 900})
            page2 = ctx2.new_page()
            page2.goto(f"http://localhost:{port}?auth=register")
            page2.wait_for_selector('[data-testid="stForm"]')
            page2.fill('input[aria-label="Full Name"]', "Bob Setup Two")
            page2.fill('input[aria-label="Email Address"]', email2)
            page2.fill('input[aria-label="Password (minimum 8 characters)"]', "Password123!")
            page2.locator('button:has-text("Register Account")').click()

            page2.wait_for_selector('text="1. Organization Details"', timeout=20000)
            page2.wait_for_selector('button:has-text("Next")', timeout=15000)
            page2.fill('input[aria-label="Organization Name (2 to 80 characters)"]', org2_name)
            page2.locator('[data-testid="stSelectbox"] input').click()
            page2.keyboard.type("Healthcare")
            page2.keyboard.press("Enter")
            page2.locator('button:has-text("Next")').click()

            page2.wait_for_selector('text="2. Community Guidelines"', timeout=15000)
            page2.locator('label:has-text("I understand this app is for synthetic or approved demo data only")').click()
            time.sleep(0.3)
            page2.locator('button:has-text("Next")').click()

            page2.wait_for_selector('text="3. Initial Telemetry Data"', timeout=15000)
            page2.locator('button:has-text("I\'ll upload logs later")').click()
            time.sleep(0.5)
            page2.locator('button:has-text("Finish setup")').click()

            page2.wait_for_selector('text="Alert Queue"', timeout=25000)
            time.sleep(1.5)
            page2.screenshot(path=str(OUT_DIR / "06_org2_isolated_dashboard.png"))
            print("Captured: 06_org2_isolated_dashboard.png")
            ctx2.close()
            browser.close()

        # Verify DB state & tenant isolation
        with get_session() as s:
            o1 = s.query(Organization).filter_by(name=org1_name).first()
            o2 = s.query(Organization).filter_by(name=org2_name).first()
            assert o1 is not None and o1.setup_completed is True, "Org 1 setup_completed not True!"
            assert o2 is not None and o2.setup_completed is True, "Org 2 setup_completed not True!"
            audit1 = s.query(AuditLog).filter_by(org_id=o1.org_id, action="org_setup_completed").first()
            audit2 = s.query(AuditLog).filter_by(org_id=o2.org_id, action="org_setup_completed").first()
            assert audit1 is not None, "Org 1 missing org_setup_completed audit event!"
            assert audit2 is not None, "Org 2 missing org_setup_completed audit event!"
            alerts1 = get_org_alerts(o1.org_id)
            alerts2 = get_org_alerts(o2.org_id)
            print(f"DB Verification: Org1 ({o1.org_id}) alerts={len(alerts1)}, Org2 ({o2.org_id}) alerts={len(alerts2)}")
            assert len(alerts1) > 0, "Org 1 should have demo alerts!"
            assert len(alerts2) == 0, "Org 2 must have 0 alerts (cannot see Org 1 data)!"
            print("PASS: Complete setup flow and strict multi-tenant isolation verified!")

    finally:
        if proc is not None:
            proc.terminate()

if __name__ == "__main__":
    run()

