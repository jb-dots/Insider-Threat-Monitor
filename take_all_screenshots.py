from playwright.sync_api import sync_playwright
from pathlib import Path
import time
import re

out_dir = Path("screenshots")
out_dir.mkdir(exist_ok=True)

def check_raw_html(page, page_name):
    # Search body text for unrendered HTML tags
    body_text = page.inner_text("body")
    suspicious = re.findall(r'<\/?(?:div|span|p|a|h\d|button|strong|em|img|code)[^>]*>', body_text, re.IGNORECASE)
    if suspicious:
        print(f"⚠️ Warning: Found potential raw HTML on {page_name}: {suspicious[:5]}")
        return False
    else:
        print(f"✅ Clean: No raw HTML detected on {page_name}")
        return True

def capture_all():
    results = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        viewports = [
            ("1440px", {"width": 1440, "height": 900}),
            ("390px", {"width": 390, "height": 844})
        ]

        # -------------------------------------------------------------
        # 1. Sign in (1440px & 390px)
        # -------------------------------------------------------------
        for vp_name, vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()
            page.goto("http://localhost:8501?auth=signin")
            page.wait_for_selector('[data-testid="stForm"]')
            time.sleep(1)
            shot_path = out_dir / f"01_signin_{vp_name}.png"
            page.screenshot(path=str(shot_path), full_page=False)
            print(f"Saved: {shot_path}")
            check_raw_html(page, f"Sign in ({vp_name})")
            context.close()

        # -------------------------------------------------------------
        # 2. Register (1440px & 390px)
        # -------------------------------------------------------------
        for vp_name, vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()
            page.goto("http://localhost:8501?auth=register")
            page.wait_for_selector('[data-testid="stForm"]')
            time.sleep(1)
            shot_path = out_dir / f"02_register_{vp_name}.png"
            page.screenshot(path=str(shot_path), full_page=False)
            print(f"Saved: {shot_path}")
            check_raw_html(page, f"Register ({vp_name})")
            context.close()

        # -------------------------------------------------------------
        # 3. Setup (Selected Plan) (1440px & 390px)
        # Login with setup_user@hulicap.test / SetupPass123!
        # -------------------------------------------------------------
        for vp_name, vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()
            page.goto("http://localhost:8501?auth=signin")
            page.wait_for_selector('[data-testid="stForm"]')
            page.fill('input[aria-label="Email Address"]', "setup_user@hulicap.test")
            page.fill('input[type="password"]', "SetupPass123!")
            page.click('button[kind="primaryFormSubmit"]')
            time.sleep(2)

            # Wait for setup page to appear
            page.wait_for_selector('text=Select Subscription Tier')
            # Select Pro plan to showcase active tier selection
            if page.locator('button:has-text("Select Pro")').count() > 0:
                page.click('button:has-text("Select Pro")')
                time.sleep(1)

            shot_path = out_dir / f"03_setup_plan_{vp_name}.png"
            page.screenshot(path=str(shot_path), full_page=False)
            print(f"Saved: {shot_path}")
            check_raw_html(page, f"Setup Plan ({vp_name})")
            context.close()

        # -------------------------------------------------------------
        # 4. Alert Queue (1440px & 390px)
        # Login with demo_analyst@hulicap.test / DemoPass123!
        # -------------------------------------------------------------
        for vp_name, vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()
            page.goto("http://localhost:8501?auth=signin")
            page.wait_for_selector('[data-testid="stForm"]')
            page.fill('input[aria-label="Email Address"]', "demo_analyst@hulicap.test")
            page.fill('input[type="password"]', "DemoPass123!")
            page.locator('button:has-text("Sign in")').click()
            time.sleep(3)

            page.wait_for_selector('text="Alert Queue"', timeout=15000)
            time.sleep(1)
            shot_path = out_dir / f"04_alert_queue_{vp_name}.png"
            page.screenshot(path=str(shot_path), full_page=False)
            print(f"Saved: {shot_path}")
            check_raw_html(page, f"Alert Queue ({vp_name})")
            context.close()

        # -------------------------------------------------------------
        # 5. Alert Detail (1440px & 390px)
        # Login with demo_analyst@hulicap.test / DemoPass123! and open detail
        # -------------------------------------------------------------
        for vp_name, vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()
            page.goto("http://localhost:8501?auth=signin")
            page.wait_for_selector('[data-testid="stForm"]')
            page.fill('input[aria-label="Email Address"]', "demo_analyst@hulicap.test")
            page.fill('input[type="password"]', "DemoPass123!")
            page.locator('button:has-text("Sign in")').click()
            time.sleep(3)

            # Click "Open" on first alert or navigate via sidebar radio
            if page.locator('button:has-text("Open")').count() > 0:
                page.locator('button:has-text("Open")').first.click(force=True)
            else:
                page.locator('label:has-text("Alert Detail")').first.click(force=True)
            time.sleep(3)

            page.wait_for_selector('text="Alert Detail"', timeout=15000)
            time.sleep(1)
            shot_path = out_dir / f"05_alert_detail_{vp_name}.png"
            page.screenshot(path=str(shot_path), full_page=False)
            print(f"Saved: {shot_path}")
            check_raw_html(page, f"Alert Detail ({vp_name})")
            context.close()

        # -------------------------------------------------------------
        # 6. Super-Admin Page (1440px & 390px)
        # Login with superadmin@hulicap.com / Password123!
        # -------------------------------------------------------------
        for vp_name, vp in viewports:
            context = browser.new_context(viewport=vp)
            page = context.new_page()
            page.goto("http://localhost:8501?auth=signin")
            page.wait_for_selector('[data-testid="stForm"]')
            page.fill('input[aria-label="Email Address"]', "superadmin@hulicap.com")
            page.fill('input[type="password"]', "Password123!")
            page.locator('button:has-text("Sign in")').click()
            time.sleep(3)

            page.wait_for_selector('text="Platform Organizations"', timeout=15000)
            time.sleep(1)
            shot_path = out_dir / f"06_superadmin_{vp_name}.png"
            page.screenshot(path=str(shot_path), full_page=False)
            print(f"Saved: {shot_path}")
            check_raw_html(page, f"SuperAdmin ({vp_name})")
            context.close()

        browser.close()

if __name__ == "__main__":
    capture_all()

