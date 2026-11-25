from playwright.sync_api import sync_playwright
from pathlib import Path
import time
import uuid

def run():
    out_dir = Path("screenshots")
    out_dir.mkdir(exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        # 1. Login Page Check (Desktop 1440x900)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto("http://localhost:8501")
        page.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1)

        # Check background and scrollability
        bg_color = page.evaluate("() => window.getComputedStyle(document.body).backgroundColor")
        is_scrollable = page.evaluate("() => document.documentElement.scrollHeight > window.innerHeight")
        print(f"Login Page Body Background: {bg_color}")
        print(f"Login Page Is Scrollable: {is_scrollable}")

        page.screenshot(path=str(out_dir / "signin_desktop_1440px.png"), full_page=False)
        print("Captured: screenshots/signin_desktop_1440px.png")

        # 2. Login Page Check (Phone 390x844)
        page_m = browser.new_page(viewport={"width": 390, "height": 844})
        page_m.goto("http://localhost:8501")
        page_m.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1)
        page_m.screenshot(path=str(out_dir / "signin_phone_390px.png"), full_page=False)
        print("Captured: screenshots/signin_phone_390px.png")

        # 3. Setup / Onboarding Page Check
        # Register a fresh user who needs onboarding
        test_uid = uuid.uuid4().hex[:6]
        test_email = f"onboarding_user_{test_uid}@test.com"
        page_reg = browser.new_page(viewport={"width": 1440, "height": 900})
        page_reg.goto("http://localhost:8501?auth=register")
        page_reg.wait_for_selector('[data-testid="stForm"]')
        page_reg.fill('input[aria-label="Full Name"]', "Setup Test User")
        page_reg.fill('input[aria-label="Email Address"]', test_email)
        page_reg.fill('input[type="password"]', "Password123!")
        page_reg.click('button[kind="primaryFormSubmit"]')
        time.sleep(2)

        # Should now be on setup/onboarding page
        page_reg.wait_for_selector('text=Setup Your Account & Accept Guidelines')
        print("Arrived on Onboarding / Setup page!")
        time.sleep(1)

        # Test selecting the Standard Plan card
        page_reg.click('button:has-text("Select Standard")')
        time.sleep(1)
        page_reg.screenshot(path=str(out_dir / "setup_page_desktop.png"), full_page=False)
        print("Captured: screenshots/setup_page_desktop.png")

        # Accept guidelines and proceed to create org
        page_reg.click('label:has-text("I have read and accept the guidelines")')
        time.sleep(1)
        page_reg.click('button:has-text("Continue")')
        time.sleep(2)

        # Create organization to enter console
        page_reg.wait_for_selector('input[aria-label="Organization Name"]')
        page_reg.fill('input[aria-label="Organization Name"]', f"Setup Test Org {test_uid}")
        page_reg.click('button[kind="primaryFormSubmit"]')
        time.sleep(2)

        # 4. Alert Queue Check
        # Load demo logs if needed
        page_reg.goto("http://localhost:8501")
        time.sleep(2)
        # Navigate to Alert Queue
        if page_reg.locator('text=Alert Queue').count() > 0:
            page_reg.click('text=Alert Queue')
            time.sleep(1)
            page_reg.screenshot(path=str(out_dir / "alert_queue_desktop.png"), full_page=False)
            print("Captured: screenshots/alert_queue_desktop.png")

        browser.close()

if __name__ == "__main__":
    run()

