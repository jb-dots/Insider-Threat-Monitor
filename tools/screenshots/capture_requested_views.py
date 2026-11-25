"""Capture high-resolution screenshots of the exact requested views:
- Sign in page
- Register page
- Sidebar expanded
- Sidebar collapsed
"""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

OUT_DIR = Path("requested_screenshots")
OUT_DIR.mkdir(exist_ok=True)

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        # 1. Sign In Page (1440x900)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.goto("http://localhost:8501?auth=signin")
        page.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1.5)
        signin_path = OUT_DIR / "01_signin_page.png"
        page.screenshot(path=str(signin_path), full_page=False)
        print(f"Captured: {signin_path}")
        context.close()

        # 2. Register Page (1440x900)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.goto("http://localhost:8501?auth=register")
        page.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1.5)
        register_path = OUT_DIR / "02_register_page.png"
        page.screenshot(path=str(register_path), full_page=False)
        print(f"Captured: {register_path}")
        context.close()

        # 3. Sidebar Expanded (1440x900)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.goto("http://localhost:8501?auth=signin")
        page.wait_for_selector('[data-testid="stForm"]')
        page.fill('input[aria-label="Email Address"]', "demo_analyst@hulicap.test")
        page.fill('input[type="password"]', "DemoPass123!")
        page.locator('button:has-text("Sign in")').click()
        time.sleep(3)
        page.wait_for_selector('text="Alert Queue"', timeout=15000)
        time.sleep(1)
        expanded_path = OUT_DIR / "03_sidebar_expanded.png"
        page.screenshot(path=str(expanded_path), full_page=False)
        print(f"Captured: {expanded_path}")

        # Also capture focused sidebar header crop
        sidebar_el = page.locator('[data-testid="stSidebar"]')
        if sidebar_el.count() > 0:
            sidebar_header_crop = OUT_DIR / "03_sidebar_header_crop.png"
            sidebar_el.screenshot(path=str(sidebar_header_crop))
            print(f"Captured: {sidebar_header_crop}")

        # 4. Sidebar Collapsed (1440x900)
        # Click the sidebar collapse button
        collapse_btn = page.locator('button[aria-label="Collapse sidebar"], [data-testid="stSidebarCollapseButton"] button').first
        if collapse_btn.count() > 0:
            collapse_btn.click()
            time.sleep(1.5)
        collapsed_path = OUT_DIR / "04_sidebar_collapsed.png"
        page.screenshot(path=str(collapsed_path), full_page=False)
        print(f"Captured: {collapsed_path}")

        # Also check top left collapsed control crop
        collapsed_control = page.locator('[data-testid="stSidebarCollapsedControl"]')
        if collapsed_control.count() > 0:
            collapsed_control_crop = OUT_DIR / "04_sidebar_collapsed_control_crop.png"
            collapsed_control.screenshot(path=str(collapsed_control_crop))
            print(f"Captured: {collapsed_control_crop}")

        context.close()
        browser.close()

if __name__ == "__main__":
    run()

