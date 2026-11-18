from playwright.sync_api import sync_playwright
from pathlib import Path
import time

def capture():
    out_dir = Path("screenshots")
    out_dir.mkdir(exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        # 1. Sign in - Desktop 1440x900
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto("http://localhost:8501")
        page.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1)
        page.screenshot(path=str(out_dir / "signin_desktop_1440px.png"), full_page=False)
        print("Captured: screenshots/signin_desktop_1440px.png")

        # 2. Sign in - Phone 390x844
        page_m = browser.new_page(viewport={"width": 390, "height": 844})
        page_m.goto("http://localhost:8501")
        page_m.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1)
        page_m.screenshot(path=str(out_dir / "signin_phone_390px.png"), full_page=False)
        print("Captured: screenshots/signin_phone_390px.png")

        # 3. Register - Desktop 1440x900
        page_reg_d = browser.new_page(viewport={"width": 1440, "height": 900})
        page_reg_d.goto("http://localhost:8501?auth=register")
        page_reg_d.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1)
        page_reg_d.screenshot(path=str(out_dir / "register_desktop_1440px.png"), full_page=False)
        print("Captured: screenshots/register_desktop_1440px.png")

        # 4. Register - Phone 390x844
        page_reg_m = browser.new_page(viewport={"width": 390, "height": 844})
        page_reg_m.goto("http://localhost:8501?auth=register")
        page_reg_m.wait_for_selector('[data-testid="stForm"]')
        time.sleep(1)
        page_reg_m.screenshot(path=str(out_dir / "register_phone_390px.png"), full_page=False)
        print("Captured: screenshots/register_phone_390px.png")

        browser.close()

if __name__ == "__main__":
    capture()
