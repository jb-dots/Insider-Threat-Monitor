"""Test rendering and capture screenshots with Playwright."""
import asyncio
from playwright.async_api import async_playwright
from pathlib import Path

SCREENSHOTS_DIR = Path("screenshots_new_logo")
SCREENSHOTS_DIR.mkdir(exist_ok=True)

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        for width, name_prefix in [(1440, "desktop_1440"), (390, "mobile_390")]:
            # 1. Sign In Page
            context = await browser.new_context(viewport={"width": width, "height": 900 if width == 1440 else 844})
            page = await context.new_page()
            await page.goto("http://localhost:8501?auth=signin", wait_until="networkidle")
            await asyncio.sleep(2)
            await page.screenshot(path=str(SCREENSHOTS_DIR / f"{name_prefix}_signin.png"), full_page=True)
            print(f"Captured {name_prefix}_signin.png")

            # 2. Register Page
            await page.goto("http://localhost:8501?auth=register", wait_until="networkidle")
            await asyncio.sleep(2)
            await page.screenshot(path=str(SCREENSHOTS_DIR / f"{name_prefix}_register.png"), full_page=True)
            print(f"Captured {name_prefix}_register.png")

            # Sign in as Admin to capture Dashboard / Alert Queue / Setup
            await page.goto("http://localhost:8501?auth=signin", wait_until="networkidle")
            await asyncio.sleep(1)
            # Fill login
            await page.fill("input[aria-label='Email Address']", "admin@company.com")
            await page.fill("input[aria-label='Password']", "AdminPass123!")
            await page.click("button:has-text('Sign In')")
            await asyncio.sleep(3)

            # 3. Alert Queue
            await page.screenshot(path=str(SCREENSHOTS_DIR / f"{name_prefix}_alert_queue.png"), full_page=True)
            print(f"Captured {name_prefix}_alert_queue.png")

            await context.close()

        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())

