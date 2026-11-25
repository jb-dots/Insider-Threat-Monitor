"""Verify .hc-panel, .hc-streaks, .hc-watermark, and input styles at 1366x768 and 1920x1080."""

import socket
import subprocess
import sys
import time
import pprint
from pathlib import Path
from playwright.sync_api import sync_playwright

OUT_DIR = Path("requested_screenshots")
OUT_DIR.mkdir(exist_ok=True)

def is_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0

def run():
    proc = None
    if not is_port_open(8501):
        proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", "8501", "--server.headless", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(30):
            if is_port_open(8501):
                break
            time.sleep(0.5)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)

            for vp_name, vp in [("1366x768", {"width": 1366, "height": 768}), ("1920x1080", {"width": 1920, "height": 1080})]:
                for auth_mode in ["signin", "register"]:
                    context = browser.new_context(viewport=vp)
                    page = context.new_page()
                    page.goto(f"http://localhost:8501?auth={auth_mode}")
                    page.wait_for_selector('[data-testid="stForm"]')
                    page.wait_for_selector('.hc-panel')
                    time.sleep(1.5)

                    shot_path = OUT_DIR / f"{auth_mode}_{vp_name}.png"
                    page.screenshot(path=str(shot_path), full_page=False)
                    print(f"Captured: {shot_path}")

                    metrics = page.evaluate("""() => {
                        const panel = document.querySelector('.hc-panel');
                        const wm = document.querySelector('.hc-watermark');
                        const streaks = document.querySelector('.hc-streaks');
                        const content = document.querySelector('.hc-panel-content');
                        const card = document.querySelector('.hc-card');
                        const inputs = Array.from(document.querySelectorAll('[data-testid="stTextInput"]'));
                        const inputMetrics = inputs.map(ti => {
                            const root = ti.querySelector('[data-testid="stTextInputRootElement"]');
                            const inp = ti.querySelector('input');
                            const btn = ti.querySelector('button');
                            const rRoot = root.getBoundingClientRect();
                            const rInp = inp.getBoundingClientRect();
                            const rBtn = btn ? btn.getBoundingClientRect() : null;
                            return {
                                label: ti.querySelector('label') ? ti.querySelector('label').innerText : '',
                                rootW: Math.round(rRoot.width),
                                rootH: Math.round(rRoot.height),
                                inpW: Math.round(rInp.width),
                                btnInsideRoot: rBtn ? (rBtn.left >= rRoot.left && rBtn.right <= rRoot.right) : null,
                            };
                        });
                        const pRect = panel.getBoundingClientRect();
                        const wRect = wm.getBoundingClientRect();
                        const cRect = content.getBoundingClientRect();
                        const cardRect = card.getBoundingClientRect();
                        return {
                            viewportH: window.innerHeight,
                            panel: {top: Math.round(pRect.top), bottom: Math.round(pRect.bottom), height: Math.round(pRect.height), width: Math.round(pRect.width)},
                            watermark: {top: Math.round(wRect.top), widthPct: Math.round((wRect.width / pRect.width) * 100), opacity: getComputedStyle(wm).opacity},
                            hasStreaks: !!streaks && getComputedStyle(streaks).backgroundImage !== 'none',
                            cardClippedInPanel: cardRect.bottom > pRect.bottom,
                            panelClippedInViewport: pRect.top < 0 || pRect.bottom > window.innerHeight,
                            inputMetrics,
                        };
                    }""")
                    print(f"--- Metrics for {auth_mode} @ {vp_name} ---")
                    pprint.pprint(metrics)
                    context.close()

            browser.close()
    finally:
        if proc is not None:
            proc.terminate()

if __name__ == "__main__":
    run()
