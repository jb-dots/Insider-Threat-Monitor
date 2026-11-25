"""Official HuliCAP Logo Assets & Base64 Encoders.

Provides reliable base64 data URIs and file paths for:
- logo_white.png: Full line art (mark + wordmark) in pure white on transparent background
- logo_black.png: Full line art in near-black (#111111) on transparent background
- icon_white.png: Icon mark only in pure white on transparent background (square)
- icon_black.png: Icon mark only in near-black (#111111) on transparent background (square)
- favicon.png: Icon mark in near-black on solid white background for browser tab favicon
"""

from pathlib import Path
import base64
import functools

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"

@functools.lru_cache(maxsize=16)
def _read_b64(filename: str) -> str:
    target = ASSETS_DIR / filename
    if target.exists():
        with open(target, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return ""

def get_logo_white_b64() -> str:
    return _read_b64("logo_white.png")

def get_logo_black_b64() -> str:
    return _read_b64("logo_black.png")

def get_icon_white_b64() -> str:
    return _read_b64("icon_white.png")

def get_icon_black_b64() -> str:
    return _read_b64("icon_black.png")

def get_logo_white_uri() -> str:
    return f"data:image/png;base64,{get_logo_white_b64()}"

def get_logo_black_uri() -> str:
    return f"data:image/png;base64,{get_logo_black_b64()}"

def get_icon_white_uri() -> str:
    return f"data:image/png;base64,{get_icon_white_b64()}"

def get_icon_black_uri() -> str:
    return f"data:image/png;base64,{get_icon_black_b64()}"

# Backward-compatible aliases
def get_logo_full_uri() -> str:
    return get_logo_black_uri()

def get_logo_brand_uri() -> str:
    return get_icon_white_uri()

def get_logo_sidebar_uri() -> str:
    return get_logo_white_uri()

def get_logo_mark_uri() -> str:
    return get_icon_black_uri()
