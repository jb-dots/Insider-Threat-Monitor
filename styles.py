"""Design system and style definitions for the HuliCAP Insider Threat Monitor.

Provides a unified corporate B2B security SaaS visual language:
- White canvas (#FFFFFF) with calm slate surfaces (#F8FAFC) and navy primary brand (#1E3A8A).
- Inter typography scale: Page Title (28px), Section Title (18px), Body (15px), Caption (13px).
- 8px spatial grid, 12px border-radius, 24px card padding, and subtle elevations.
- Accessible semantic chips for severity and status (text + color dual signaling).
- Specialized platform accent (Dark Teal #0F766E) for super-admin views.
"""

from typing import Any, Dict, Optional, List, Union
import streamlit as st

# Color Palette Constants
COLOR_CANVAS = "#F5F5F5"
COLOR_CARD_SURFACE = "#FFFFFF"
COLOR_BORDER = "#E5E7EB"
COLOR_BORDER_HOVER = "#D1D5DB"
COLOR_TEXT_HEADING = "#111111"
COLOR_TEXT_BODY = "#374151"
COLOR_TEXT_CAPTION = "#6B7280"
COLOR_PRIMARY = "#111111"  # Near-black primary brand matching login page
COLOR_PRIMARY_HOVER = "#27272A"
COLOR_TEAL_ACCENT = "#0F766E"
COLOR_TEAL_HOVER = "#115E59"

# Official HuliCAP Brand Tokens (Sampled from Logo via Python Pillow)
# Dominant Blue (monitor outline & "Huli"): #2884D9 (Fallback: #2F7BD0)
# Dominant Orange (padlock & "CAP"): #FFA823 (Fallback: #F5A623)
BRAND_BLUE = "#2884D9"
BRAND_BLUE_DARK = "#1D5FB0"    # Contrast on white: 6.33:1 (WCAG AA > 4.5:1)
BRAND_ORANGE = "#FFA823"
BRAND_ORANGE_DARK = "#B45F06"  # Contrast on white: 4.58:1 (WCAG AA > 4.5:1)
BRAND_BLUE_TINT = "#EAF2FC"
BRAND_ORANGE_TINT = "#FFF4E0"
BRAND_NEAR_BLACK = "#111111"
BRAND_DARK_SURFACE = "#0B0B0C"

# Semantic Chip Palettes (Background, Border, Text)
CHIP_PALETTES: Dict[str, Dict[str, str]] = {
    # Severity Chips
    "critical": {"bg": "#FEF2F2", "border": "#FECACA", "text": "#991B1B"},
    "high": {"bg": "#FFF1F2", "border": "#FFE4E6", "text": "#B91C1C"},
    "medium": {"bg": "#FFFBEB", "border": "#FDE68A", "text": "#B45309"},
    "low": {"bg": "#F1F5F9", "border": "#E2E8F0", "text": "#475569"},
    # Status Chips
    "new": {"bg": "#EFF6FF", "border": "#BFDBFE", "text": "#1D4ED8"},
    "reviewed": {"bg": "#F0FDF4", "border": "#BBF7D0", "text": "#15803D"},
    "escalated": {"bg": "#FEF2F2", "border": "#FECACA", "text": "#991B1B"},
    "dismissed": {"bg": "#F8FAFC", "border": "#E2E8F0", "text": "#64748B"},
    # Platform Chip
    "platform": {"bg": "#F0FDFA", "border": "#99F6E4", "text": "#0F766E"},
}


def get_custom_css(is_superadmin: bool = False) -> str:
    """Generate the unified CSS stylesheet for HuliCAP."""
    from logo_assets import get_icon_white_uri
    icon_white_uri = get_icon_white_uri()
    brand_primary = COLOR_TEAL_ACCENT if is_superadmin else COLOR_PRIMARY
    brand_hover = COLOR_TEAL_HOVER if is_superadmin else COLOR_PRIMARY_HOVER

    return f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/icon?family=Material+Icons');

    :root {{
        --brand-blue: #2884D9;
        --brand-blue-dark: #1D5FB0;
        --brand-orange: #FFA823;
        --brand-orange-dark: #B45F06;
        --brand-blue-tint: #EAF2FC;
        --brand-orange-tint: #FFF4E0;
        --brand-near-black: #111111;
        --brand-dark-surface: #0B0B0C;
    }}

    /* Links: near-black #111111 with underline */
    a, .stMarkdown a, .b2b-link {{
        color: #111111 !important;
        text-decoration: underline !important;
        text-underline-offset: 3px !important;
        font-weight: 600;
        transition: color 0.15s ease !important;
    }}
    a:hover, .stMarkdown a:hover, .b2b-link:hover {{
        color: #374151 !important;
    }}
    a.plan-card-link,
    a.plan-card-link *,
    .plan-card-link h3,
    .plan-card-link p,
    .plan-card-link span,
    .plan-card-link strong,
    .plan-card-link div {{
        text-decoration: none !important;
    }}

    /* Selected filter chips and pills: brand-blue-dark on brand-blue-tint */
    [data-testid="stPill"][aria-selected="true"],
    [data-baseweb="tag"],
    .filter-chip-selected,
    .filter-chip-active {{
        background-color: var(--brand-blue-tint) !important;
        color: var(--brand-blue-dark) !important;
        border: 1px solid var(--brand-blue) !important;
    }}
    [data-testid="stPill"][aria-selected="true"] p,
    [data-testid="stPill"][aria-selected="true"] span,
    [data-baseweb="tag"] span {{
        color: var(--brand-blue-dark) !important;
        font-weight: 600 !important;
    }}

    /* Charts series styling: brand-blue for main series, brand-orange for second */
    svg .mark-bar path:nth-child(1),
    svg .mark-rect path:nth-child(1),
    .vega-embed path.mark-line:nth-child(1),
    .stChart [data-testid="stVegaLiteChart"] svg path:nth-child(1) {{
        fill: var(--brand-blue) !important;
        stroke: var(--brand-blue) !important;
    }}
    svg .mark-bar path:nth-child(2),
    svg .mark-rect path:nth-child(2),
    .vega-embed path.mark-line:nth-child(2),
    .stChart [data-testid="stVegaLiteChart"] svg path:nth-child(2) {{
        fill: var(--brand-orange) !important;
        stroke: var(--brand-orange) !important;
    }}

    /* Global Reset & Typography */
    html, body, [class*="css"], .stApp {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
        background-color: {COLOR_CANVAS} !important;
        color: {COLOR_TEXT_BODY} !important;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }}

    /* Chrome Cleanup: Hide Streamlit Deploy Button, Main Menu, and Footer - Keep Header & Sidebar Controls */
    #MainMenu, footer, .stDeployButton, [data-testid="stDeployButton"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] {{
        display: none !important;
        visibility: hidden !important;
    }}
    header[data-testid="stHeader"] {{
        background: transparent !important;
        height: 0px !important;
        min-height: 0px !important;
        border: none !important;
        visibility: visible !important;
        display: flex !important;
    }}
    header [data-testid="stToolbar"] {{
        visibility: visible !important;
        display: flex !important;
    }}
    /* Hide empty element containers, empty markdown blocks, and zero-height iframes */
    [data-testid="stElementContainer"]:empty,
    [data-testid="stElementContainer"]:has(> [data-testid="stMarkdown"]:empty),
    iframe[height="0"],
    iframe[width="0"] {{
        display: none !important;
        height: 0px !important;
        margin: 0px !important;
        padding: 0px !important;
    }}
    [data-testid="stSidebarCollapseButton"],
    [data-testid="stSidebarCollapseButton"] *,
    [data-testid="stExpandSidebarButton"],
    [data-testid="stExpandSidebarButton"] *,
    button[aria-label="Collapse sidebar"],
    button[aria-label="Expand sidebar"] {{
        visibility: visible !important;
        display: inline-flex !important;
        opacity: 1 !important;
    }}

    /* Typography Scale: Title 28px, Section 18px, Body 15px, Caption 13px */
    h1, .page-title {{
        font-family: 'Inter', sans-serif !important;
        font-size: 28px !important;
        line-height: 36px !important;
        font-weight: 700 !important;
        color: {COLOR_TEXT_HEADING} !important;
        letter-spacing: -0.02em !important;
        margin-top: 0px !important;
        margin-bottom: 8px !important;
    }}

    h2, h3, .section-title {{
        font-family: 'Inter', sans-serif !important;
        font-size: 18px !important;
        line-height: 24px !important;
        font-weight: 600 !important;
        color: {COLOR_TEXT_HEADING} !important;
        letter-spacing: -0.01em !important;
        margin-top: 6px !important;
        margin-bottom: 4px !important;
    }}

    p, .stMarkdown p, [data-testid="stMarkdownContainer"] p {{
        font-size: 15px !important;
        line-height: 22px !important;
        color: {COLOR_TEXT_BODY} !important;
        margin-bottom: 4px !important;
    }}

    .stCaption, .caption, [data-testid="stCaptionContainer"] {{
        font-size: 13px !important;
        line-height: 18px !important;
        color: {COLOR_TEXT_CAPTION} !important;
    }}

    hr {{
        border: none !important;
        border-top: 1px solid {COLOR_BORDER} !important;
        margin: 4px 0 !important;
    }}

    /* Layout Containers & Tight Spatial Grid */
    .block-container {{
        padding-top: 1rem !important;
        padding-bottom: 1.5rem !important;
        padding-left: 2.25rem !important;
        padding-right: 2.25rem !important;
        max-width: 1440px !important;
    }}
    .block-container [data-testid="stVerticalBlock"] {{
        gap: 0.45rem !important;
    }}

    /* Standard Card Surfaces - 16px radius, 1px border, no heavy shadows */
    .b2b-card, .hulicap-card, div[data-testid="stForm"] {{
        background-color: #FFFFFF !important;
        border: 1px solid {COLOR_BORDER} !important;
        border-radius: 16px !important;
        padding: 14px 18px !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04) !important;
        margin-bottom: 6px !important;
    }}
    div[data-testid="stExpander"] {{
        background-color: #FFFFFF !important;
        border: 1px solid {COLOR_BORDER} !important;
        border-radius: 12px !important;
        padding: 0 !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04) !important;
        margin-bottom: 4px !important;
    }}

    /* Alert / Notification Banners (st.info, st.warning, st.success, st.error) */
    [data-testid="stAlert"] div[role="alert"],
    [data-testid="stNotification"] {{
        display: flex !important;
        align-items: center !important;
        padding: 12px 16px !important;
        min-height: 0 !important;
    }}
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"],
    [data-testid="stNotification"] [data-testid="stMarkdownContainer"] {{
        margin: 0 !important;
        padding: 0 !important;
    }}
    [data-testid="stAlert"] p,
    [data-testid="stNotification"] p {{
        margin: 0 !important;
        padding: 0 !important;
        line-height: 20px !important;
    }}

    /* Toast Notifications: right-aligned, single visible toast (never stack/block view) */
    [data-testid="stToastContainer"] {{
        right: 20px !important;
        left: auto !important;
        bottom: 20px !important;
        top: auto !important;
        width: auto !important;
        max-width: 400px !important;
        z-index: 999999 !important;
    }}
    [data-testid="stToastContainer"] > div:not(:last-child) {{
        display: none !important;
    }}
    @keyframes hcToastSlideFade {{
        0% {{
            opacity: 0;
            transform: translateX(24px);
        }}
        8% {{
            opacity: 1;
            transform: translateX(0);
        }}
        84% {{
            opacity: 1;
            transform: translateX(0);
        }}
        100% {{
            opacity: 0;
            transform: translateX(48px);
        }}
    }}
    @keyframes hcToastProgress {{
        0% {{
            transform: scaleX(1);
        }}
        100% {{
            transform: scaleX(0);
        }}
    }}
    [data-testid="stToast"] {{
        position: relative !important;
        background-color: #111111 !important;
        color: #FFFFFF !important;
        border: 1px solid #27272A !important;
        border-radius: 12px !important;
        padding: 14px 18px 17px 18px !important;
        height: auto !important;
        min-height: 48px !important;
        overflow: hidden !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.18) !important;
        animation: hcToastSlideFade 4s cubic-bezier(0.22, 1, 0.36, 1) forwards !important;
    }}
    [data-testid="stToast"]::after {{
        content: "";
        position: absolute;
        left: 0;
        right: 0;
        bottom: 0;
        height: 3px;
        background: linear-gradient(90deg, {BRAND_BLUE}, {BRAND_ORANGE});
        transform-origin: left center;
        animation: hcToastProgress 3.6s linear forwards;
    }}
    [data-testid="stToast"] > div,
    [data-testid="stToast"] [data-testid="stMarkdownContainer"] {{
        height: auto !important;
        overflow: visible !important;
        margin: 0 !important;
        padding: 0 !important;
        display: flex !important;
        align-items: center !important;
    }}
    [data-testid="stToast"] p {{
        color: #FFFFFF !important;
        font-size: 14px !important;
        line-height: 20px !important;
        margin: 0 !important;
        padding: 0 !important;
    }}
    [data-testid="stToast"] * {{
        color: #FFFFFF !important;
    }}

    /* KPI Metric Cards - White cards with 16px radius and 1px #E5E7EB border */
    [data-testid="stMetric"] {{
        background-color: #FFFFFF !important;
        border: 1px solid {COLOR_BORDER} !important;
        border-radius: 16px !important;
        padding: 14px 18px !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04) !important;
        transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
    }}
    [data-testid="stMetric"]:hover {{
        border-color: {COLOR_BORDER_HOVER} !important;
        box-shadow: 0 2px 4px 0 rgba(0, 0, 0, 0.06) !important;
    }}
    [data-testid="stMetricLabel"] {{
        font-size: 11px !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.06em !important;
        color: {COLOR_TEXT_CAPTION} !important;
    }}
    [data-testid="stMetricValue"] {{
        font-size: 28px !important;
        font-weight: 800 !important;
        color: {COLOR_TEXT_HEADING} !important;
        line-height: 36px !important;
        margin-top: 4px !important;
    }}

    /* Data Table Styling (st.dataframe container) */
    [data-testid="stDataFrame"] {{
        border: 1px solid {COLOR_BORDER} !important;
        border-radius: 14px !important;
        overflow: hidden !important;
        background-color: #FFFFFF !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04) !important;
    }}
    [data-testid="stDataFrame"] [role="gridcell"] {{
        font-size: 14px !important;
        line-height: 22px !important;
        color: {COLOR_TEXT_BODY} !important;
        white-space: normal !important;
        word-break: break-word !important;
    }}

    /* Inputs: 12px radius, 48px height, white background, 1px border */
    .stTextInput input,
    .stNumberInput input,
    .stSelectbox div[data-baseweb="select"] > div,
    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input {{
        min-height: 48px !important;
        height: 48px !important;
        border-radius: 12px !important;
        border: 1px solid {COLOR_BORDER} !important;
        background-color: #FFFFFF !important;
        font-size: 14px !important;
        color: {COLOR_TEXT_HEADING} !important;
    }}
    .stTextArea textarea,
    [data-testid="stTextArea"] textarea {{
        border-radius: 12px !important;
        border: 1px solid {COLOR_BORDER} !important;
        background-color: #FFFFFF !important;
        font-size: 14px !important;
        color: {COLOR_TEXT_HEADING} !important;
    }}

    /* Buttons: Primary & Secondary (Near-black #111111 for primary, White for secondary) */
    .stButton > button {{
        min-height: 48px !important;
        height: 48px !important;
        border-radius: 12px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        padding: 10px 20px !important;
        transition: all 0.15s ease-in-out !important;
        border: 1px solid {COLOR_BORDER} !important;
        background-color: #FFFFFF !important;
        color: {COLOR_TEXT_HEADING} !important;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04) !important;
    }}
    .stButton > button:hover {{
        background-color: #111111 !important;
        border-color: #111111 !important;
        color: #FFFFFF !important;
    }}
    .stButton > button:hover * {{
        color: #FFFFFF !important;
    }}
    .stButton > button[kind="primary"],
    .stFormSubmitButton > button[kind="primaryFormSubmit"],
    .stFormSubmitButton > button {{
        background: {brand_primary} !important;
        border: 1px solid {brand_primary} !important;
        color: #FFFFFF !important;
        min-height: 48px !important;
        height: 48px !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        box-shadow: none !important;
        transition: background-color 0.15s ease, transform 0.1s ease !important;
    }}
    .stButton > button[kind="primary"] *,
    .stFormSubmitButton > button * {{
        color: #FFFFFF !important;
        font-weight: 600 !important;
        margin: 0 !important;
    }}
    .stButton > button[kind="primary"]:hover,
    .stFormSubmitButton > button:hover {{
        background: {brand_hover} !important;
        border-color: {brand_hover} !important;
        transform: translateY(-1px);
    }}
    button[data-testid$="FormSubmit"] {{ width: 100% !important; margin-top: 8px; }}
    div:has(> button[data-testid$="FormSubmit"]) {{ width: 100% !important; }}
    [data-testid="stTab"]::after, [data-testid="stTab"]::before, [role="tablist"]::after, [role="tablist"]::before {{ display:none !important; content:none !important; }}
    [data-testid="stFormSubmitButton"], [data-testid="stFormSubmitButton"] > div, div:has(> [data-testid="stFormSubmitButton"]), [data-testid="stElementContainer"]:has([data-testid="stFormSubmitButton"]) {{ width: 100% !important; }}
    [role="tablist"] {{ border-bottom: none !important; box-shadow: none !important; }}
    [data-testid="stTab"] {{ border-bottom: none !important; }}
    [role="tablist"] > div:not([data-testid="stTab"]) {{ display: none !important; }}

    /* ========================================================================= */
    /* LOGIN & AUTH SPLIT-SCREEN LAYOUT & BRAND PANEL                          */
    /* ========================================================================= */

    /* Background for auth page */
    html:has(#login-form-marker),
    body:has(#login-form-marker),
    .stApp:has(#login-form-marker),
    [data-testid="stAppViewContainer"]:has(#login-form-marker),
    [data-testid="stMain"]:has(#login-form-marker) {{
        background-color: #F8FAFC !important;
        min-height: 100vh !important;
    }}

    .stApp:has(#login-form-marker) [data-testid="stSidebar"],
    .stApp:has(#login-form-marker) [data-testid="stSidebarCollapsedControl"],
    .stApp:has(#login-form-marker) header,
    .stApp:has(#login-form-marker) footer,
    .stApp:has(#login-form-marker) #MainMenu,
    .stApp:has(#login-form-marker) .stDeployButton,
    .stApp:has(#login-form-marker) [data-testid="stToolbar"],
    .stApp:has(#login-form-marker) [data-testid="stDecoration"] {{
        display: none !important;
        visibility: hidden !important;
    }}

    .stApp:has(#login-form-marker) .block-container {{
        max-width: 1200px !important;
        padding: 24px 2rem !important;
        height: 100vh !important;
        max-height: 100vh !important;
        min-height: 100vh !important;
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
        box-sizing: border-box !important;
    }}
    .stApp:has(#login-form-marker) .block-container > [data-testid="stVerticalBlock"],
    .stApp:has(#login-form-marker) .block-container > div > [data-testid="stVerticalBlock"] {{
        gap: 0 !important;
        justify-content: center !important;
        flex: 1 !important;
    }}
    .stApp:has(#login-form-marker) .block-container > [data-testid="stVerticalBlock"] > [data-testid="stElementContainer"],
    .stApp:has(#login-form-marker) .block-container > div > [data-testid="stVerticalBlock"] > [data-testid="stElementContainer"] {{
        position: absolute !important;
        width: 0 !important;
        height: 0 !important;
        overflow: hidden !important;
        margin: 0 !important;
        padding: 0 !important;
        pointer-events: none !important;
    }}

    /* Horizontal container holding left form and right brand panel */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) {{
        align-items: center !important;
        min-height: 640px !important;
        gap: 3.5rem !important;
        max-width: 1200px !important;
        width: 100% !important;
        margin: 0 auto !important;
    }}

    /* Left form column */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:first-child {{
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
        align-items: flex-start !important;
        padding: 0.5rem 1rem !important;
    }}

    /* Max width 400px for the left form container elements */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child > div,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:first-child > div {{
        max-width: 400px !important;
        width: 100% !important;
    }}

    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child > div > [data-testid="stVerticalBlock"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:first-child > div > [data-testid="stVerticalBlock"] {{
        gap: 0 !important;
    }}

    /* Form container and all input parent wrappers: transparent background, no shadow or border */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stForm"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stForm"] > div,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child [data-testid="stVerticalBlockBorderWrapper"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child [data-testid="stLayoutWrapper"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child [data-testid="stVerticalBlock"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child [data-testid="stElementContainer"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] > div,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stTextInput,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stTextInput > div,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .react-aria-TextField {{
        border: none !important;
        padding: 0 !important;
        background: transparent !important;
        background-color: transparent !important;
        background-image: none !important;
        box-shadow: none !important;
        outline: none !important;
        max-width: 400px !important;
        width: 100% !important;
        margin-bottom: 0 !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stForm"] [data-testid="stVerticalBlock"] {{
        gap: 0.55rem !important;
    }}

    /* HuliCAP Logo & Brand header on Left Side */
    .login-brand {{
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 32px !important;
    }}
    .login-brand-img {{
        height: 72px !important;
        width: auto !important;
        max-width: 100% !important;
        object-fit: contain !important;
        display: block !important;
    }}

    /* Heading: "Sign in" (28px, bold) */
    .login-heading {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 28px !important;
        font-weight: 700 !important;
        color: #111111 !important;
        line-height: 34px !important;
        letter-spacing: -0.02em;
        margin: 0 0 14px 0 !important;
    }}

    /* Input Field Labels: above inputs */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] label {{
        margin-bottom: 6px !important;
        min-height: auto !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] label p {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        color: #111111 !important;
        line-height: 20px !important;
    }}

    /* Input box container: border, radius, white background, 48px height, flex row */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] div[data-baseweb="input"] {{
        position: relative !important;
        display: flex !important;
        align-items: center !important;
        width: 100% !important;
        max-width: 400px !important;
        height: 48px !important;
        min-height: 48px !important;
        background-color: #FFFFFF !important;
        border: 1px solid #E5E5E5 !important;
        border-radius: 12px !important;
        box-shadow: none !important;
        box-sizing: border-box !important;
        padding: 0 !important;
        margin: 0 !important;
        overflow: hidden !important;
        transition: border-color 0.15s ease !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] [data-testid="stTextInputRootElement"]:focus-within,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] div[data-baseweb="input"]:focus-within {{
        border: 1px solid #111111 !important;
        box-shadow: none !important;
    }}

    /* Eye-icon wrapper inside root element must NOT be width: 100% */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] [data-testid="stTextInputRootElement"] > div,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] div[data-baseweb="input"] > div {{
        width: auto !important;
        flex: 0 0 auto !important;
        display: flex !important;
        align-items: center !important;
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0 !important;
        margin: 0 !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] [data-testid="stTextInputRootElement"] button,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] div[data-baseweb="input"] button {{
        background: transparent !important;
        background-color: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 4px 12px 4px 4px !important;
        margin: 0 !important;
        height: auto !important;
        min-height: 0 !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        cursor: pointer !important;
    }}

    /* Inner <input> element: flex 1, width 100%, transparent bg, no border or shadow */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] input,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stTextInput > div > div > input,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInputField"] {{
        width: 100% !important;
        flex: 1 1 auto !important;
        min-width: 0 !important;
        height: 100% !important;
        min-height: 46px !important;
        background: transparent !important;
        background-color: transparent !important;
        border: none !important;
        border-radius: 0 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 14px !important;
        color: #111111 !important;
        padding-left: 44px !important;
        padding-right: 12px !important;
        box-shadow: none !important;
        box-sizing: border-box !important;
        outline: none !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] input:focus,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stTextInput > div > div > input:focus,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInputField"]:focus {{
        outline: none !important;
        border: none !important;
        box-shadow: none !important;
    }}

    /* Small Icon inside each input (envelope, lock, person, key) */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"]:has(input[aria-label*="Email"]) [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .st-key-login_email [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .st-key-reg_email [data-testid="stTextInputRootElement"] {{
        background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' height='20' viewBox='0 0 24 24' width='20' fill='%238E8E93'><path d='M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z'/></svg>") !important;
        background-repeat: no-repeat !important;
        background-position: left 14px center !important;
    }}

    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"]:has(input[type="password"]) [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .st-key-login_password [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .st-key-reg_password [data-testid="stTextInputRootElement"] {{
        background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' height='20' viewBox='0 0 24 24' width='20' fill='%238E8E93'><path d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z'/></svg>") !important;
        background-repeat: no-repeat !important;
        background-position: left 14px center !important;
    }}

    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"]:has(input[aria-label*="Full Name"]) [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .st-key-reg_name [data-testid="stTextInputRootElement"] {{
        background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' height='20' viewBox='0 0 24 24' width='20' fill='%238E8E93'><path d='M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z'/></svg>") !important;
        background-repeat: no-repeat !important;
        background-position: left 14px center !important;
    }}

    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"]:has(input[aria-label*="Invite Code"]) [data-testid="stTextInputRootElement"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .st-key-reg_invite_code [data-testid="stTextInputRootElement"] {{
        background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' height='20' viewBox='0 0 24 24' width='20' fill='%238E8E93'><path d='M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z'/></svg>") !important;
        background-repeat: no-repeat !important;
        background-position: left 14px center !important;
    }}

    /* Full-width primary button "Sign in", near-black (#111111) with white text, 12px corners, 48px tall */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stFormSubmitButton"] > button,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) button[kind="primaryFormSubmit"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stFormSubmitButton > button {{
        background: #111111 !important;
        background-color: #111111 !important;
        color: #FFFFFF !important;
        border: 1px solid #111111 !important;
        border-radius: 12px !important;
        height: 48px !important;
        min-height: 48px !important;
        width: 100% !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 15px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.12) !important;
        transition: background-color 0.15s ease, transform 0.1s ease !important;
        margin-top: 10px !important;
        margin-bottom: 0 !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stFormSubmitButton"] > button:hover,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stFormSubmitButton > button:hover {{
        background: #222222 !important;
        background-color: #222222 !important;
        border-color: #222222 !important;
        color: #FFFFFF !important;
        transform: translateY(-1px);
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stFormSubmitButton"] > button:active,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stFormSubmitButton > button:active {{
        background: #000000 !important;
        background-color: #000000 !important;
        transform: translateY(0);
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stFormSubmitButton"] > button p,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) .stFormSubmitButton > button p {{
        color: #FFFFFF !important;
        font-weight: 600 !important;
        font-size: 15px !important;
    }}

    /* Footer lines under the button: 20px gap after Sign in button, 8px before forgot line */
    .login-footer {{
        margin-top: 20px !important;
        text-align: left;
    }}
    .login-footer-register,
    .stMarkdown p.login-footer-register,
    [data-testid="stMarkdownContainer"] p.login-footer-register {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 14px !important;
        color: #475569 !important;
        margin: 0 0 8px 0 !important;
        line-height: 20px !important;
    }}
    .login-register-link {{
        color: #111111 !important;
        font-weight: 600 !important;
        text-decoration: underline !important;
        text-underline-offset: 3px !important;
        cursor: pointer;
        transition: color 0.15s ease;
    }}
    .login-register-link:hover {{
        color: #374151 !important;
    }}
    .login-footer-forgot,
    .stMarkdown p.login-footer-forgot,
    [data-testid="stMarkdownContainer"] p.login-footer-forgot {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 14px !important;
        color: #64748B !important;
        margin: 0 !important;
        line-height: 20px !important;
        white-space: nowrap !important;
    }}

    /* Right Side: Brand Panel */
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:last-child,
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:last-child {{
        padding: 0 !important;
        margin: 0 !important;
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:last-child [data-testid="stVerticalBlock"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:last-child [data-testid="stElementContainer"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:last-child [data-testid="stMarkdown"],
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:last-child [data-testid="stMarkdownContainer"] {{
        padding: 0 !important;
        margin: 0 !important;
        gap: 0 !important;
        width: 100% !important;
    }}

    .brand-panel,
    .hc-panel {{
        background: #0B0B0C !important;
        background: linear-gradient(155deg, #18181A 0%, #0B0B0C 100%) !important;
        border-radius: 32px !important;
        height: calc(100vh - 48px) !important;
        min-height: 640px !important;
        position: relative !important;
        overflow: hidden !important;
        display: flex !important;
        flex-direction: column !important;
        padding: 0 !important;
        box-sizing: border-box !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.45) !important;
    }}

    .brand-panel-decorations {{
        position: absolute !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        bottom: 0 !important;
        pointer-events: none !important;
        overflow: hidden !important;
        z-index: 0 !important;
    }}

    .brand-panel-svg {{
        width: 100% !important;
        height: 100% !important;
        object-fit: cover !important;
    }}

    /* Watermark: absolutely positioned layer, width 48%, centered horizontally, top 8%, opacity 0.05 */
    .brand-panel-watermark-wrap {{
        position: absolute !important;
        top: 8% !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        width: 48% !important;
        z-index: 0 !important;
        pointer-events: none !important;
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        padding: 0 !important;
        margin: 0 !important;
    }}

    .brand-panel-watermark-img {{
        width: 100% !important;
        height: auto !important;
        max-width: 100% !important;
        object-fit: contain !important;
        opacity: 0.05 !important;
        filter: none !important;
        pointer-events: none !important;
        display: block !important;
    }}

    .hc-streaks {{
        position: absolute !important;
        top: -10% !important;
        right: -5% !important;
        width: 60% !important;
        height: 70% !important;
        background:
            linear-gradient(115deg, transparent 40%, rgba(255,255,255,0.07) 45%, transparent 50%),
            linear-gradient(115deg, transparent 55%, rgba(255,255,255,0.05) 58%, transparent 62%),
            linear-gradient(115deg, transparent 68%, rgba(255,255,255,0.04) 70%, transparent 73%) !important;
        pointer-events: none !important;
        z-index: 0 !important;
    }}

    .hc-watermark {{
        position: absolute !important;
        top: 4% !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        width: 62% !important;
        height: auto !important;
        object-fit: contain !important;
        opacity: 0.06 !important;
        pointer-events: none !important;
        z-index: 0 !important;
    }}

    /* Content block anchored to bottom with padding 40px and margin-top: auto */
    .brand-panel-content,
    .hc-panel-content {{
        position: relative !important;
        z-index: 1 !important;
        margin-top: auto !important;
        padding: 40px !important;
        width: 100% !important;
        box-sizing: border-box !important;
        display: flex !important;
        flex-direction: column !important;
    }}

    .brand-panel-middle {{
        margin: 0 0 12px 0 !important;
    }}

    .brand-panel-tag,
    .hc-eyebrow {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        letter-spacing: 0.08em !important;
        text-transform: uppercase !important;
        color: #A1A1AA !important;
        line-height: 16px !important;
        margin: 0 0 4px 0 !important;
    }}

    .brand-panel-heading,
    .hc-panel h2,
    .hc-panel [data-testid="stMarkdownContainer"] h2 {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 28px !important;
        font-weight: 700 !important;
        color: #FFFFFF !important;
        line-height: 34px !important;
        letter-spacing: -0.02em !important;
        margin: 4px 0 6px 0 !important;
        padding: 0 !important;
    }}

    .brand-panel-desc,
    .brand-panel [data-testid="stMarkdownContainer"] p,
    .brand-panel p {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 14px !important;
        line-height: 20px !important;
        color: #E4E4E7 !important;
        margin: 0 !important;
    }}

    .hc-panel p,
    .hc-panel [data-testid="stMarkdownContainer"] p {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 14px !important;
        line-height: 20px !important;
        color: #E4E4E7 !important;
        margin: 0 0 12px 0 !important;
    }}

    .brand-panel-card,
    .hc-card {{
        background-color: #3A3A3C !important;
        border-radius: 20px !important;
        padding: 16px 20px !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25) !important;
        margin: 0 !important;
        display: flex !important;
        flex-direction: column !important;
        gap: 4px !important;
    }}

    .privacy-card-title,
    .brand-panel-card h3,
    .hc-card strong {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 16px !important;
        font-weight: 600 !important;
        color: #FFFFFF !important;
        line-height: 22px !important;
        margin: 0 0 4px 0 !important;
        letter-spacing: -0.01em !important;
    }}

    .privacy-card-body,
    .brand-panel-card [data-testid="stMarkdownContainer"] p,
    .brand-panel-card p,
    .hc-card span {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 13.5px !important;
        line-height: 19px !important;
        color: #F4F4F5 !important;
        margin: 0 !important;
    }}

    /* Responsive: below 900px, hide right panel, center form */
    @media (max-width: 900px) {{
        html:has(#login-form-marker),
        body:has(#login-form-marker),
        .stApp:has(#login-form-marker),
        [data-testid="stAppViewContainer"]:has(#login-form-marker),
        [data-testid="stMain"]:has(#login-form-marker),
        .stApp:has(#login-form-marker) .block-container {{
            overflow-y: auto !important;
            height: auto !important;
            max-height: none !important;
        }}
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) {{
            display: flex !important;
            flex-direction: column !important;
            min-height: auto !important;
            height: auto !important;
            max-height: none !important;
            padding-top: 1rem !important;
            gap: 1rem !important;
        }}
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child,
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:first-child {{
            width: 100% !important;
            align-items: center !important;
            padding: 1rem 0 !important;
        }}
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:first-child > div,
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:first-child > div {{
            margin: 0 auto !important;
            max-width: 400px !important;
        }}
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="stColumn"]:last-child,
        div[data-testid="stHorizontalBlock"]:has(#login-form-marker) > div[data-testid="column"]:last-child,
        .brand-panel,
        .hc-panel {{
            display: none !important;
        }}
    }}


    /* Form Inputs (Selectbox, TextInput, TextArea) */
    .stSelectbox > div > div,
    .stTextArea > div > div > textarea {{
        border-radius: 8px !important;
        border: 1px solid {COLOR_BORDER} !important;
        background-color: {COLOR_CANVAS} !important;
        color: {COLOR_TEXT_HEADING} !important;
        font-size: 14px !important;
        padding: 8px 12px !important;
        min-height: 40px !important;
    }}
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus,
    .stTextInput input:focus,
    .stNumberInput input:focus,
    .stTextArea textarea:focus,
    [data-testid="stTextInput"] input:focus,
    [data-testid="stNumberInput"] input:focus,
    [data-testid="stTextArea"] textarea:focus,
    [data-baseweb="select"]:focus-within > div {{
        border: 1px solid #111111 !important;
        box-shadow: 0 0 0 2px rgba(17, 17, 17, 0.08) !important;
        outline: none !important;
    }}
    div[data-testid="stHorizontalBlock"]:has(#login-form-marker) [data-testid="stTextInput"] input:focus {{
        border: 1px solid #111111 !important;
        box-shadow: none !important;
        outline: none !important;
    }}

    /* Empty State Card */
    .empty-state-box {{
        background-color: {COLOR_CARD_SURFACE};
        border: 1px dashed {COLOR_BORDER_HOVER};
        border-radius: 12px;
        padding: 40px 24px;
        text-align: center;
        margin: 20px 0;
    }}
    .empty-state-title {{
        font-size: 16px;
        font-weight: 600;
        color: {COLOR_TEXT_HEADING};
        margin-bottom: 6px;
    }}
    .empty-state-desc {{
        font-size: 14px;
        color: {COLOR_TEXT_CAPTION};
        max-width: 50ch;
        margin: 0 auto;
    }}

    /* Sidebar: Near-black #0B0B0C background with white text, section labels in gray */
    [data-testid="stSidebar"],
    [data-testid="stSidebarContent"],
    [data-testid="stSidebarUserContent"],
    [data-testid="stSidebarHeader"] {{
        background-color: #0B0B0C !important;
        color: #FFFFFF !important;
    }}
    [data-testid="stSidebar"] {{
        border-right: 1px solid #1F1F23 !important;
    }}
    [data-testid="stSidebar"] .block-container {{
        padding: 8px 14px 12px 14px !important;
    }}
    [data-testid="stSidebarUserContent"] {{
        padding-top: 0.25rem !important;
        padding-bottom: 0.75rem !important;
    }}
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{
        gap: 0.35rem !important;
    }}
    [data-testid="stSidebar"] * {{
        color: #FFFFFF;
    }}
    [data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] button {{
        color: #FFFFFF !important;
        background-color: transparent !important;
    }}
    [data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] svg {{
        fill: #FFFFFF !important;
        stroke: #FFFFFF !important;
    }}

    /* Sidebar Brand Header: expanded vs collapsed */
    [data-testid="stSidebar"][aria-expanded="false"] .sidebar-header-expanded {{
        display: none !important;
    }}
    [data-testid="stSidebar"][aria-expanded="false"] .sidebar-header-collapsed {{
        display: flex !important;
    }}
    /* Collapsed sidebar control button at top-left */
    [data-testid="stSidebarCollapsedControl"] {{
        display: block !important;
        visibility: visible !important;
        opacity: 1 !important;
        z-index: 1000 !important;
    }}
    [data-testid="stSidebarCollapsedControl"] button {{
        background-color: #111111 !important;
        border: 1px solid #27272A !important;
        border-radius: 8px !important;
        padding: 4px 8px !important;
        display: inline-flex !important;
        align-items: center !important;
        gap: 6px !important;
        color: #FFFFFF !important;
    }}
    [data-testid="stSidebarCollapsedControl"] button::before {{
        content: '';
        display: inline-block;
        width: 20px;
        height: 20px;
        background-image: url('{icon_white_uri}');
        background-size: contain;
        background-repeat: no-repeat;
        background-position: center;
    }}

    .sidebar-brand-container {{
        padding: 4px 8px 18px 8px;
        border-bottom: 1px solid #1F1F23;
        margin-bottom: 16px;
    }}
    .sidebar-brand-title {{
        font-size: 18px;
        font-weight: 700;
        color: #FFFFFF !important;
        letter-spacing: -0.01em;
        line-height: 22px;
        display: flex;
        align-items: center;
        gap: 8px;
    }}
    .sidebar-brand-sub {{
        font-size: 11px;
        color: #94A3B8 !important;
        margin-top: 4px;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }}

    /* Radio Group in Sidebar (Clean Nav Links with subtle active state) */
    [data-testid="stSidebar"] div[role="radiogroup"] {{
        gap: 2px !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] > div {{
        margin-bottom: 1px !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"] {{
        background-color: transparent !important;
        border-radius: 10px !important;
        padding: 7px 12px !important;
        transition: background-color 0.15s ease, color 0.15s ease !important;
        cursor: pointer !important;
        width: 100% !important;
        display: flex !important;
        align-items: center !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"]:hover {{
        background-color: #1A1A1E !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"]:hover p,
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"]:hover span {{
        color: #FFFFFF !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] div[data-selected="true"] label[data-testid="stRadioOption"] {{
        background-color: #2C2C2E !important;
        border-left: 3px solid #FFFFFF !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"] > div > div:first-child {{
        display: none !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"] p,
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stRadioOption"] span {{
        font-size: 14px !important;
        font-weight: 500 !important;
        color: #D1D5DB !important;
        margin: 0 !important;
        line-height: 20px !important;
        text-decoration: none !important;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] div[data-selected="true"] p,
    [data-testid="stSidebar"] div[role="radiogroup"] div[data-selected="true"] span {{
        color: #FFFFFF !important;
        font-weight: 600 !important;
    }}

    /* Navigation Grouping Section Headers via CSS in small uppercase gray */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(1)::before {{
        content: "INVESTIGATION";
        display: block;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #71717A !important;
        margin-bottom: 4px;
        padding-left: 6px;
    }}
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(4)::before {{
        content: "MANAGEMENT";
        display: block;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #71717A !important;
        margin-top: 10px;
        margin-bottom: 4px;
        padding-left: 6px;
    }}

    /* Sidebar User Profile Card & Logout Button */
    .sidebar-profile-card {{
        background-color: #18181B !important;
        border: 1px solid #27272A !important;
        border-radius: 12px !important;
        padding: 10px 12px !important;
        margin-top: 10px !important;
        margin-bottom: 8px !important;
    }}
    .sidebar-profile-name {{
        font-size: 14px !important;
        font-weight: 600 !important;
        color: #FFFFFF !important;
        line-height: 18px !important;
    }}
    .sidebar-profile-meta {{
        font-size: 12px !important;
        color: #94A3B8 !important;
        margin-top: 4px !important;
    }}
    [data-testid="stSidebar"] .stButton > button {{
        background-color: #1C1C1E !important;
        color: #FFFFFF !important;
        border: 1px solid #3A3A3C !important;
        border-radius: 10px !important;
        min-height: 36px !important;
        font-size: 13px !important;
        font-weight: 600 !important;
    }}
    [data-testid="stSidebar"] .stButton > button * {{
        color: #FFFFFF !important;
    }}
    [data-testid="stSidebar"] .stButton > button:hover {{
        background-color: #2C2C2E !important;
        color: #FFFFFF !important;
        border-color: #4A4A4C !important;
    }}

    /* Mobile Responsive Optimizations */
    @media (max-width: 768px) {{
        .block-container {{
            padding-top: 1.25rem !important;
            padding-bottom: 2rem !important;
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }}
        h1, .page-title {{
            font-size: 24px !important;
            line-height: 32px !important;
        }}
        h2, h3, .section-title {{
            font-size: 17px !important;
            line-height: 24px !important;
            margin-top: 20px !important;
        }}
        .b2b-card {{
            padding: 16px !important;
        }}
        [data-testid="stMetric"] {{
            padding: 16px !important;
        }}
        [data-testid="stMetricValue"] {{
            font-size: 24px !important;
        }}
    }}
    </style>
    """


def clean_html(html_str: str) -> str:
    """Strip all leading and trailing whitespace and empty lines from HTML string to prevent Markdown parser from converting indented HTML into code blocks."""
    if not html_str:
        return ""
    return "".join(line.strip() for line in str(html_str).splitlines() if line.strip())


def render_html(html_str: str, sidebar: bool = False) -> None:
    """Render HTML safely without markdown indentation or code-block interpretation."""
    cleaned = clean_html(html_str)
    if not cleaned:
        return
    if sidebar:
        st.sidebar.markdown(cleaned, unsafe_allow_html=True)
    else:
        st.markdown(cleaned, unsafe_allow_html=True)


def inject_styles(is_superadmin: bool = False) -> None:
    """Inject the unified design system CSS into the current Streamlit page."""
    st.markdown(get_custom_css(is_superadmin=is_superadmin), unsafe_allow_html=True)


def render_severity_chip(severity: str) -> str:
    """Return semantic HTML chip for severity level (text + color dual signaling)."""
    sev_clean = str(severity).strip().lower()
    palette = CHIP_PALETTES.get(sev_clean, CHIP_PALETTES["low"])
    label = sev_clean.upper()
    return clean_html(
        f'<span style="display:inline-flex;align-items:center;padding:3px 9px;'
        f'border-radius:6px;font-size:11px;font-weight:600;letter-spacing:0.05em;'
        f'background-color:{palette["bg"]};border:1px solid {palette["border"]};'
        f'color:{palette["text"]};text-transform:uppercase;">{label}</span>'
    )


def render_status_chip(status: str) -> str:
    """Return semantic HTML chip for alert disposition status."""
    st_clean = str(status).strip().lower()
    palette = CHIP_PALETTES.get(st_clean, CHIP_PALETTES["dismissed"])
    label = st_clean.replace("_", " ").upper()
    return clean_html(
        f'<span style="display:inline-flex;align-items:center;padding:3px 9px;'
        f'border-radius:6px;font-size:11px;font-weight:600;letter-spacing:0.05em;'
        f'background-color:{palette["bg"]};border:1px solid {palette["border"]};'
        f'color:{palette["text"]};text-transform:uppercase;">{label}</span>'
    )


def render_platform_badge() -> str:
    """Return the distinct Platform indicator for super-admin consoles."""
    palette = CHIP_PALETTES["platform"]
    return clean_html(
        f'<span style="display:inline-flex;align-items:center;padding:3px 10px;'
        f'border-radius:6px;font-size:11px;font-weight:700;letter-spacing:0.06em;'
        f'background-color:{palette["bg"]};border:1px solid {palette["border"]};'
        f'color:{palette["text"]};text-transform:uppercase;">Platform</span>'
    )


def render_kpi_card(
    label: str,
    value: Any,
    subtext: Optional[str] = None,
    chip_html: Optional[str] = None,
) -> str:
    """Render a clean B2B KPI card surface with 24px padding and 12px border radius."""
    sub_markup = (
        f'<div style="font-size:13px;color:{COLOR_TEXT_CAPTION};margin-top:4px;">{subtext}</div>'
        if subtext
        else ""
    )
    chip_markup = (
        f'<div style="margin-top:8px;">{chip_html}</div>' if chip_html else ""
    )
    raw = f"""
    <div style="background-color:{COLOR_CARD_SURFACE};border:1px solid {COLOR_BORDER};border-radius:12px;padding:20px 24px;box-shadow:0 1px 3px 0 rgba(15,23,42,0.05);height:100%;display:flex;flex-direction:column;justify-content:space-between;">
        <div>
            <div style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:{COLOR_TEXT_CAPTION};">{label}</div>
            <div style="font-size:28px;font-weight:700;color:{COLOR_TEXT_HEADING};line-height:36px;margin-top:6px;">{value}</div>
            {sub_markup}
        </div>
        {chip_markup}
    </div>
    """
    return clean_html(raw)


def style_severity_cell(val: Any) -> str:
    """Pandas Styler mapping for severity table cells."""
    v = str(val).lower()
    palette = CHIP_PALETTES.get(v, CHIP_PALETTES["low"])
    return f"background-color: {palette['bg']}; color: {palette['text']}; font-weight: 600; border: 1px solid {palette['border']}; border-radius: 6px; padding: 3px 8px; text-transform: uppercase;"


def style_status_cell(val: Any) -> str:
    """Pandas Styler mapping for status table cells."""
    v = str(val).lower()
    palette = CHIP_PALETTES.get(v, CHIP_PALETTES["dismissed"])
    return f"background-color: {palette['bg']}; color: {palette['text']}; font-weight: 600; border: 1px solid {palette['border']}; border-radius: 6px; padding: 3px 8px; text-transform: uppercase;"


def render_sidebar_header(is_superadmin: bool = False) -> None:
    """Render near-black brand header with the official HuliCAP logo.
    
    Shows logo_white.png when expanded, and icon_white.png when collapsed.
    """
    from logo_assets import get_logo_white_uri, get_icon_white_uri
    logo_white_uri = get_logo_white_uri()
    icon_white_uri = get_icon_white_uri()
    badge_html = render_platform_badge() if is_superadmin else ""

    markup = (
        f'<div class="sidebar-brand-wrapper" style="padding:0 0 10px 0;border-bottom:1px solid #1F1F23;margin-bottom:6px;">'
        f'<div class="sidebar-header-expanded" style="display:flex;align-items:center;justify-content:space-between;gap:8px;">'
        f'<img src="{logo_white_uri}" alt="HuliCAP" style="height:81px;width:auto;max-width:100%;object-fit:contain;display:block;" />'
        f'{badge_html}'
        f'</div>'
        f'<div class="sidebar-header-collapsed" style="display:none;justify-content:center;align-items:center;">'
        f'<img src="{icon_white_uri}" alt="HuliCAP" style="width:48px;height:48px;object-fit:contain;display:block;" />'
        f'</div>'
        f'</div>'
    )
    render_html(markup, sidebar=True)


def render_sidebar_profile(
    user_name: str,
    role: str,
    org_name: Optional[str] = None,
    is_superadmin: bool = False,
) -> None:
    """Render a small user card at the bottom of the near-black sidebar (name, role, organization)."""
    role_display = "SUPER ADMIN" if is_superadmin else role.replace("_", " ").upper()
    org_html = f'<div style="color:#71717A;font-size:11px;margin-top:2px;">{org_name}</div>' if org_name else ""
    role_color = "#0F766E" if is_superadmin else "#22C55E"

    markup = (
        f'<div style="background-color:#18181B;border:1px solid #27272A;border-radius:12px;padding:10px 12px;margin-top:10px;margin-bottom:8px;">'
        f'<div style="color:#FFFFFF;font-size:13px;font-weight:600;margin-bottom:3px;word-break:break-word;">{user_name}</div>'
        f'<div style="display:flex;align-items:center;gap:6px;">'
        f'<span style="display:inline-block;width:6px;height:6px;border-radius:50%;background-color:{role_color};"></span>'
        f'<span style="color:#94A3B8;font-size:11px;font-weight:600;letter-spacing:0.04em;">{role_display}</span>'
        f'</div>'
        f'{org_html}'
        f'</div>'
    )
    render_html(markup, sidebar=True)


def render_incident_overview(
    total: int,
    new_count: int,
    under_review_count: int,
    dismissed_count: int,
    severity_counts: Dict[str, int],
) -> None:
    """Render incident overview with one row of 4 compact cards (New is dark #0B0B0C) and severity chips."""
    c1, c2, c3, c4 = st.columns(4, gap="medium")

    with c1:
        render_html(
            f'<div style="background-color:#FFFFFF;border:1px solid #E5E7EB;border-radius:16px;padding:18px 20px;box-shadow:0 1px 2px rgba(0,0,0,0.04);height:100%;">'
            f'<div style="font-size:11px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;">Total Incidents</div>'
            f'<div style="font-size:28px;font-weight:800;color:#111111;line-height:34px;">{total}</div>'
            f'<div style="font-size:12px;color:#9CA3AF;margin-top:4px;">All recorded detections</div>'
            f'</div>'
        )

    with c2:
        # Dark card for "New" like the login brand card
        render_html(
            f'<div style="background-color:#0B0B0C;border:1px solid #27272A;border-radius:16px;padding:18px 20px;box-shadow:0 2px 8px rgba(0,0,0,0.15);height:100%;">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">'
            f'<div style="font-size:11px;font-weight:700;color:#94A3B8;text-transform:uppercase;letter-spacing:0.06em;">New Incidents</div>'
            f'<span style="background-color:#EF4444;color:#FFFFFF;font-size:10px;font-weight:700;padding:1px 6px;border-radius:8px;">ACTION REQ</span>'
            f'</div>'
            f'<div style="font-size:28px;font-weight:800;color:#FFFFFF;line-height:34px;">{new_count}</div>'
            f'<div style="font-size:12px;color:#A1A1AA;margin-top:4px;">Awaiting initial triage</div>'
            f'</div>'
        )

    with c3:
        render_html(
            f'<div style="background-color:#FFFFFF;border:1px solid #E5E7EB;border-radius:16px;padding:18px 20px;box-shadow:0 1px 2px rgba(0,0,0,0.04);height:100%;">'
            f'<div style="font-size:11px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;">Under Review</div>'
            f'<div style="font-size:28px;font-weight:800;color:#111111;line-height:34px;">{under_review_count}</div>'
            f'<div style="font-size:12px;color:#9CA3AF;margin-top:4px;">Active investigation</div>'
            f'</div>'
        )

    with c4:
        render_html(
            f'<div style="background-color:#FFFFFF;border:1px solid #E5E7EB;border-radius:16px;padding:18px 20px;box-shadow:0 1px 2px rgba(0,0,0,0.04);height:100%;">'
            f'<div style="font-size:11px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;">Dismissed</div>'
            f'<div style="font-size:28px;font-weight:800;color:#111111;line-height:34px;">{dismissed_count}</div>'
            f'<div style="font-size:12px;color:#9CA3AF;margin-top:4px;">Closed as false positive</div>'
            f'</div>'
        )

    # Line of severity chips with counts
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)

    render_html(
        f'<div style="background-color:#FFFFFF;border:1px solid #E5E7EB;border-radius:12px;padding:10px 18px;margin-top:14px;margin-bottom:24px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;box-shadow:0 1px 2px rgba(0,0,0,0.03);">'
        f'<span style="font-size:11px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:0.06em;">Severity Breakdown:</span>'
        f'<div style="display:flex;align-items:center;gap:6px;">{render_severity_chip("critical")} <strong style="font-size:13px;color:#111111;">{crit}</strong></div>'
        f'<div style="display:flex;align-items:center;gap:6px;">{render_severity_chip("high")} <strong style="font-size:13px;color:#111111;">{high}</strong></div>'
        f'<div style="display:flex;align-items:center;gap:6px;">{render_severity_chip("medium")} <strong style="font-size:13px;color:#111111;">{med}</strong></div>'
        f'<div style="display:flex;align-items:center;gap:6px;">{render_severity_chip("low")} <strong style="font-size:13px;color:#111111;">{low}</strong></div>'
        f'</div>'
    )


def render_page_header(
    title: str,
    description: str,
    action_label: Optional[str] = None,
    action_key: Optional[str] = None,
    is_superadmin: bool = False,
) -> bool:
    """Render unified dashboard page header with single-line title, one-line description, and optional right-aligned primary action."""
    badge_html = ""
    if is_superadmin:
        badge_html = '<span style="background-color:#0F766E;color:#FFFFFF;font-size:11px;font-weight:700;padding:3px 9px;border-radius:10px;margin-left:12px;letter-spacing:0.04em;text-transform:uppercase;">Platform</span>'

    header_html = (
        f'<div style="margin-bottom:20px;width:100%;">'
        f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:nowrap;">'
        f'<h1 class="page-title" style="margin:0;font-size:28px;font-weight:700;color:#111111;letter-spacing:-0.02em;white-space:nowrap;line-height:36px;">{title}</h1>'
        f'{badge_html}'
        f'</div>'
        f'<div style="color:#6B7280;font-size:14px;margin-top:4px;line-height:20px;">{description}</div>'
        f'</div>'
    )

    if action_label and action_key:
        col_t, col_b = st.columns([5, 1])
        with col_t:
            render_html(header_html)
        with col_b:
            clicked = st.button(action_label, key=action_key, type="primary", use_container_width=True)
            return clicked
    else:
        render_html(header_html)
        return False


def render_page_layout(
    title: str,
    description: str,
    action_label: Optional[str] = None,
    action_key: Optional[str] = None,
    is_superadmin: bool = False,
) -> bool:
    """Shared layout wrapper function for all dashboard pages so layout and typography cannot drift apart."""
    return render_page_header(
        title=title,
        description=description,
        action_label=action_label,
        action_key=action_key,
        is_superadmin=is_superadmin,
    )


def render_stepper(current_step: Any = "Organization", current_step_idx: Optional[int] = None) -> str:
    """Render a clean 3-step setup progress indicator (Organization, Guidelines, Data).
    
    Accepts string ('Organization', 'Guidelines', 'Data') or integer index (0, 1, 2),
    or (steps_list, current_step_idx) for backwards compatibility.
    Returns single-line whitespace-stripped HTML string.
    """
    steps = ["Organization", "Guidelines", "Data"]
    if isinstance(current_step, (list, tuple)):
        steps = list(current_step)
        idx = current_step_idx if current_step_idx is not None else 0
    elif isinstance(current_step, int):
        idx = current_step
    elif isinstance(current_step, str):
        step_map = {
            "organization": 0, "org": 0, "create_org": 0,
            "guidelines": 1, "guideline": 1, "rules": 1,
            "data": 2, "demo": 2, "logs": 2,
        }
        idx = step_map.get(current_step.strip().lower(), 0)
    else:
        idx = 0

    items = []
    for i, name in enumerate(steps):
        is_done = i < idx
        is_current = i == idx
        if is_current:
            circle_bg = "#111111"
            circle_color = "#FFFFFF"
            label_color = "#111111"
            font_weight = "700"
            check_or_num = str(i + 1)
        elif is_done:
            circle_bg = "#111111"
            circle_color = "#FFFFFF"
            label_color = "#4B5563"
            font_weight = "500"
            check_or_num = "&#10003;"
        else:
            circle_bg = "#E5E7EB"
            circle_color = "#6B7280"
            label_color = "#9CA3AF"
            font_weight = "500"
            check_or_num = str(i + 1)
        items.append(
            f'<div style="display:flex;align-items:center;gap:8px;">'
            f'<div style="width:24px;height:24px;border-radius:50%;background-color:{circle_bg};color:{circle_color};display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;">{check_or_num}</div>'
            f'<span style="font-size:13px;font-weight:{font_weight};color:{label_color};white-space:nowrap;">{name}</span>'
            f'</div>'
        )
    divider = '<div style="flex:1;height:1px;background-color:#E5E7EB;margin:0 8px;min-width:16px;"></div>'
    joined = divider.join(items)
    return clean_html(
        f'<div style="display:flex;align-items:center;justify-content:space-between;width:100%;max-width:680px;margin:0 auto 20px auto;padding:12px 0;">{joined}</div>'
    )

