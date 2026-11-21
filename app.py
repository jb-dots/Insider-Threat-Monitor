"""Insider Threat Monitor - Streamlit Web Application Dashboard.

Professional security analyst console with privacy-conscious salted pseudonymization,
role-based access control (RBAC), and immutable audit tracking.
Strictly adheres to corporate light theme and clean typographic standards.
"""

from datetime import datetime, timedelta
import hashlib
import html
import os
from pathlib import Path
import textwrap
import time
from typing import Dict, List, Optional
import pandas as pd
import streamlit as st
from streamlit_cookies_controller import CookieController
import yaml

from config import MAX_EVENTS_PER_UPLOAD, MAX_STAFF_SEATS
from session_config import COOKIE_NAME, IDLE_WARN_SECONDS, IDLE_LOGOUT_SECONDS, SESSION_LIFETIME_HOURS
from db import (
    accept_invite_code,
    add_or_invite_staff,
    authenticate_user,
    cancel_pending_invite,
    check_permission,
    complete_org_setup,
    create_organization,
    create_user_session,
    get_active_org_context,
    get_all_alerts,
    get_alert_by_id,
    get_audit_logs,
    get_last_record_id,
    get_org_alerts,
    get_org_alert_by_id,
    get_org_audit_logs,
    get_org_events_df,
    get_org_pending_invites,
    get_org_portal_url,
    get_org_rules,
    get_org_staff,
    get_platform_audit_logs,
    get_session,
    get_session_by_token,
    get_superadmin_organizations,
    get_superadmin_users,
    get_user_membership,
    has_accepted_guidelines,
    init_db,
    log_audit_event,
    log_org_audit_event,
    log_session_timeout_audit_event,
    record_guideline_acceptance,
    record_log_upload,
    register_user,
    remove_staff_member,
    revoke_session,
    revoke_session_by_token,
    save_org_alerts,
    save_org_events,
    save_org_rule,
    set_org_portal_url,
    touch_session,
    update_alert_review,
    update_incomplete_organization,
    update_org_alert_review,
    update_org_status_by_superadmin,
    update_user_status_by_superadmin,
    DbSession,
    User,
)
from detector import run_detection_pipeline

import importlib
import logo_assets
import styles
importlib.reload(logo_assets)
importlib.reload(styles)

from styles import (
    clean_html,
    inject_styles,
    render_html,
    render_incident_overview,
    render_kpi_card,
    render_page_header,
    render_page_layout,
    render_platform_badge,
    render_severity_chip,
    render_sidebar_header,
    render_sidebar_profile,
    render_status_chip,
    render_stepper,
    style_severity_cell,
    style_status_cell,
    BRAND_BLUE,
    BRAND_BLUE_DARK,
    BRAND_ORANGE,
    BRAND_ORANGE_DARK,
    BRAND_BLUE_TINT,
    BRAND_ORANGE_TINT,
    BRAND_NEAR_BLACK,
    BRAND_DARK_SURFACE,
)
from logo_assets import (
    get_logo_black_uri,
    get_icon_white_uri,
    get_logo_white_uri,
    get_icon_black_uri,
)

# Page configuration
st.set_page_config(
    page_title="HuliCAP - Insider Threat Monitor",
    page_icon="assets/favicon.png",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject corporate design system
inject_styles()


def notify_toast(message: str, rerun_pending: bool = True) -> None:
    """Queue or display a single toast notification, debouncing repeated clicks."""
    now = time.monotonic()
    last = st.session_state.get("_last_toast")
    if last and last[0] == message and (now - last[1]) < 3.0:
        return
    st.session_state["_last_toast"] = (message, now)
    if rerun_pending:
        st.session_state["pending_toast"] = message
    else:
        st.toast(message)


def flush_pending_toast() -> None:
    """Display any queued toast notification once after a rerun."""
    msg = st.session_state.pop("pending_toast", None)
    if msg:
        st.toast(msg)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def set_session_cookie(raw_token: str) -> None:
    """Set persistent browser cookie via client-side JavaScript."""
    import streamlit.components.v1 as components
    max_age_sec = int(SESSION_LIFETIME_HOURS * 3600)
    components.html(
        f"""
        <script>
        const cookieStr = "{COOKIE_NAME}={raw_token}; path=/; max-age={max_age_sec}; SameSite=Lax";
        document.cookie = cookieStr;
        try {{
            if (window.parent && window.parent.document) {{
                window.parent.document.cookie = cookieStr;
            }}
        }} catch (e) {{}}
        </script>
        """,
        height=0,
        width=0,
    )


def clear_session_cookie() -> None:
    """Clear browser cookie via client-side JavaScript."""
    import streamlit.components.v1 as components
    components.html(
        f"""
        <script>
        const cookieStr = "{COOKIE_NAME}=; path=/; max-age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax";
        document.cookie = cookieStr;
        try {{
            if (window.parent && window.parent.document) {{
                window.parent.document.cookie = cookieStr;
            }}
        }} catch (e) {{}}
        </script>
        """,
        height=0,
        width=0,
    )


def get_privacy_salt() -> str:
    """Retrieve secret salt from st.secrets or .streamlit/secrets.toml."""
    try:
        if hasattr(st, "secrets") and "salt" in st.secrets:
            return str(st.secrets["salt"])
    except Exception:
        pass

    secrets_file = Path(".streamlit/secrets.toml")
    if secrets_file.exists():
        try:
            for line in secrets_file.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("salt"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass

    return "insider_threat_monitor_privacy_salt_2026_x89q"


@st.cache_data
def load_all_logs() -> pd.DataFrame:
    """Load and cache the full audit logs for timeline inspection."""
    df = pd.read_csv("logs.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def get_user_id_from_pseudonym(pseudonym: str, logs_df: pd.DataFrame, org_salt: Optional[str] = None) -> Optional[str]:
    """Resolve which real user_id matches the pseudonym using organization salt or global salt."""
    salt = org_salt or get_privacy_salt()
    if not logs_df.empty and "user_id" in logs_df.columns:
        for uid in logs_df["user_id"].unique():
            token = f"USER-{hashlib.sha256(f'{salt}_{uid}'.encode('utf-8')).hexdigest()[:8].upper()}"
            if token == pseudonym:
                return uid

    # Check Dunmore Corp Portal employee directory if available
    portal_db = Path(__file__).resolve().parent.parent / "dunmore_portal" / "portal.db"
    if portal_db.exists():
        import sqlite3
        try:
            conn = sqlite3.connect(portal_db)
            rows = conn.execute("SELECT employee_id, name, department FROM employees").fetchall()
            conn.close()
            for emp_id, name, dept in rows:
                token = f"USER-{hashlib.sha256(f'{salt}_{emp_id}'.encode('utf-8')).hexdigest()[:8].upper()}"
                if token == pseudonym:
                    return f"{emp_id} ({name} — {dept})"
        except Exception:
            pass
    return None


def get_user_timeline(
    logs_df: pd.DataFrame,
    user_id: str,
    alert_time: datetime,
    window_hours: int = 12,
) -> pd.DataFrame:
    """Extract a window of user events around the alert timestamp."""
    user_logs = logs_df[logs_df["user_id"] == user_id].copy()
    start_time = alert_time - timedelta(hours=window_hours)
    end_time = alert_time + timedelta(hours=window_hours)

    window_logs = user_logs[
        (user_logs["timestamp"] >= start_time) & (user_logs["timestamp"] <= end_time)
    ].sort_values("timestamp")

    if len(window_logs) < 10:
        window_logs = user_logs.sort_values("timestamp").tail(50)

    return window_logs


def navigate_to_detail_view(alert_id: str):
    """Callback to switch navigation to Alert Detail view before widgets instantiate."""
    st.session_state["sidebar_nav"] = "Alert Detail"
    st.session_state["selected_alert_id"] = alert_id
    st.session_state["detail_alert_picker"] = alert_id
    notify_toast(f"Opened alert {alert_id}.")


@st.fragment(run_every="2s")
def render_idle_monitor(cookie_ctrl: CookieController):
    """Client-side activity heartbeat checking against server-authoritative DB session."""
    token = st.session_state.get("session_token")
    if not token:
        return

    session_obj = get_session_by_token(token)
    if not session_obj:
        try:
            cookie_ctrl.remove(COOKIE_NAME)
        except Exception:
            pass
        st.session_state.clear()
        st.rerun()
        return

    now = datetime.utcnow()
    last_seen = session_obj.get("last_seen_at_dt")
    if not last_seen:
        last_seen = datetime.strptime(session_obj["last_seen_at"], "%Y-%m-%d %H:%M:%S")

    elapsed = (now - last_seen).total_seconds()

    if elapsed >= IDLE_LOGOUT_SECONDS:
        revoke_session(session_obj["session_id"])
        log_session_timeout_audit_event(session_obj["user_id"])
        try:
            cookie_ctrl.remove(COOKIE_NAME)
        except Exception:
            pass
        clear_session_cookie()
        st.session_state.clear()
        mins = max(1, int(IDLE_LOGOUT_SECONDS // 60))
        if IDLE_LOGOUT_SECONDS >= 60:
            st.session_state["logout_message"] = f"You were signed out after {mins} minutes of inactivity."
        else:
            st.session_state["logout_message"] = f"You were signed out after {int(IDLE_LOGOUT_SECONDS)} seconds of inactivity."
        st.rerun()
        return

    if elapsed >= IDLE_WARN_SECONDS:
        remaining = max(0, int(IDLE_LOGOUT_SECONDS - elapsed))
        mins = remaining // 60
        secs = remaining % 60
        time_str = f"{mins}:{secs:02d}" if IDLE_LOGOUT_SECONDS >= 60 else f"{remaining}s"

        render_html(
            f'<div style="position:fixed; top:24px; left:50%; transform:translateX(-50%); z-index:999999; width:92%; max-width:480px; background-color:#FFFFFF; border:1px solid #E5E7EB; border-top:4px solid {BRAND_ORANGE}; border-radius:16px; padding:22px 24px; box-shadow:0 12px 36px rgba(0,0,0,0.22);">'
            f'<div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">'
            f'<div style="width:10px; height:10px; border-radius:50%; background-color:#EF4444;"></div>'
            f'<div style="font-size:16px; font-weight:700; color:#111111;">Are you still there?</div>'
            f'</div>'
            f'<div style="font-size:14px; color:#4B5563; line-height:1.5; margin-bottom:16px;">'
            f'You have been inactive. For security compliance, your session will automatically terminate in <strong style="color:#111111; font-size:15px;">{time_str}</strong>.'
            f'</div>'
            f'</div>'
        )
        col_w1, col_w2 = st.columns(2)
        with col_w1:
            if st.button("Stay signed in", type="primary", key="btn_stay_signed_in", use_container_width=True):
                touch_session(session_obj["session_id"])
                st.rerun()
        with col_w2:
            if st.button("Sign out now", type="secondary", key="btn_idle_sign_out", use_container_width=True):
                revoke_session(session_obj["session_id"])
                try:
                    cookie_ctrl.remove(COOKIE_NAME)
                except Exception:
                    pass
                st.session_state.clear()
                st.rerun()


def render_alert_queue(alerts: List[Dict]):
    """Page 1: Alert queue with unified overview cards and 10-per-page paginated alert cards."""
    render_page_layout(
        title="Alert Queue",
        description="Review and triage security deviations flagged by the detection engine across monitored infrastructure.",
    )

    if not alerts:
        render_html(
            '<div class="empty-state-box">'
            '<div class="empty-state-title">No Security Alerts</div>'
            '<div class="empty-state-desc">No insider threat deviations have been flagged for this organization yet. Upload new activity logs to trigger detection analysis.</div>'
            '</div>'
        )
        return

    df_alerts = pd.DataFrame(alerts)

    # 1. Incident Overview: 1 row of 4 cards (Total, New [dark #0B0B0C], Under Review, Dismissed) + severity chips
    sev_counts = df_alerts["severity"].str.lower().value_counts().to_dict()
    new_count = int(len(df_alerts[df_alerts["status"] == "new"]))
    under_review_count = int(len(df_alerts[df_alerts["status"].isin(["reviewed", "escalated"])]))
    dismissed_count = int(len(df_alerts[df_alerts["status"] == "dismissed"]))

    render_incident_overview(
        total=len(df_alerts),
        new_count=new_count,
        under_review_count=under_review_count,
        dismissed_count=dismissed_count,
        severity_counts=sev_counts,
    )

    # 2. Filters above the alert card list
    render_html('<div class="section-title">Security Incidents</div>')
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        status_options = ["All"] + sorted(list(df_alerts["status"].unique()))
        selected_status = st.selectbox("Filter by Status", status_options, index=0)

    with col_f2:
        rule_options = ["All"] + sorted(list(df_alerts["rule_id"].unique()))
        selected_rule = st.selectbox("Filter by Rule", rule_options, index=0)

    filtered_df = df_alerts.copy()
    if selected_status != "All":
        filtered_df = filtered_df[filtered_df["status"] == selected_status]
    if selected_rule != "All":
        filtered_df = filtered_df[filtered_df["rule_id"] == selected_rule]

    # Sort by status priority (new -> escalated -> reviewed -> dismissed), then severity, then newest
    status_order = {"new": 0, "escalated": 1, "reviewed": 2, "dismissed": 3}
    filtered_df["status_rank"] = (
        filtered_df["status"].str.lower().map(lambda s: status_order.get(s, 99))
    )
    filtered_df["severity_rank"] = (
        filtered_df["severity"].str.upper().map(lambda s: SEVERITY_ORDER.get(s, 99))
    )
    filtered_df = filtered_df.sort_values(
        by=["status_rank", "severity_rank", "created_at"], ascending=[True, True, False]
    ).drop(columns=["status_rank", "severity_rank"])

    if filtered_df.empty:
        render_html(
            '<div class="empty-state-box">'
            '<div class="empty-state-title">No Matching Alerts</div>'
            '<div class="empty-state-desc">No security alerts match the selected status and rule filters. Adjust your filters above to see more records.</div>'
            '</div>'
        )
        return

    # 3. List of alert cards: 10 per page with Previous and Next buttons
    total_alerts = len(filtered_df)
    per_page = 10
    total_pages = max(1, (total_alerts + per_page - 1) // per_page)

    current_page = st.session_state.get("alert_queue_page", 0)
    if current_page >= total_pages:
        current_page = total_pages - 1
    if current_page < 0:
        current_page = 0
    st.session_state["alert_queue_page"] = current_page

    start_idx = current_page * per_page
    end_idx = min(start_idx + per_page, total_alerts)
    page_records = filtered_df.iloc[start_idx:end_idx].to_dict(orient="records")

    render_html(
        f'<div style="font-size:13px; color:#6B7280; margin: 6px 0 8px 0;">'
        f'Showing {start_idx + 1}–{end_idx} of {total_alerts} incident(s)'
        f'</div>'
    )

    for a in page_records:
        with st.container(border=True):
            col_l, col_r = st.columns([6.5, 1])
            with col_l:
                card_markup = (
                    f'<div style="padding:4px 2px;">'
                    f'<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px;">'
                    f'{render_severity_chip(a["severity"])}'
                    f'<span style="font-weight:700; font-size:14px; color:#111111;">{a["rule_id"]}</span>'
                    f'<span style="color:#9CA3AF; font-size:12px;">•</span>'
                    f'<span style="font-family:monospace; font-size:12px; color:#374151; background-color:#F3F4F6; padding:2px 8px; border-radius:6px; font-weight:600;">{a["user_pseudonym"]}</span>'
                    f'<span style="color:#9CA3AF; font-size:12px;">•</span>'
                    f'{render_status_chip(a["status"])}'
                    f'<span style="color:#9CA3AF; font-size:12px;">•</span>'
                    f'<span style="font-size:12px; color:#6B7280;">{a["created_at"]}</span>'
                    f'</div>'
                    f'<div style="font-size:14px; color:#1F2937; line-height:1.55; word-break:break-word; white-space:normal; margin-bottom:8px;">'
                    f'{html.escape(a["reason"])}'
                    f'</div>'
                    f'<div style="font-size:12px; color:#6B7280; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">'
                    f'<span>Alert ID: <span style="font-family:monospace; font-size:12px; color:#111111; background-color:#F3F4F6; padding:2px 6px; border-radius:4px; font-weight:600;">{a["alert_id"]}</span></span>'
                    f'<span style="color:#D1D5DB;">|</span>'
                    f'<span>Reviewer: <span style="color:#374151; font-weight:500;">{a["reviewer"] or "Unassigned"}</span></span>'
                    f'</div>'
                    f'</div>'
                )
                render_html(card_markup)
            with col_r:
                st.write("")
                st.button(
                    "Open",
                    key=f"btn_open_{a['alert_id']}",
                    type="secondary",
                    use_container_width=True,
                    on_click=navigate_to_detail_view,
                    args=(a["alert_id"],),
                )

    # 4. Pagination Controls
    col_prev, col_info, col_next = st.columns([1, 2, 1])
    with col_prev:
        if st.button("Previous", disabled=(current_page == 0), key="btn_prev_page", use_container_width=True):
            new_page = max(0, current_page - 1)
            st.session_state["alert_queue_page"] = new_page
            notify_toast(f"Loaded page {new_page + 1} of {total_pages}.")
            st.rerun()
    with col_info:
        render_html(
            f'<div style="text-align:center; padding-top:10px; font-size:13px; font-weight:600; color:#4B5563;">'
            f'Page {current_page + 1} of {total_pages} ({total_alerts} incidents)'
            f'</div>'
        )
    with col_next:
        if st.button("Next", disabled=(current_page >= total_pages - 1), key="btn_next_page", use_container_width=True):
            new_page = min(total_pages - 1, current_page + 1)
            st.session_state["alert_queue_page"] = new_page
            notify_toast(f"Loaded page {new_page + 1} of {total_pages}.")
            st.rerun()


def render_alert_detail(
    alerts: List[Dict],
    org_id: str,
    active_role: str,
    user_id: str,
    org_salt: Optional[str] = None,
):
    """Page 2: Alert detail with event timeline, re-identification controls, and triage notes."""
    render_page_layout(
        title="Alert Detail & Investigation",
        description="Deep-dive into event timeline, reason metadata, and triage disposition.",
    )

    if not alerts:
        st.info("No alerts found in the database. Run detector.py to generate alerts.")
        return

    status_order = {"new": 0, "escalated": 1, "reviewed": 2, "dismissed": 3}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (
            status_order.get(str(a.get("status", "")).lower(), 99),
            SEVERITY_ORDER.get(str(a.get("severity", "")).upper(), 99),
            str(a.get("created_at", "")),
        ),
    )

    counts = {
        k: sum(1 for a in sorted_alerts if str(a.get("status", "")).lower() == k)
        for k in ("new", "escalated", "reviewed", "dismissed")
    }
    active_count = counts["new"] + counts["escalated"]
    filter_options = [
        ("active", f"Active — New & Escalated ({active_count})"),
        ("all", f"All Alerts ({len(sorted_alerts)})"),
        ("new", f"New ({counts['new']})"),
        ("escalated", f"Escalated ({counts['escalated']})"),
        ("reviewed", f"Reviewed ({counts['reviewed']})"),
        ("dismissed", f"Dismissed ({counts['dismissed']})"),
    ]
    filter_labels = dict(filter_options)

    preselected_id = st.session_state.pop("selected_alert_id", None)
    if preselected_id:
        pre_alert = next((a for a in sorted_alerts if a["alert_id"] == preselected_id), None)
        if pre_alert:
            pre_status = str(pre_alert.get("status", "")).lower()
            st.session_state["detail_status_filter"] = "active" if pre_status in ("new", "escalated") else pre_status

    if "detail_status_filter" not in st.session_state:
        st.session_state["detail_status_filter"] = "active" if active_count > 0 else "all"

    col_f, col_a = st.columns([1, 2.2])
    with col_f:
        selected_filter = st.selectbox(
            "Filter Queue",
            options=[k for k, _ in filter_options],
            format_func=lambda k: filter_labels[k],
            key="detail_status_filter",
        )

    if selected_filter == "active":
        visible_alerts = [a for a in sorted_alerts if str(a.get("status", "")).lower() in ("new", "escalated")]
    elif selected_filter == "all":
        visible_alerts = sorted_alerts
    else:
        visible_alerts = [a for a in sorted_alerts if str(a.get("status", "")).lower() == selected_filter]

    if not visible_alerts:
        st.info(f"No alerts in **{filter_labels[selected_filter]}**.")
        return

    visible_ids = [a["alert_id"] for a in visible_alerts]
    if preselected_id in visible_ids:
        st.session_state["detail_alert_picker"] = preselected_id
    elif st.session_state.get("detail_alert_picker") not in visible_ids:
        st.session_state["detail_alert_picker"] = visible_ids[0]

    alert_lookup = {a["alert_id"]: a for a in visible_alerts}
    with col_a:
        selected_id = st.selectbox(
            "Select Alert",
            options=visible_ids,
            format_func=lambda aid: (
                f"[{alert_lookup[aid]['severity'].upper()}] {alert_lookup[aid]['rule_id']} · "
                f"{alert_lookup[aid]['user_pseudonym']} · {alert_lookup[aid]['status'].upper()} ({aid})"
            ),
            key="detail_alert_picker",
        )

    alert = get_org_alert_by_id(selected_id, org_id)
    if not alert:
        st.error("Alert not found.")
        return

    # Write every alert view into audit_log with org_id and user_id
    last_view_key = f"last_viewed_alert_{org_id}_{user_id}"
    if st.session_state.get(last_view_key) != selected_id:
        log_org_audit_event(
            org_id=org_id,
            user_id=user_id,
            action="VIEW_ALERT",
            target=selected_id,
            justification=f"Alert viewed in investigation console by {active_role}",
        )
        st.session_state[last_view_key] = selected_id

    # Alert Overview Card
    with st.container(border=True):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            render_html(
                f'<div style="font-size:11px; font-weight:700; color:#6B7280; text-transform:uppercase;">Alert ID & Severity</div>'
                f'<div style="font-size:16px; font-weight:700; color:#111111; margin: 4px 0;">{alert["alert_id"]}</div>'
                f'<div>{render_severity_chip(alert["severity"])}</div>'
            )
        with c2:
            render_html(
                f'<div style="font-size:11px; font-weight:700; color:#6B7280; text-transform:uppercase;">Rule & Status</div>'
                f'<div style="font-size:15px; font-weight:600; color:#111111; margin: 4px 0;">{alert["rule_id"]}</div>'
                f'<div>{render_status_chip(alert["status"])}</div>'
            )
        with c3:
            render_html(
                f'<div style="font-size:11px; font-weight:700; color:#6B7280; text-transform:uppercase;">Subject Pseudonym</div>'
                f'<div style="font-family:monospace; font-size:14px; font-weight:700; color:#111111; margin: 4px 0; background-color:#F3F4F6; padding:3px 8px; border-radius:6px; display:inline-block;">{alert["user_pseudonym"]}</div>'
                f'<div style="font-size:12px; color:#6B7280; margin-top:4px;">{alert["created_at"]}</div>'
            )
        with c4:
            notes_prev = alert['reviewer_notes'] or 'None'
            render_html(
                f'<div style="font-size:11px; font-weight:700; color:#6B7280; text-transform:uppercase;">Triage Reviewer</div>'
                f'<div style="font-size:14px; font-weight:600; color:#111111; margin: 4px 0;">{alert["reviewer"] or "Unassigned"}</div>'
                f'<div style="font-size:12px; color:#6B7280;">Notes: {notes_prev[:35]}...</div>'
            )

        render_html(
            f'<div style="border-top:1px solid #E5E7EB; padding:12px 16px; margin-top:8px; box-sizing:border-box; width:100%;">'
            f'<div style="font-size:11px; font-weight:700; color:#475569; text-transform:uppercase; margin-bottom:4px;">Reason & Observed Anomalies</div>'
            f'<div style="font-size:14px; color:#1E293B; line-height:1.5; word-break:break-word;">{html.escape(alert["reason"])}</div>'
            f'</div>'
        )

    # Re-Identification Section (RBAC controlled)
    st.markdown("---")
    st.subheader("User Identity & De-anonymization")

    logs_df = load_all_logs()
    real_user_id = get_user_id_from_pseudonym(alert["user_pseudonym"], logs_df, org_salt=org_salt)

    deanon_key = f"deanon_{alert['alert_id']}"
    is_revealed = st.session_state.get(deanon_key, False)

    # Privacy Rule: Analysts strictly see pseudonyms; cannot see real ID even if deanon flag is present
    if active_role != "analyst" and is_revealed and real_user_id:
        st.success(
            f"De-anonymized User ID: `{real_user_id}` | "
            f"Audit Record: Re-identification authorized and logged to audit trail.",
        )
    else:
        if active_role == "analyst":
            st.warning(
                f"Privacy Lock Active (Analyst Role): User is displayed as pseudonym `{alert['user_pseudonym']}`. "
                "Analysts are restricted to pseudonyms only and cannot request re-identification.",
            )
        elif active_role in ["reviewer", "org_admin", "admin"]:
            with st.expander("Request Re-Identification (Written Justification Required)"):
                st.write(
                    "De-anonymizing an employee record requires a formal written justification "
                    "(e.g., HR investigation reference, legal ticket, or executive authorization)."
                )
                justification_input = st.text_area(
                    "Written Justification for De-Anonymization:",
                    placeholder="E.g., Authorized by HR Ticket #4829 for forensic insider threat review.",
                    key=f"just_{alert['alert_id']}",
                )

                if st.button("Authorize & Reveal Real User ID", type="primary"):
                    # Server-side permission check inside button handler
                    allowed, err = check_permission(active_role, "request_reidentification")
                    if not allowed:
                        st.error(f"Action Blocked: {err}")
                    elif not justification_input.strip():
                        st.error("Justification cannot be blank. A formal reason is mandatory.")
                    else:
                        log_org_audit_event(
                            org_id=org_id,
                            user_id=user_id,
                            action="RE_IDENTIFY_USER",
                            target=alert["alert_id"],
                            justification=justification_input.strip(),
                        )
                        st.session_state[deanon_key] = True
                        notify_toast(f"Re-identification authorized for {alert['alert_id']} and logged.")
                        st.rerun()

    # Timeline of User Activity
    st.markdown("---")
    st.subheader("Activity Timeline Around Alert")

    alert_time = pd.to_datetime(alert["created_at"])
    org_events_df = get_org_events_df(org_id)
    timeline_df = pd.DataFrame()

    if not org_events_df.empty:
        org_events_df["timestamp"] = pd.to_datetime(org_events_df["timestamp"])
        if not org_events_df[org_events_df["user_id"] == alert["user_pseudonym"]].empty:
            timeline_df = get_user_timeline(
                org_events_df, alert["user_pseudonym"], alert_time, window_hours=12
            )

    if timeline_df.empty and real_user_id:
        timeline_df = get_user_timeline(logs_df, real_user_id, alert_time, window_hours=12)

    if not timeline_df.empty:
        flagged_ids = set(alert["event_ids"].split(","))
        timeline_df["is_flagged_event"] = timeline_df["event_id"].apply(
            lambda x: "FLAGGED" if x in flagged_ids else "Normal"
        )

        render_html(
            f'<div style="font-size:13px;color:#64748B;padding:4px 0 12px 0;">'
            f'Showing {len(timeline_df)} activity events around {alert["created_at"]} for {alert["user_pseudonym"]} (Metadata Only):'
            f'</div>'
        )

        show_tech_timeline = st.checkbox(
            "Show technical details", value=False, key=f"timeline_tech_{alert['alert_id']}"
        )

        display_tl = timeline_df.copy()
        display_tl["What Happened"] = display_tl.apply(_format_live_event_summary, axis=1)
        display_tl["Flagged"] = display_tl["is_flagged_event"].apply(
            lambda v: "Flagged" if v == "FLAGGED" else "Normal"
        )
        display_tl["Location"] = display_tl["resource"].apply(
            lambda r: "Windows Sign-In" if r == "auth/windows_logon" else r
        )
        display_tl["Origin"] = display_tl["source_ip"].apply(
            lambda ip: "This computer (local)" if str(ip).strip() in ("::1", "127.0.0.1", "") else str(ip)
        )
        display_tl["Status"] = display_tl["outcome"].apply(
            lambda o: "Blocked" if str(o).lower() in ("denied", "failure") else "Allowed"
        )

        if show_tech_timeline:
            cols_to_show = [
                "timestamp",
                "Flagged",
                "What Happened",
                "Location",
                "sensitivity",
                "bytes",
                "device",
                "source_ip",
                "Status",
            ]
        else:
            cols_to_show = ["timestamp", "Flagged", "What Happened", "Location", "Origin", "Status"]

        st.dataframe(
            display_tl[cols_to_show],
            width="stretch",
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
            },
        )
    else:
        st.warning("Could not associate pseudonym with logs timeline.")

    # Reviewer Triage Action Section
    st.markdown("---")
    st.subheader("Analyst Triage & Investigation Disposition")

    current_notes = alert["reviewer_notes"] or ""
    notes_input = st.text_area(
        "Investigation Notes & Rationale:",
        value=current_notes,
        placeholder="Enter investigative findings, employee contact notes, or justification for status update...",
        height=100,
        key=f"notes_input_{alert['alert_id']}",
    )

    b_col1, b_col2, b_col3, b_col4 = st.columns(4)

    with b_col1:
        if st.button("Mark as Reviewed", width="stretch"):
            allowed, err = check_permission(active_role, "triage_review")
            if not allowed:
                st.error(f"Action Blocked: {err}")
            else:
                update_org_alert_review(
                    alert["alert_id"],
                    org_id=org_id,
                    status="reviewed",
                    reviewer_notes=notes_input,
                    reviewer=f"{active_role}_user",
                    role=active_role,
                )
                log_org_audit_event(
                    org_id=org_id,
                    user_id=user_id,
                    action="UPDATE_ALERT_STATUS",
                    target=alert["alert_id"],
                    justification=f"Changed status to REVIEWED. Notes: {notes_input[:50]}",
                )
                notify_toast(f"Alert {alert['alert_id']} marked as REVIEWED.")
                st.rerun()

    with b_col2:
        # Server-side check inside button handler; button also disabled for analysts
        if st.button("Escalate to Tier 2", width="stretch", disabled=(active_role == "analyst")):
            allowed, err = check_permission(active_role, "triage_escalate")
            if not allowed:
                st.error(f"Action Blocked: {err}")
            else:
                update_org_alert_review(
                    alert["alert_id"],
                    org_id=org_id,
                    status="escalated",
                    reviewer_notes=notes_input,
                    reviewer=f"{active_role}_user",
                    role=active_role,
                )
                log_org_audit_event(
                    org_id=org_id,
                    user_id=user_id,
                    action="UPDATE_ALERT_STATUS",
                    target=alert["alert_id"],
                    justification=f"Changed status to ESCALATED. Notes: {notes_input[:50]}",
                )
                notify_toast(f"Alert {alert['alert_id']} escalated to Tier 2.")
                st.rerun()

    with b_col3:
        if st.button("Dismiss as False Positive", width="stretch"):
            allowed, err = check_permission(active_role, "triage_dismiss")
            if not allowed:
                st.error(f"Action Blocked: {err}")
            else:
                update_org_alert_review(
                    alert["alert_id"],
                    org_id=org_id,
                    status="dismissed",
                    reviewer_notes=notes_input,
                    reviewer=f"{active_role}_user",
                    role=active_role,
                )
                log_org_audit_event(
                    org_id=org_id,
                    user_id=user_id,
                    action="UPDATE_ALERT_STATUS",
                    target=alert["alert_id"],
                    justification=f"Changed status to DISMISSED. Notes: {notes_input[:50]}",
                )
                notify_toast(f"Alert {alert['alert_id']} dismissed as false positive.")
                st.rerun()

    with b_col4:
        if st.button("Save Notes Only", width="stretch"):
            allowed, err = check_permission(active_role, "save_notes")
            if not allowed:
                st.error(f"Action Blocked: {err}")
            else:
                update_org_alert_review(
                    alert["alert_id"],
                    org_id=org_id,
                    status=alert["status"],
                    reviewer_notes=notes_input,
                    reviewer=alert["reviewer"] or f"{active_role}_user",
                    role=active_role,
                )
                log_org_audit_event(
                    org_id=org_id,
                    user_id=user_id,
                    action="UPDATE_NOTES",
                    target=alert["alert_id"],
                    justification="Updated analyst investigation notes",
                )
                notify_toast(f"Investigation notes saved for {alert['alert_id']}.")
                st.rerun()


def render_rules_page(org_id: str, active_role: str, user_id: str):
    """Page 3: Rules configuration editor (Org Admin only)."""
    render_page_layout(
        title="Detection Rules Configuration",
        description="Inspect and tune organization-specific detection thresholds.",
    )

    # Access Control Enforcement: org_admin required
    allowed, err = check_permission(active_role, "view_rules")
    if not allowed:
        st.error(f"Access Denied: Only organization administrators can view and edit detection rules. ({err})")
        return

    # Load organization rules from database
    org_rules = get_org_rules(org_id, role=active_role)
    if not org_rules:
        rules_path = Path("rules.yaml")
        current_yaml_text = rules_path.read_text(encoding="utf-8") if rules_path.exists() else "rules: []"
    else:
        current_yaml_text = yaml.dump({"rules": [{"rule_id": k, "thresholds": v} for k, v in org_rules.items()]}, sort_keys=False)

    st.warning("Admin Authority: Changes made here alter detection thresholds specifically for your organization.")

    justification_rule = st.text_input(
        "Administrative Justification for Rule Modification:",
        placeholder="E.g., Lowering bulk_access threshold per Q4 threat model review.",
    )

    edited_yaml = st.text_area(
        "YAML Configuration Content:",
        value=current_yaml_text,
        height=380,
    )

    if st.button("Save & Apply Rule Changes", type="primary"):
        # Server-side check inside button handler
        allowed, err = check_permission(active_role, "edit_rules")
        if not allowed:
            st.error(f"Action Blocked: {err}")
            return

        if not justification_rule.strip():
            st.error("Justification cannot be blank. Administrative updates must be accounted for.")
            return

        try:
            parsed = yaml.safe_load(edited_yaml)
            if not isinstance(parsed, dict) or "rules" not in parsed:
                st.error("Invalid YAML structure: Root must contain a 'rules' list.")
                return

            for r in parsed.get("rules", []):
                save_org_rule(org_id, r["rule_id"], r.get("thresholds", {}), role=active_role)

            log_org_audit_event(
                org_id=org_id,
                user_id=user_id,
                action="UPDATE_RULES",
                target=f"org_rules:{org_id}",
                justification=justification_rule.strip(),
            )
            notify_toast("Organization rules updated and audited.")
            st.rerun()
        except Exception as e:
            st.error(f"Failed to parse YAML: {e}")


def _format_live_event_summary(row: pd.Series) -> str:
    """Translate raw event action/outcome into plain-English text for non-technical users."""
    action = str(row.get("action", "")).lower()
    outcome = str(row.get("outcome", "")).lower()
    if action == "login":
        if outcome in ("denied", "failure"):
            return "Failed sign-in attempt (wrong password or unknown user)"
        return "Signed in to this computer"
    if action == "read":
        return "Opened or read a file/folder"
    if action == "delete":
        return "Deleted a file or folder"
    return f"{action.replace('_', ' ').title()} ({outcome})"


def render_live_events_page(org_id: str):
    """Real-time Windows Security Event Log stream from monitor.db."""
    render_page_layout(
        title="Live Activity Feed",
        description="Real-time sign-ins and file activity recorded from this computer.",
    )

    c_toggle, c_act, c_out, c_tech, c_sync = st.columns([1.1, 1, 1, 1, 0.9])
    with c_toggle:
        auto_refresh = st.toggle("Auto-refresh (every 5s)", value=True, key="live_events_auto_refresh")
    with c_act:
        action_label = st.selectbox(
            "Activity Type",
            ["All Activity", "Sign-Ins", "File Reads", "File Deletions"],
            key="live_events_action",
        )
    with c_out:
        outcome_label = st.selectbox(
            "Status",
            ["All", "Allowed", "Blocked"],
            key="live_events_outcome",
        )
    with c_tech:
        show_technical = st.checkbox("Show technical details", value=False, key="live_events_tech")
    with c_sync:
        st.write("")
        manual_sync = st.button("🔄 Sync Portal", use_container_width=True, key="live_events_sync_btn")

    action_map = {"Sign-Ins": "login", "File Reads": "read", "File Deletions": "delete"}
    outcome_map = {"Allowed": "success", "Blocked": "denied"}

    render_html('<div style="height:12px;"></div>')

    def _render_live_body():
        if auto_refresh or manual_sync:
            try:
                from collector import collect_company_portal_once, load_collector_config
                c_cfg = load_collector_config()
                org_portal_url = get_org_portal_url(org_id) or c_cfg.get("company_portal_url", "")
                if c_cfg.get("enable_company_portal") and (org_portal_url or c_cfg["company_portal_log_path"].exists()):
                    collect_company_portal_once(org_id=org_id, run_detector=True, portal_url=org_portal_url)
            except Exception:
                pass

        df_win = get_org_events_df(org_id, source="windows_event_log")
        df_portal = get_org_events_df(org_id, source="company_portal")
        frames = [d for d in (df_portal, df_win) if not d.empty]
        df_live = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        if not df_live.empty and "timestamp" in df_live.columns:
            df_live = df_live.sort_values("timestamp", ascending=False).reset_index(drop=True)

        win_last_id = get_last_record_id(org_id, source="windows_event_log")
        portal_last_id = get_last_record_id(org_id, source="company_portal")
        last_rec_id = max(win_last_id, portal_last_id)

        total_ev = len(df_live)
        failed_logins = int((df_live["action"].isin(["login", "login_failed"]) & (df_live["outcome"] == "denied")).sum()) if total_ev else 0
        file_ops = int(df_live["action"].isin(["read", "download", "export", "delete"]).sum()) if total_ev else 0
        monitor_status = "Active" if last_rec_id > 0 else "Waiting"

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            render_html(render_kpi_card("Total Activity", f"{total_ev:,}", "Recorded events"))
        with k2:
            render_html(render_kpi_card("Failed Sign-Ins", f"{failed_logins:,}", "Wrong password / blocked"))
        with k3:
            render_html(render_kpi_card("File Activity", f"{file_ops:,}", "Files opened or deleted"))
        with k4:
            render_html(render_kpi_card("Live Monitor", monitor_status, f"Checkpoint #{last_rec_id:,}"))

        render_html('<div class="section-title" style="padding-top:16px;padding-bottom:4px;">Recent Activity</div>')

        if df_live.empty:
            st.info(
                "No live activity recorded yet for this organization. "
                "Start `collector.py` as Administrator to begin streaming events."
            )
            return

        filtered = df_live.copy()
        if action_label in action_map:
            filtered = filtered[filtered["action"] == action_map[action_label]]
        if outcome_label in outcome_map:
            filtered = filtered[filtered["outcome"] == outcome_map[outcome_label]]

        filtered = filtered.sort_values("timestamp", ascending=False).head(200).copy()
        filtered["What Happened"] = filtered.apply(_format_live_event_summary, axis=1)
        filtered["Status"] = filtered["outcome"].apply(
            lambda o: "Blocked" if str(o).lower() in ("denied", "failure") else "Allowed"
        )
        filtered["Location"] = filtered["resource"].apply(
            lambda r: "Windows Sign-In" if r == "auth/windows_logon" else r
        )
        filtered["Origin"] = filtered["source_ip"].apply(
            lambda ip: "This computer (local)" if str(ip).strip() in ("::1", "127.0.0.1", "") else str(ip)
        )

        render_html(
            f'<div style="font-size:13px;color:#64748B;padding:2px 0 12px 0;">'
            f'Showing {len(filtered):,} of {total_ev:,} event(s) (newest first, user names protected). '
            f'Updated at {datetime.now().strftime("%I:%M:%S %p")}'
            f'</div>'
        )

        if show_technical:
            cols = [
                "timestamp",
                "What Happened",
                "user_id",
                "role",
                "Location",
                "sensitivity",
                "device",
                "source_ip",
                "Status",
            ]
        else:
            cols = ["timestamp", "What Happened", "user_id", "Location", "Origin", "Status"]

        st.dataframe(
            filtered[cols],
            width="stretch",
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
                "user_id": st.column_config.TextColumn("User (Protected ID)"),
            },
        )

    if auto_refresh:
        @st.fragment(run_every=5)
        def _live_fragment():
            _render_live_body()
        _live_fragment()
    else:
        if st.button("Refresh Now", type="secondary"):
            st.rerun()
        _render_live_body()


def render_audit_trail_page(org_id: str, active_role: str):
    """Page 4: Tamper-evident audit trail table for the organization (Org Admin only)."""
    render_page_layout(
        title="Security Audit Trail",
        description="Immutable log of all alert reviews, user re-identifications, and rule changes for this organization.",
    )

    allowed, err = check_permission(active_role, "view_audit_trail")
    if not allowed:
        st.error(f"Access Denied: Only organization administrators can view the audit trail. ({err})")
        return

    logs = get_org_audit_logs(org_id, role=active_role)
    if not logs:
        st.info("No audit entries recorded for your organization yet.")
        return

    df_audit = pd.DataFrame(logs)

    # Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_html(render_kpi_card("Total Events", len(df_audit), "All audit records"))
    with c2:
        render_html(render_kpi_card("Alert Views", len(df_audit[df_audit["action"] == "VIEW_ALERT"]), "Console triage actions"))
    with c3:
        render_html(render_kpi_card("Re-Identifications", len(df_audit[df_audit["action"] == "RE_IDENTIFY_USER"]), "Privileged de-anonymizations"))
    with c4:
        render_html(render_kpi_card("Rule Updates", len(df_audit[df_audit["action"] == "UPDATE_RULES"]), "Detection threshold changes"))

    # Action Filter
    actions_available = ["All"] + sorted(list(df_audit["action"].unique()))
    selected_act = st.selectbox("Filter by Audit Action", actions_available)

    filtered_audit = df_audit.copy()
    if selected_act != "All":
        filtered_audit = filtered_audit[filtered_audit["action"] == selected_act]

    st.dataframe(
        filtered_audit,
        width="stretch",
        hide_index=True,
    )


def render_staff_page(org_context: Dict, user_id: str):
    """Page: Staff management and member invitations (Org Admin only)."""
    render_page_layout(
        title="Staff Management",
        description="Manage security staff members, roles, and invitation codes for your organization.",
    )

    org_id = org_context["org_id"]
    active_role = org_context["role"]

    # Role enforcement: org_admin only
    allowed, err = check_permission(active_role, "invite_staff")
    if not allowed:
        st.error(f"Access Denied: Only organization administrators can manage staff. ({err})")
        return

    # Staff Seats Overview (fixed limit from config.py)
    staff_members = get_org_staff(org_id, role=active_role)
    pending_invites = get_org_pending_invites(org_id, role=active_role)

    active_count = len(staff_members)
    pending_count = len(pending_invites)
    total_assigned = active_count + pending_count
    available_seats = max(0, MAX_STAFF_SEATS - total_assigned)

    m1, m2, m3 = st.columns(3)
    m1.metric("Active Staff Members", active_count)
    m2.metric("Pending Invites", pending_count)
    m3.metric("Available Seats", f"{available_seats} / {MAX_STAFF_SEATS}")
    st.caption(f"Up to {MAX_STAFF_SEATS} staff seats per organization.")

    st.markdown("---")

    # Add or Invite Staff Form
    st.subheader("Add or Invite Staff Member")
    st.caption("Add an existing platform user by email or generate a one-time invitation code.")

    col_add1, col_add2, col_add3 = st.columns([3, 2, 2])
    with col_add1:
        staff_email = st.text_input("Staff Email Address", placeholder="analyst@yourcompany.com", key="add_staff_email")
    with col_add2:
        staff_role = st.selectbox("Assigned Role", ["analyst", "reviewer"], key="add_staff_role")
    with col_add3:
        st.write("")
        st.write("")
        add_btn = st.button("Add or Invite Staff", type="primary", key="btn_add_staff")

    if add_btn:
        if not staff_email.strip():
            st.error("Please enter a valid email address.")
        else:
            try:
                res, add_err = add_or_invite_staff(
                    org_id=org_id,
                    email=staff_email.strip(),
                    assign_role=staff_role,
                    admin_role=active_role,
                )
                if add_err:
                    st.error(add_err)
                else:
                    if res["type"] == "added":
                        log_org_audit_event(
                            org_id=org_id,
                            user_id=user_id,
                            action="ADD_STAFF",
                            target=res["email"],
                            justification=f"Added existing user {res['email']} as {res['role']}",
                        )
                        notify_toast(f"Added {res['email']} as {res['role'].upper()}.")
                        st.rerun()
                    else:
                        log_org_audit_event(
                            org_id=org_id,
                            user_id=user_id,
                            action="INVITE_STAFF",
                            target=res["email"],
                            justification=f"Generated invite code for {res['email']} as {res['role']}",
                        )
                        notify_toast(f"Invitation created for {res['email']} (Code: {res['code']}).")
                        st.rerun()
            except PermissionError as pe:
                st.error(f"Action Blocked: {pe}")

    st.markdown("---")

    # Active Staff Members Table
    st.subheader("Active Staff Members")
    if staff_members:
        df_staff = pd.DataFrame(staff_members)
        st.dataframe(
            df_staff[["full_name", "email", "role", "status", "created_at"]],
            column_config={
                "full_name": st.column_config.TextColumn("Full Name", width=180),
                "email": st.column_config.TextColumn("Email Address", width=220),
                "role": st.column_config.TextColumn("Role", width=110),
                "status": st.column_config.TextColumn("Account Status", width=120),
                "created_at": st.column_config.TextColumn("Registered At", width=160),
            },
            width="stretch",
            hide_index=True,
        )

        # Removal Controls
        removable_staff = [s for s in staff_members if s["user_id"] != user_id]
        if removable_staff:
            with st.expander("Remove Staff Member"):
                st.caption("Remove a staff member's access from your organization.")
                remove_options = {s["user_id"]: f"{s['full_name']} ({s['email']}) - {s['role']}" for s in removable_staff}
                selected_remove_id = st.selectbox(
                    "Select staff member to remove:",
                    options=list(remove_options.keys()),
                    format_func=lambda uid: remove_options[uid],
                    key="select_remove_staff_id",
                )

                if st.button("Remove Selected Staff", type="secondary", key="btn_remove_staff"):
                    try:
                        ok, rem_err = remove_staff_member(
                            org_id=org_id,
                            target_user_id=selected_remove_id,
                            requesting_user_id=user_id,
                            admin_role=active_role,
                        )
                        if rem_err:
                            st.error(rem_err)
                        else:
                            log_org_audit_event(
                                org_id=org_id,
                                user_id=user_id,
                                action="REMOVE_STAFF",
                                target=selected_remove_id,
                                justification=f"Removed staff member {remove_options[selected_remove_id]} from organization",
                            )
                            notify_toast("Staff member removed from organization.")
                            st.rerun()
                    except PermissionError as pe:
                        st.error(f"Action Blocked: {pe}")
        else:
            st.caption("No other staff members in this organization yet.")
    else:
        st.info("No staff members found.")

    # Pending Invites Table
    if pending_invites:
        st.markdown("---")
        st.subheader("Pending Invitations")
        st.caption("These users have not yet registered with their one-time invite code.")

        df_inv = pd.DataFrame(pending_invites)
        st.dataframe(
            df_inv[["email", "role", "code", "created_at"]],
            column_config={
                "email": st.column_config.TextColumn("Invited Email", width=220),
                "role": st.column_config.TextColumn("Role", width=110),
                "code": st.column_config.TextColumn("One-Time Code", width=160),
                "created_at": st.column_config.TextColumn("Invited At", width=160),
            },
            width="stretch",
            hide_index=True,
        )

        with st.expander("Cancel Pending Invitation"):
            inv_cancel_opts = {inv["invite_id"]: f"{inv['email']} (Code: {inv['code']})" for inv in pending_invites}
            selected_cancel_id = st.selectbox(
                "Select invite to cancel:",
                options=list(inv_cancel_opts.keys()),
                format_func=lambda iid: inv_cancel_opts[iid],
                key="select_cancel_invite_id",
            )
            if st.button("Cancel Selected Invite", type="secondary", key="btn_cancel_invite"):
                ok, cancel_err = cancel_pending_invite(org_id, selected_cancel_id, active_role)
                if cancel_err:
                    st.error(cancel_err)
                else:
                    log_org_audit_event(
                        org_id=org_id,
                        user_id=user_id,
                        action="CANCEL_INVITE",
                        target=selected_cancel_id,
                        justification="Cancelled pending invitation",
                    )
                    notify_toast("Pending invitation cancelled.")
                    st.rerun()


REQUIRED_COLUMNS = [
    "event_id",
    "timestamp",
    "user_id",
    "role",
    "action",
    "resource",
    "sensitivity",
    "bytes",
    "device",
    "source_ip",
    "outcome",
]


def render_upload_logs_page(org_context: Dict, user_id: str):
    """Page: Upload audit logs, validate columns/types, enforce upload limits, and run detector."""
    render_page_layout(
        title="Upload Telemetry Logs",
        description="Import audit event logs for baseline modeling and threat anomaly detection.",
    )

    org_id = org_context["org_id"]
    org_salt = org_context["org_salt"]

    # Role enforcement: org_admin only
    allowed, err = check_permission(org_context.get("role"), "upload_logs")
    if not allowed:
        st.error(f"Access Denied: Only organization administrators can upload logs. ({err})")
        return

    st.info(f"Up to {MAX_EVENTS_PER_UPLOAD:,} events per upload.")

    # 1. Sample CSV Download
    sample_csv = (
        "event_id,timestamp,user_id,role,action,resource,sensitivity,bytes,device,source_ip,outcome\n"
        "ev_0001,2026-10-15 09:12:00,usr_001,engineer,read,repo/backend_api.git,medium,12400,DEV-CORP-001,10.0.10.101,success\n"
        "ev_0002,2026-10-15 09:15:30,usr_002,sales,read,crm/lead_pipeline.csv,medium,8500,DEV-CORP-002,10.0.11.102,success\n"
        "ev_0003,2026-10-15 09:20:10,usr_003,analyst,download,db/analytics_warehouse.sql,high,1250000,DEV-CORP-003,10.0.12.103,success\n"
        "ev_0004,2026-10-15 09:25:40,usr_004,hr,read,portal/employee_directory.xlsx,low,4500,DEV-CORP-004,10.0.13.104,success\n"
    )
    st.download_button(
        label="Download Sample CSV Template",
        data=sample_csv,
        file_name="sample_audit_telemetry.csv",
        mime="text/csv",
    )

    st.markdown("---")

    col1, col2 = st.columns([3, 2])

    with col1:
        st.subheader("Upload Custom CSV")
        uploaded_file = st.file_uploader(
            "Select an audit log CSV file:",
            type=["csv"],
            key="custom_log_uploader",
        )

        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                st.write(f"File loaded: `{uploaded_file.name}` ({len(df):,} rows)")

                # Validate required columns
                missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
                if missing_cols:
                    st.error(
                        f"Validation Failed: Missing required column(s): {', '.join(missing_cols)}. "
                        "Please verify your file format matches the sample template."
                    )
                elif len(df) > MAX_EVENTS_PER_UPLOAD:
                    st.error(
                        f"Upload Limit Exceeded: Your file contains {len(df):,} events, which exceeds "
                        f"the limit of {MAX_EVENTS_PER_UPLOAD:,} events per upload."
                    )
                else:
                    # Validate types
                    try:
                        parsed_ts = pd.to_datetime(df["timestamp"], errors="coerce")
                        if parsed_ts.isna().sum() > len(df) * 0.1:
                            st.error("Validation Failed: Column 'timestamp' contains invalid datetime formats.")
                        else:
                            df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype(int)

                            if st.button("Process & Ingest Uploaded Telemetry", type="primary"):
                                with st.spinner("Ingesting logs and executing detection engine..."):
                                    upload_id = record_log_upload(org_id, user_id, uploaded_file.name, len(df))
                                    inserted_count = save_org_events(df, org_id, upload_id, org_salt)

                                    # Run detector for this org only
                                    org_rules = get_org_rules(org_id)
                                    alerts = run_detection_pipeline(df, org_id, org_rules, org_salt)
                                    save_org_alerts(alerts, org_id)

                                    notify_toast(
                                        f"Ingested {inserted_count:,} events; {len(alerts)} alert(s) generated."
                                    )
                                    st.rerun()
                    except Exception as e:
                        st.error(f"Data type validation error: {e}")
            except Exception as e:
                st.error(f"Failed to read CSV: {e}")

    with col2:
        st.subheader("Load Demo Dataset")
        st.caption(
            "Generates baseline enterprise activity plus injected threat scenarios, "
            "scoped exclusively to this organization with your private organizational salt."
        )

        demo_file = Path("logs.csv")
        if demo_file.exists():
            if st.button("Load Demo Dataset & Run Engine", type="secondary"):
                with st.spinner("Loading demo dataset and running detection engine..."):
                    demo_df = pd.read_csv("logs.csv")

                    # Enforce upload limit on demo dataset
                    if len(demo_df) > MAX_EVENTS_PER_UPLOAD:
                        demo_df = demo_df.head(MAX_EVENTS_PER_UPLOAD)

                    upload_id = record_log_upload(org_id, user_id, "demo_dataset.csv", len(demo_df))
                    inserted_count = save_org_events(demo_df, org_id, upload_id, org_salt)

                    # Run detector for this organization only
                    org_rules = get_org_rules(org_id)
                    alerts = run_detection_pipeline(demo_df, org_id, org_rules, org_salt)
                    save_org_alerts(alerts, org_id)

                    notify_toast(
                        f"Demo dataset loaded ({inserted_count:,} events); {len(alerts)} alert(s) flagged."
                    )
                    st.rerun()
        else:
            st.warning("logs.csv not found on server.")


def render_auth_page(cookie_ctrl: Optional[CookieController] = None):
    """Render split-screen sign in and registration page with dark brand panel."""
    if cookie_ctrl is None:
        cookie_ctrl = CookieController()

    auth_mode = st.query_params.get("auth", "signin")
    col_form, col_panel = st.columns([1, 1], gap="large")

    with col_form:
        render_html('<div id="login-form-marker"></div>')

        # Inform user if logged out due to inactivity or account suspension
        if "logout_message" in st.session_state:
            st.warning(st.session_state["logout_message"])

        logo_black_uri = get_logo_black_uri()

        if auth_mode == "register":
            render_html(
                f'<div class="login-brand">'
                f'<img src="{logo_black_uri}" alt="HuliCAP" class="login-brand-img" />'
                f'</div>'
                f'<h1 class="login-heading">Register</h1>'
            )

            with st.form("register_form"):
                full_name = st.text_input("Full Name", key="reg_name")
                reg_email = st.text_input("Email Address", key="reg_email")
                reg_password = st.text_input(
                    "Password (minimum 8 characters)",
                    type="password",
                    key="reg_password",
                    help="Must contain at least 8 characters",
                )
                invite_code = st.text_input(
                    "One-Time Invite Code (Optional)",
                    key="reg_invite_code",
                    placeholder="E.g., INV-1A2B3C4D",
                    help="Enter the code provided by your organization administrator to join directly.",
                )
                reg_submitted = st.form_submit_button("Register Account", type="primary")

                if reg_submitted:
                    user, err = register_user(full_name, reg_email, reg_password)
                    if err:
                        st.error(err)
                    else:
                        if invite_code.strip():
                            inv_res, inv_err = accept_invite_code(invite_code.strip(), user["user_id"], reg_email)
                            if inv_err:
                                st.warning(f"Account created, but invite code could not be redeemed: {inv_err}")
                            else:
                                log_org_audit_event(
                                    org_id=inv_res["org_id"],
                                    user_id=user["user_id"],
                                    action="ACCEPT_INVITE",
                                    target=reg_email,
                                    justification=f"User registered with one-time code and joined organization as {inv_res['role']}",
                                )
                        sess_dict, raw_token = create_user_session(user["user_id"])
                        try:
                            cookie_ctrl.set(COOKIE_NAME, raw_token, max_age=SESSION_LIFETIME_HOURS * 3600)
                        except Exception:
                            pass
                        st.session_state["logged_in_user"] = user
                        st.session_state["session_token"] = raw_token
                        st.session_state["session_id"] = sess_dict["session_id"]
                        st.success("Account created successfully! Logging you in...")
                        st.rerun()

            render_html(
                '<div class="login-footer">'
                '<p class="login-footer-register">Already have an account? <a href="?auth=signin" target="_self" class="login-register-link">Sign in</a></p>'
                '</div>'
            )

        else:
            render_html(
                f'<div class="login-brand">'
                f'<img src="{logo_black_uri}" alt="HuliCAP" class="login-brand-img" />'
                f'</div>'
                f'<h1 class="login-heading">Sign in</h1>'
            )

            with st.form("login_form"):
                email = st.text_input("Email Address", key="login_email")
                password = st.text_input("Password", type="password", key="login_password")
                submitted = st.form_submit_button("Sign in", type="primary")

                if submitted:
                    if not email or not password:
                        st.error("Please enter both email and password.")
                    else:
                        user, err = authenticate_user(email, password)
                        if err:
                            st.error(err)
                        else:
                            sess_dict, raw_token = create_user_session(user["user_id"])
                            try:
                                cookie_ctrl.set(COOKIE_NAME, raw_token, max_age=SESSION_LIFETIME_HOURS * 3600)
                            except Exception:
                                pass
                            st.session_state["logged_in_user"] = user
                            st.session_state["session_token"] = raw_token
                            st.session_state["session_id"] = sess_dict["session_id"]
                            st.rerun()

            render_html(
                '<div class="login-footer">'
                '<p class="login-footer-register">Don\'t have an account? <a href="?auth=register" target="_self" class="login-register-link">Register</a></p>'
                '<p class="login-footer-forgot">Forgot your password? Contact your organization admin.</p>'
                '</div>'
            )

    with col_panel:
        icon_white_uri = get_icon_white_uri()
        render_html(
            f'<div class="hc-panel">'
            f'<div class="hc-streaks"></div>'
            f'<img class="hc-watermark" src="{icon_white_uri}" alt="">'
            f'<div class="hc-panel-content">'
            f'<div class="hc-eyebrow">HULICAP</div>'
            f'<h2>Welcome to HuliCAP</h2>'
            f'<p>Insider threat monitoring that flags deviations for human review. Metadata only, pseudonyms by default.</p>'
            f'<div class="hc-card"><strong>Built for privacy</strong><span>Every alert view and re-identification request is recorded in an audit trail.</span></div>'
            f'</div>'
            f'</div>'
        )



def render_setup_page(logged_user: Dict, org_context: Optional[Dict] = None):
    """3-step 'Set up your account' flow for new org admins before entering the dashboard."""
    # Security check: if org already exists, only its org_admin may complete setup
    if org_context is not None and org_context.get("role") != "org_admin":
        st.error("Your organization administrator has not completed account setup yet.")
        return

    if "setup_step" not in st.session_state or st.session_state["setup_step"] not in [1, 2, 3]:
        st.session_state["setup_step"] = 1

    step = st.session_state["setup_step"]
    step_names = {1: "Organization", 2: "Guidelines", 3: "Data"}
    industries = ["Education", "Finance", "Healthcare", "Government", "Other"]

    _, col_center, _ = st.columns([1, 4, 1])

    with col_center:
        render_html(
            '<div style="margin-bottom:8px;">'
            '<h1 class="page-title" style="margin:0 0 4px 0;">Set up your account</h1>'
            '<div class="caption">Complete these three steps to configure your organization workspace.</div>'
            '</div>'
        )
        render_html(render_stepper(step_names[step]))

        if step == 1:
            render_html(
                '<div style="margin-bottom:18px;">'
                '<h2 class="section-title" style="margin:0 0 4px 0;">1. Organization Details</h2>'
                '<div class="caption">Enter your organization name and optional industry classification.</div>'
                '</div>'
            )

            default_name = org_context.get("name", "") if org_context else st.session_state.get("setup_org_name", "")
            existing_ind = org_context.get("industry", "") if org_context else st.session_state.get("setup_org_industry", "")
            default_idx = industries.index(existing_ind) if existing_ind in industries else None

            org_name = st.text_input(
                "Organization Name (2 to 80 characters)",
                value=default_name,
                max_chars=80,
                placeholder="E.g., Apex Financial Technologies",
                key="setup_org_name_input",
            )
            industry = st.selectbox(
                "Industry (Optional)",
                industries,
                index=default_idx,
                placeholder="Select an industry (optional)",
                key="setup_org_industry_select",
            )

            st.write("")
            _, col_next = st.columns([2, 1])
            with col_next:
                if st.button("Next", type="primary", use_container_width=True, key="setup_step1_next"):
                    clean_name = (org_name or "").strip()
                    clean_ind = (industry or "").strip()
                    if len(clean_name) < 2 or len(clean_name) > 80:
                        st.error("Organization name must be between 2 and 80 characters.")
                    else:
                        if org_context is None:
                            created, err = create_organization(
                                name=clean_name,
                                industry=clean_ind,
                                creator_user_id=logged_user["user_id"],
                                setup_completed=False,
                            )
                        else:
                            created, err = update_incomplete_organization(
                                org_id=org_context["org_id"],
                                user_id=logged_user["user_id"],
                                name=clean_name,
                                industry=clean_ind,
                            )
                        if err:
                            st.error(err)
                        else:
                            st.session_state["setup_org_name"] = clean_name
                            st.session_state["setup_org_industry"] = clean_ind
                            st.session_state["setup_step"] = 2
                            st.rerun()

        elif step == 2:
            render_html(
                '<div style="margin-bottom:18px;">'
                '<h2 class="section-title" style="margin:0 0 4px 0;">2. Community Guidelines</h2>'
                '<div class="caption">Review and confirm the platform data safety and compliance rules.</div>'
                '</div>'
            )

            guidelines_card_html = (
                '<div style="border: 1px solid #CBD5E1; border-radius: 12px; background-color: #FFFFFF; padding: 22px 24px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(15,23,42,0.04);">'
                '<div style="font-size: 15px; font-weight: 700; color: #0F172A; margin-bottom: 12px; letter-spacing: -0.01em;">'
                'Platform Compliance & Data Safety Rules (v1.0)'
                '</div>'
                '<div style="color: #0F172A; font-size: 14px; line-height: 24px;">'
                '<p style="margin: 0 0 10px 0; color: #0F172A;"><strong>1. Synthetic & Approved Data Only:</strong> Use synthetic or authorized test logs only. Never import production credentials or live corporate secrets.</p>'
                '<p style="margin: 0 0 10px 0; color: #0F172A;"><strong>2. Zero Real Personal Data:</strong> Never import real employee names, government IDs, credit cards, or personal PII.</p>'
                '<p style="margin: 0 0 10px 0; color: #0F172A;"><strong>3. Metadata Only (No File Contents):</strong> Strictly log telemetry and file activity metadata; never upload actual file contents or payloads.</p>'
                '<p style="margin: 0 0 10px 0; color: #0F172A;"><strong>4. Strict Cross-Tenant Isolation:</strong> Do not probe, query, or attempt to access another organization\'s telemetry or alerts.</p>'
                f'<p style="margin: 0 0 10px 0; color: #0F172A;"><strong>5. Platform Usage Limits:</strong> Up to {MAX_EVENTS_PER_UPLOAD:,} events per upload and up to {MAX_STAFF_SEATS} staff seats per organization.</p>'
                '<p style="margin: 0; color: #0F172A;"><strong>6. Account Suspension Policy:</strong> Telemetry tampering or unauthorized re-identification requests result in immediate suspension or permanent ban.</p>'
                '</div>'
                '</div>'
            )
            render_html(guidelines_card_html)

            guidelines_path = Path("guidelines.md")
            if guidelines_path.exists():
                with st.expander("Read Complete Community Guidelines Document (guidelines.md)"):
                    st.markdown(guidelines_path.read_text(encoding="utf-8"))

            agreed = st.checkbox(
                "I understand this app is for synthetic or approved demo data only",
                key="setup_guidelines_checkbox",
            )

            st.write("")
            col_back, col_next = st.columns([1, 2])
            with col_back:
                if st.button("Back", type="secondary", use_container_width=True, key="setup_step2_back"):
                    st.session_state["setup_step"] = 1
                    st.rerun()
            with col_next:
                if st.button("Next", type="primary", disabled=not agreed, use_container_width=True, key="setup_step2_next"):
                    record_guideline_acceptance(logged_user["user_id"], version="v1.0")
                    st.session_state["setup_step"] = 3
                    st.rerun()

        else:
            render_html(
                '<div style="margin-bottom:18px;">'
                '<h2 class="section-title" style="margin:0 0 4px 0;">3. Initial Telemetry Data</h2>'
                '<div class="caption">Choose whether to populate your workspace with synthetic demo telemetry or upload logs later.</div>'
                '</div>'
            )

            if "setup_data_choice" not in st.session_state:
                st.session_state["setup_data_choice"] = "demo"

            choice = st.session_state["setup_data_choice"]
            data_options = [
                (
                    "demo",
                    "Load demo data",
                    "Generate synthetic enterprise activity with injected insider threat scenarios and run the detector for your organization.",
                ),
                (
                    "portal",
                    "Connect company portal",
                    "Stream live audit events from the Dunmore Corp Portal (company_audit.jsonl) and run detection on portal activity.",
                ),
                (
                    "later",
                    "I'll upload logs later",
                    "Start with an empty workspace and upload your own CSV telemetry logs from the Upload Logs page whenever ready.",
                ),
            ]

            cols = st.columns(3, gap="medium")
            for idx, (opt_key, opt_title, opt_desc) in enumerate(data_options):
                is_selected = (choice == opt_key)
                border = "2px solid #111111" if is_selected else "1px solid #E5E7EB"
                shadow = "box-shadow: 0 4px 12px rgba(0,0,0,0.08);" if is_selected else "box-shadow: 0 1px 3px rgba(0,0,0,0.04);"
                badge = '<span style="flex-shrink:0;background-color:#111111;color:#FFFFFF;font-size:11px;font-weight:700;padding:3px 9px;border-radius:12px;">SELECTED</span>' if is_selected else ""
                with cols[idx]:
                    # Fixed height keeps all three cards (and the buttons below them) aligned
                    render_html(
                        f'<div style="box-sizing:border-box;height:240px;overflow:hidden;border:{border};border-radius:12px;padding:20px 22px;background-color:#FFFFFF;{shadow}margin-bottom:16px;">'
                        f'<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:12px;min-height:48px;">'
                        f'<h3 style="margin:0;padding:0;color:#111111;font-size:17px;font-weight:700;line-height:24px;">{opt_title}</h3>'
                        f'{badge}'
                        f'</div>'
                        f'<p style="margin:0;font-size:14px;color:#475569;line-height:21px;">{opt_desc}</p>'
                        f'</div>'
                    )
                    if st.button(
                        "Selected" if is_selected else "Select",
                        key=f"setup_data_btn_{opt_key}",
                        type="primary" if is_selected else "secondary",
                        use_container_width=True,
                    ):
                        st.session_state["setup_data_choice"] = opt_key
                        st.rerun()

            portal_url_input = ""
            if choice == "portal":
                st.write("")
                default_portal_url = os.environ.get("COMPANY_PORTAL_URL", "")
                portal_url_input = st.text_input(
                    "Company Portal URL (or leave blank for local file)",
                    value=st.session_state.get("setup_portal_url", default_portal_url),
                    placeholder="https://dunmore-portal-sample-web.onrender.com",
                    help="Paste your deployed company portal URL (e.g. https://dunmore-portal-sample-web.onrender.com) or full /app/static/company_audit.jsonl URL.",
                    key="setup_portal_url_input",
                )
                st.session_state["setup_portal_url"] = portal_url_input

            render_html('<div style="height:20px;"></div>')
            col_back, col_finish = st.columns([1, 2], gap="medium")
            with col_back:
                if st.button("Back", type="secondary", use_container_width=True, key="setup_step3_back"):
                    st.session_state["setup_step"] = 2
                    st.rerun()
            with col_finish:
                if st.button("Finish setup", type="primary", use_container_width=True, key="setup_finish_btn"):
                    # Always derive org_id from DB session, never from a form field
                    live_org, live_err = get_active_org_context(logged_user["user_id"])
                    if live_err or not live_org:
                        st.error("Unable to verify organization from session. Please restart setup.")
                    elif live_org.get("role") != "org_admin":
                        st.error("Access Denied: Only the organization admin can finish setup.")
                    else:
                        target_org_id = live_org["org_id"]
                        target_org_salt = live_org["org_salt"]

                        if choice == "demo":
                            with st.spinner("Generating synthetic demo logs and running threat detector..."):
                                from generate_logs import build_user_directory, generate_normal_logs, inject_scenarios
                                normal_df = generate_normal_logs(days=30)
                                users_dir = build_user_directory()
                                injected_df, _ = inject_scenarios(users_dir)
                                demo_df = (
                                    pd.concat([normal_df, injected_df], ignore_index=True)
                                    .sort_values(by="timestamp")
                                    .reset_index(drop=True)
                                )

                                if len(demo_df) > MAX_EVENTS_PER_UPLOAD:
                                    demo_df = demo_df.head(MAX_EVENTS_PER_UPLOAD)

                                upload_id = record_log_upload(target_org_id, logged_user["user_id"], "demo_dataset.csv", len(demo_df))
                                save_org_events(demo_df, target_org_id, upload_id, target_org_salt)
                                org_rules = get_org_rules(target_org_id)
                                alerts = run_detection_pipeline(demo_df, target_org_id, org_rules, target_org_salt)
                                save_org_alerts(alerts, target_org_id)
                        elif choice == "portal":
                            with st.spinner("Connecting company portal audit log and running initial detection..."):
                                from collector import collect_company_portal_once, load_collector_config
                                cfg = load_collector_config()
                                raw_url = (portal_url_input or "").strip()
                                if raw_url and not raw_url.startswith(("http://", "https://")):
                                    raw_url = "https://" + raw_url
                                if raw_url and not raw_url.endswith(".jsonl"):
                                    raw_url = raw_url.rstrip("/") + "/app/static/company_audit.jsonl"
                                if raw_url:
                                    set_org_portal_url(target_org_id, raw_url)
                                collect_company_portal_once(
                                    org_id=target_org_id,
                                    log_path=cfg["company_portal_log_path"],
                                    run_detector=True,
                                    portal_url=raw_url or None,
                                )

                        data_choice_label = {
                            "demo": "Load demo data",
                            "portal": "Connect company portal",
                            "later": "Upload logs later",
                        }.get(choice, "Upload logs later")

                        ok, finish_err = complete_org_setup(
                            org_id=target_org_id,
                            user_id=logged_user["user_id"],
                            data_choice=data_choice_label,
                        )
                        if not ok:
                            st.error(finish_err)
                        else:
                            st.session_state.pop("setup_step", None)
                            st.session_state.pop("setup_data_choice", None)
                            st.session_state.pop("setup_org_name", None)
                            st.session_state.pop("setup_org_industry", None)
                            st.session_state["setup_success_msg"] = "Account setup complete! Your organization workspace is ready."
                            st.rerun()


def render_superadmin_console(logged_user: Dict, cookie_ctrl: Optional[CookieController] = None):
    """Platform Super-Admin Console: Global oversight, metadata, and user/org lifecycle controls."""
    if not logged_user.get("is_super_admin"):
        st.error("Access Denied: Super-admin authority required.")
        return

    if cookie_ctrl is None:
        cookie_ctrl = CookieController()

    # Super-admin view uses distinct dark teal accent and visible Platform indicators
    inject_styles(is_superadmin=True)

    render_sidebar_header(is_superadmin=True)

    sa_pages = ["Organizations", "Users", "Platform Audit Trail"]
    if "sa_nav" not in st.session_state or st.session_state["sa_nav"] not in sa_pages:
        st.session_state["sa_nav"] = "Organizations"

    selected_sa_page = st.sidebar.radio("Platform Administration", sa_pages, key="sa_nav", label_visibility="collapsed")

    render_html(
        '<div style="background-color:#18181B;border:1px solid #27272A;border-radius:10px;padding:10px 12px;margin-top:10px;font-size:12px;color:#A1A1AA;">'
        '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">'
        '<span style="color:#71717A;">Access Scope</span>'
        '<span style="font-weight:600;color:#FFFFFF;">Platform Ops Only</span>'
        '</div>'
        '<div style="display:flex;justify-content:space-between;">'
        '<span style="color:#71717A;">Tenant Isolation</span>'
        '<span style="font-weight:600;color:#FFFFFF;">Zero Tenant Data</span>'
        '</div>'
        '</div>',
        sidebar=True,
    )

    render_sidebar_profile(
        user_name=logged_user["full_name"],
        role="PLATFORM_SUPER_ADMIN",
        is_superadmin=True,
    )

    if st.sidebar.button("Log Out", type="secondary", use_container_width=True):
        token = st.session_state.get("session_token")
        if token:
            revoke_session_by_token(token)
        try:
            cookie_ctrl.remove(COOKIE_NAME)
        except Exception:
            pass
        clear_session_cookie()
        st.session_state.clear()
        st.rerun()

    if selected_sa_page == "Organizations":
        render_page_layout(
            title="Platform Organizations",
            description="Cross-tenant organization directory with aggregate metrics and lifecycle management.",
            is_superadmin=True,
        )

        orgs = get_superadmin_organizations()
        if not orgs:
            st.info("No organizations registered on the platform yet.")
            return

        df_orgs = pd.DataFrame(orgs)

        # Overview Metrics in clean cards
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            render_html(render_kpi_card("Total Organizations", len(df_orgs), "All registered tenants"))
        with m2:
            render_html(render_kpi_card("Active Orgs", len(df_orgs[df_orgs["status"] == "active"]), "Operational accounts"))
        with m3:
            render_html(render_kpi_card("Suspended / Closed", len(df_orgs[df_orgs["status"].isin(["suspended", "closed"])]), "Restricted access"))
        with m4:
            render_html(render_kpi_card("Total Log Uploads", int(df_orgs["upload_count"].sum()), "Platform-wide ingested batches"))

        render_html('<div style="height:24px;"></div><div class="section-title">Organization Directory (Metadata & Counts Only)</div>')
        st.caption("No organization alerts, notes, events, rules, or real user IDs are accessible.")
        render_html('<div style="height:8px;"></div>')

        display_orgs = df_orgs[["name", "status", "user_count", "alert_count", "upload_count", "industry", "created_at"]]
        st.dataframe(
            display_orgs,
            column_config={
                "name": st.column_config.TextColumn("Organization Name", width=220),
                "status": st.column_config.TextColumn("Status", width=100),
                "user_count": st.column_config.NumberColumn("Users", width=90),
                "alert_count": st.column_config.NumberColumn("Alerts", width=90),
                "upload_count": st.column_config.NumberColumn("Uploads", width=90),
                "industry": st.column_config.TextColumn("Industry", width=160),
                "created_at": st.column_config.TextColumn("Created At", width=160),
            },
            width="stretch",
            hide_index=True,
        )

        st.markdown("---")
        with st.expander("Modify Organization Lifecycle Status"):
            st.caption("Suspend, close, or reactivate an organization. A written reason is mandatory.")
            org_options = {o["org_id"]: f"{o['name']} ({o['org_id']}) - Current: {o['status'].upper()}" for o in orgs}
            selected_org_id = st.selectbox("Select Organization:", options=list(org_options.keys()), format_func=lambda oid: org_options[oid])
            new_org_status = st.selectbox("New Organization Status:", ["suspended", "active", "closed"])
            org_status_reason = st.text_area("Written Justification (Saved in Platform Audit Log):", placeholder="E.g., Account suspended pending compliance investigation.")

            if st.button("Apply Organization Status Update", type="primary"):
                ok, err = update_org_status_by_superadmin(
                    actor_user_id=logged_user["user_id"],
                    target_org_id=selected_org_id,
                    new_status=new_org_status,
                    reason=org_status_reason,
                )
                if not ok:
                    st.error(err)
                else:
                    notify_toast(f"Organization status updated to {new_org_status.upper()}.")
                    st.rerun()

    elif selected_sa_page == "Users":
        render_page_layout(
            title="Platform User Accounts",
            description="Directory of all registered platform user identities and security statuses.",
            is_superadmin=True,
        )

        users = get_superadmin_users()
        if not users:
            st.info("No registered users found.")
            return

        df_users = pd.DataFrame(users)

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            render_html(render_kpi_card("Total Users", len(df_users), "All registered identities"))
        with m2:
            render_html(render_kpi_card("Active Users", len(df_users[df_users["status"] == "active"]), "Normal operational state"))
        with m3:
            render_html(render_kpi_card("Suspended Users", len(df_users[df_users["status"] == "suspended"]), "Temporarily disabled"))
        with m4:
            render_html(render_kpi_card("Banned Users", len(df_users[df_users["status"] == "banned"]), "Permanently revoked"))

        render_html('<div style="height:24px;"></div><div class="section-title">User Directory</div><div style="height:12px;"></div>')

        display_users = df_users[["name", "email", "status", "organization", "role", "created_at"]].copy()
        display_users["organization"] = display_users["organization"].fillna("Platform").replace({"None": "Platform", "": "Platform"})
        display_users["role"] = display_users["role"].fillna("super_admin").replace({"None": "super_admin", "": "super_admin"})
        st.dataframe(
            display_users,
            column_config={
                "name": st.column_config.TextColumn("Full Name", width=180),
                "email": st.column_config.TextColumn("Email Address", width=220),
                "status": st.column_config.TextColumn("Status", width=100),
                "organization": st.column_config.TextColumn("Organization", width=180),
                "role": st.column_config.TextColumn("Role", width=100),
                "created_at": st.column_config.TextColumn("Registered At", width=160),
            },
            width="stretch",
            hide_index=True,
        )

        render_html('<div style="height:16px;"></div>')
        st.markdown("---")
        render_html('<div style="height:8px;"></div>')
        with st.expander("Modify User Security Status"):
            st.caption("Suspend, ban, or reactivate a user. A written reason is mandatory.")
            user_options = {u["user_id"]: f"{u['name']} ({u['email']}) - Current: {u['status'].upper()}" for u in users}
            selected_user_id = st.selectbox("Select User:", options=list(user_options.keys()), format_func=lambda uid: user_options[uid])
            new_user_status = st.selectbox("New User Status:", ["suspended", "banned", "active"])
            user_status_reason = st.text_area("Written Justification (Saved in Platform Audit Log):", placeholder="E.g., Suspended user due to suspected compromised credentials.")

            if st.button("Apply User Status Update", type="primary"):
                ok, err = update_user_status_by_superadmin(
                    actor_user_id=logged_user["user_id"],
                    target_user_id=selected_user_id,
                    new_status=new_user_status,
                    reason=user_status_reason,
                )
                if not ok:
                    st.error(err)
                else:
                    notify_toast(f"User status updated to {new_user_status.upper()}.")
                    st.rerun()

    elif selected_sa_page == "Platform Audit Trail":
        render_page_layout(
            title="Platform Security Audit Trail",
            description="Immutable ledger of all administrative interventions across the platform.",
            is_superadmin=True,
        )

        p_logs = get_platform_audit_logs()
        if not p_logs:
            st.info("No platform administrative events recorded yet.")
            return

        df_p_logs = pd.DataFrame(p_logs)

        m1, m2, m3 = st.columns(3)
        with m1:
            render_html(render_kpi_card("Total Interventions", len(df_p_logs), "All logged admin actions"))
        with m2:
            render_html(render_kpi_card("User Modifications", len(df_p_logs[df_p_logs["target_type"] == "user"]), "User status interventions"))
        with m3:
            render_html(render_kpi_card("Org Modifications", len(df_p_logs[df_p_logs["target_type"] == "organization"]), "Tenant lifecycle interventions"))
        render_html('<div style="height:20px;"></div>')
        st.caption("Notice: This audit trail tracks platform governance only. Justification text from organization-level audit logs is strictly isolated and omitted.")
        render_html('<div style="height:8px;"></div>')

        st.dataframe(
            df_p_logs[["actor", "timestamp", "action", "target_type", "target_id", "reason"]],
            column_config={
                "actor": st.column_config.TextColumn("Administrator Actor", width=180),
                "timestamp": st.column_config.TextColumn("Timestamp (UTC)", width=160),
                "action": st.column_config.TextColumn("Action Type", width=180),
                "target_type": st.column_config.TextColumn("Target Type", width=120),
                "target_id": st.column_config.TextColumn("Target ID", width=130),
                "reason": st.column_config.TextColumn("Intervention Reason", width=350),
            },
            width="stretch",
            hide_index=True,
        )


@st.cache_resource
def _bootstrap_superadmin() -> bool:
    """Create or update super-admin once on startup when SUPERADMIN_EMAIL/PASSWORD env vars are set."""
    if os.environ.get("SUPERADMIN_EMAIL") and os.environ.get("SUPERADMIN_PASSWORD"):
        try:
            from create_superadmin import create_or_update_superadmin
            create_or_update_superadmin()
        except Exception as exc:
            print(f"[WARN] Superadmin bootstrap skipped: {exc}")
    return True


def main():
    init_db()
    _bootstrap_superadmin()
    flush_pending_toast()
    cookie_ctrl = CookieController()

    # Session Restoration Check from Browser Cookie
    logged_user = st.session_state.get("logged_in_user")
    if not logged_user:
        raw_token = st.context.cookies.get(COOKIE_NAME)
        if not raw_token:
            try:
                raw_token = cookie_ctrl.get(COOKIE_NAME)
            except Exception:
                raw_token = None
        if raw_token:
            db_sess = get_session_by_token(raw_token)
            if db_sess:
                user_data = db_sess.get("user")
                if user_data and user_data.get("status") not in ["suspended", "banned", "inactive"]:
                    logged_user = user_data
                    st.session_state["logged_in_user"] = logged_user
                    st.session_state["session_token"] = raw_token
                    st.session_state["session_id"] = db_sess["session_id"]
                    touch_session(db_sess["session_id"])
                else:
                    revoke_session(db_sess["session_id"])
                    try:
                        cookie_ctrl.remove(COOKIE_NAME)
                    except Exception:
                        pass
                    st.session_state.clear()
                    st.session_state["logout_message"] = "Your account has been suspended or deactivated. Contact your organization administrator."
            else:
                try:
                    cookie_ctrl.remove(COOKIE_NAME)
                except Exception:
                    pass

    # Security Check: Stop execution if not logged in
    if not logged_user:
        render_auth_page(cookie_ctrl)
        st.stop()

    # Security Check: Verify user account status directly in DB on every execution
    with get_session() as session:
        current_db_user = session.query(User).filter(User.user_id == logged_user["user_id"]).first()
        if not current_db_user or current_db_user.status in ["suspended", "banned", "inactive"]:
            token = st.session_state.get("session_token")
            if token:
                revoke_session_by_token(token)
            try:
                cookie_ctrl.remove(COOKIE_NAME)
            except Exception:
                pass
            st.session_state.clear()
            st.session_state["logout_message"] = "Your account has been suspended or deactivated. Contact your organization administrator."
            render_auth_page(cookie_ctrl)
            st.stop()

    # Server Authority: touch_session only on real user interaction rerun, NOT by idle timer fragment
    sess_id = st.session_state.get("session_id")
    if sess_id:
        touch_session(sess_id)

    # Sync session token to browser cookie
    if "session_token" in st.session_state:
        set_session_cookie(st.session_state["session_token"])

    # Client-side idle monitor (runs at background interval without touching session)
    render_idle_monitor(cookie_ctrl)

    # Super-Admin Console Gate: Super-admins have NO organization pages and cannot access tenant data
    if logged_user.get("is_super_admin"):
        render_superadmin_console(logged_user, cookie_ctrl)
        st.stop()

    # Security Rule: Retrieve active organization context from DB session on every page load
    org_context, org_err = get_active_org_context(logged_user["user_id"])
    if org_err == "NO_ORG":
        render_setup_page(logged_user, None)
        st.stop()
    elif org_err:
        # Organization suspended or closed
        st.error(org_err)
        if st.sidebar.button("Log Out"):
            token = st.session_state.get("session_token")
            if token:
                revoke_session_by_token(token)
            try:
                cookie_ctrl.remove(COOKIE_NAME)
            except Exception:
                pass
            st.session_state.clear()
            st.rerun()
        st.stop()
    elif not org_context.get("setup_completed", False):
        # Server-side gate: cannot skip to dashboard via URL before setup is complete
        render_setup_page(logged_user, org_context)
        st.stop()

    org_id = org_context["org_id"]
    active_role = org_context["role"]

    if "setup_success_msg" in st.session_state:
        st.success(st.session_state.pop("setup_success_msg"))

    # Tenant-scoped alerts query strictly filtered by org_id
    alerts = get_org_alerts(org_id)

    # 1. Product Name at the Top (Clean B2B branding, zero emojis)
    render_sidebar_header(is_superadmin=False)

    # 2. Navigation grouped under small section labels
    if active_role == "org_admin":
        pages = ["Alert Queue", "Alert Detail", "Live Events", "Upload Logs", "Rules", "Staff", "Audit Trail"]
    else:
        # Analysts and Reviewers only have access to Alert Queue, Alert Detail, and Live Events
        pages = ["Alert Queue", "Alert Detail", "Live Events"]

    if "sidebar_nav" not in st.session_state or st.session_state["sidebar_nav"] not in pages:
        st.session_state["sidebar_nav"] = "Alert Queue"

    nav_choice = st.sidebar.radio("Navigation", pages, key="sidebar_nav", label_visibility="collapsed")

    # 3. Sidebar Organization Context Card (dark styled to match sidebar)
    render_html(
        f'<div style="background-color:#18181B;border:1px solid #27272A;border-radius:10px;padding:10px 12px;margin-top:10px;font-size:12px;color:#A1A1AA;">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:4px;">'
        f'<span style="color:#71717A;">Organization</span>'
        f'<span style="font-weight:600;color:#FFFFFF;">{org_context["name"]}</span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:4px;">'
        f'<span style="color:#71717A;">Industry</span>'
        f'<span style="font-weight:600;color:#FFFFFF;">{org_context["industry"]}</span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;">'
        f'<span style="color:#71717A;">Tenant Alerts</span>'
        f'<span style="font-weight:600;color:#FFFFFF;">{len(alerts)}</span>'
        f'</div>'
        f'</div>',
        sidebar=True,
    )

    # 4. The user's name and role at the bottom with a logout button
    render_sidebar_profile(
        user_name=logged_user["full_name"],
        role=active_role,
        org_name=org_context["name"],
        is_superadmin=False,
    )

    if st.sidebar.button("Log Out", type="secondary", use_container_width=True):
        token = st.session_state.get("session_token")
        if token:
            revoke_session_by_token(token)
        try:
            cookie_ctrl.remove(COOKIE_NAME)
        except Exception:
            pass
        clear_session_cookie()
        st.session_state.clear()
        st.rerun()

    # Page Routing (strictly tenant-isolated and RBAC enforced)
    if nav_choice == "Alert Queue":
        render_alert_queue(alerts)
    elif nav_choice == "Alert Detail":
        render_alert_detail(
            alerts,
            org_id,
            active_role,
            logged_user["user_id"],
            org_salt=org_context.get("org_salt"),
        )
    elif nav_choice == "Live Events":
        render_live_events_page(org_id)
    elif nav_choice == "Upload Logs":
        render_upload_logs_page(org_context, logged_user["user_id"])
    elif nav_choice == "Rules":
        render_rules_page(org_id, active_role, logged_user["user_id"])
    elif nav_choice == "Staff":
        render_staff_page(org_context, logged_user["user_id"])
    elif nav_choice == "Audit Trail":
        render_audit_trail_page(org_id, active_role)


if __name__ == "__main__":
    main()
