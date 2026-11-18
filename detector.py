"""Rule loader and baseline detection engine for Insider Threat Monitor."""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
import numpy as np
import pandas as pd
import yaml

from db import clear_alerts, init_db, save_alerts


def load_rules(rules_path: str = "rules.yaml") -> Dict[str, Any]:
    """Load and parse configurable detection rules from YAML."""
    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Rules configuration file not found at: {rules_path}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    rules_dict = {}
    for entry in config.get("rules", []):
        rules_dict[entry["rule_id"]] = entry
    return rules_dict


def get_salt() -> str:
    """Retrieve the privacy salt stored outside code (from .streamlit/secrets.toml or env)."""
    import os
    secrets_file = Path(".streamlit/secrets.toml")
    if secrets_file.exists():
        try:
            for line in secrets_file.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("salt"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return os.environ.get("PRIVACY_SALT", "insider_threat_monitor_privacy_salt_2026_x89q")


def pseudonymize_user(user_id: str, salt: Optional[str] = None) -> str:
    """Generate a privacy-conscious, salted pseudonym for a user ID."""
    if str(user_id).startswith("USER-"):
        return str(user_id)
    active_salt = salt or get_salt()
    token = hashlib.sha256(f"{active_salt}_{user_id}".encode("utf-8")).hexdigest()[:8].upper()
    return f"USER-{token}"


def calculate_median_mad(series: pd.Series) -> Dict[str, float]:
    """
    Compute Median and Median Absolute Deviation (MAD).

    WHY MEDIAN AND MAD (INSTEAD OF MEAN AND STANDARD DEVIATION):
    ------------------------------------------------------------
    1. Robustness Against Outliers: Mean and standard deviation are sensitive
       to extreme values. A single attack event (e.g. 5,000 bulk reads at 2 a.m.
       or a 1.25 GB export) heavily inflates the mean and stretches standard
       deviation, which masks the malicious activity (known as 'masking').
    2. High Breakdown Point: Median and MAD possess a 50% breakdown point,
       meaning up to half of the sample can be anomalous without corrupting
       the baseline estimates.
    3. Normal-Consistent Scaling: Multiplying MAD by 1.4826 provides an
       unbiased estimator of standard deviation for normally distributed
       subsets while remaining immune to extreme leverage points.
    """
    clean_series = pd.to_numeric(series.dropna(), errors="coerce").dropna()
    if len(clean_series) == 0:
        return {"median": 0.0, "mad": 0.0, "mad_scaled": 0.0}

    median_val = float(np.median(clean_series))
    abs_deviations = np.abs(clean_series - median_val)
    mad_val = float(np.median(abs_deviations))
    mad_scaled = float(1.4826 * mad_val)

    return {
        "median": round(median_val, 2),
        "mad": round(mad_val, 2),
        "mad_scaled": round(mad_scaled, 2),
    }


def compute_baselines(
    df: pd.DataFrame,
    min_history_days: int = 5,
) -> Dict[str, Any]:
    """
    Compute per-user behavioral baselines using Median and MAD.

    Metrics calculated per user:
      - daily_event_count: median and MAD of events per active day
      - daily_download_bytes: median and MAD of download/export bytes per day
      - single_download_bytes: median and MAD of bytes per individual transfer
      - hourly_read_count: median and MAD of read actions per active hour

    Fallback mechanism:
      - If a user has fewer active days than `min_history_days`, their baseline
        falls back to the role-level baseline across their peers.
    """
    df_clean = df.copy()
    df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"])
    df_clean["date"] = df_clean["timestamp"].dt.date
    df_clean["hour_bucket"] = df_clean["timestamp"].dt.floor("1h")

    # 1. Role-Level Baselines
    role_baselines = {}
    for role, role_df in df_clean.groupby("role"):
        # Role daily event volume
        role_user_daily_counts = (
            role_df.groupby(["user_id", "date"])["event_id"].count().reset_index(name="event_count")
        )
        role_daily_stats = calculate_median_mad(role_user_daily_counts["event_count"])

        # Role daily download/export bytes
        dl_filter = role_df["action"].isin(["download", "export"])
        role_user_daily_bytes = (
            role_df[dl_filter]
            .groupby(["user_id", "date"])["bytes"]
            .sum()
            .reset_index(name="daily_bytes")
        )
        role_daily_bytes_stats = calculate_median_mad(role_user_daily_bytes["daily_bytes"])
        role_single_bytes_stats = calculate_median_mad(role_df[dl_filter]["bytes"])

        # Role hourly reads
        read_filter = role_df["action"] == "read"
        role_user_hourly_reads = (
            role_df[read_filter]
            .groupby(["user_id", "hour_bucket"])["event_id"]
            .count()
            .reset_index(name="read_count")
        )
        role_hourly_read_stats = calculate_median_mad(role_user_hourly_reads["read_count"])

        role_baselines[role] = {
            "daily_event_count": role_daily_stats,
            "daily_download_bytes": role_daily_bytes_stats,
            "single_download_bytes": role_single_bytes_stats,
            "hourly_read_count": role_hourly_read_stats,
        }

    # 2. User-Level Baselines
    user_baselines = {}
    for user_id, user_df in df_clean.groupby("user_id"):
        role = user_df["role"].iloc[0]
        active_days = user_df["date"].nunique()

        if active_days < min_history_days:
            user_baselines[user_id] = {
                "user_id": user_id,
                "role": role,
                "active_days": active_days,
                "is_fallback": True,
                "fallback_source": f"role:{role}",
                "daily_event_count": role_baselines[role]["daily_event_count"],
                "daily_download_bytes": role_baselines[role]["daily_download_bytes"],
                "single_download_bytes": role_baselines[role]["single_download_bytes"],
                "hourly_read_count": role_baselines[role]["hourly_read_count"],
            }
            continue

        daily_counts = (
            user_df.groupby("date")["event_id"].count().reset_index(name="event_count")
        )
        daily_count_stats = calculate_median_mad(daily_counts["event_count"])

        dl_events = user_df[user_df["action"].isin(["download", "export"])]
        daily_bytes = (
            dl_events.groupby("date")["bytes"].sum().reset_index(name="daily_bytes")
        )
        daily_bytes_stats = calculate_median_mad(daily_bytes["daily_bytes"])
        single_bytes_stats = calculate_median_mad(dl_events["bytes"])

        # Hourly read volume baseline
        read_events = user_df[user_df["action"] == "read"]
        hourly_reads = (
            read_events.groupby("hour_bucket")["event_id"]
            .count()
            .reset_index(name="read_count")
        )
        hourly_read_stats = calculate_median_mad(hourly_reads["read_count"])

        user_baselines[user_id] = {
            "user_id": user_id,
            "role": role,
            "active_days": active_days,
            "is_fallback": False,
            "fallback_source": None,
            "daily_event_count": daily_count_stats,
            "daily_download_bytes": daily_bytes_stats,
            "single_download_bytes": single_bytes_stats,
            "hourly_read_count": hourly_read_stats,
        }

    return {
        "user_baselines": user_baselines,
        "role_baselines": role_baselines,
    }


def detect_bulk_access(
    df: pd.DataFrame,
    rules: Dict[str, Any],
    baselines: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Detect bulk access anomalies (only the bulk_access rule).

    Alert reason format required:
    "Read X records in 1 hour. This user's median is Y per hour."
    """
    rule = rules.get("bulk_access")
    if not rule:
        return []

    thresholds = rule.get("thresholds", {})
    min_event_count = thresholds.get("min_event_count", 50)
    mad_multiplier = thresholds.get("mad_multiplier", 3.5)
    severity = rule.get("severity", "high")

    df_clean = df.copy()
    df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"])
    read_df = df_clean[df_clean["action"] == "read"].sort_values("timestamp")

    alerts = []

    for user_id, user_reads in read_df.groupby("user_id"):
        user_baseline = baselines["user_baselines"].get(user_id)
        if not user_baseline:
            continue

        hourly_stats = user_baseline["hourly_read_count"]
        hourly_median = hourly_stats["median"]
        hourly_mad_scaled = hourly_stats["mad_scaled"]

        # Cutoff: count must exceed minimum threshold and robust statistical threshold
        cutoff = max(min_event_count, hourly_median + (mad_multiplier * hourly_mad_scaled))

        # Group by 1-hour tumbling intervals
        grouped_hourly = (
            user_reads.groupby(pd.Grouper(key="timestamp", freq="1h"))
        )

        for hour_start, hour_records in grouped_hourly:
            count = len(hour_records)
            if count >= cutoff:
                event_ids = hour_records["event_id"].tolist()
                pseudonym = pseudonymize_user(user_id)
                reason = f"Read {count:,} records in 1 hour. This user's median is {round(hourly_median)} per hour."
                alert_id = f"alt_{uuid.uuid4().hex[:8]}"

                alerts.append(
                    {
                        "alert_id": alert_id,
                        "rule_id": "bulk_access",
                        "severity": severity,
                        "user_pseudonym": pseudonym,
                        "event_ids": ",".join(event_ids),
                        "reason": reason,
                        "status": "new",
                        "reviewer": None,
                        "reviewer_notes": None,
                        "created_at": hour_start.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )

    return alerts


def detect_atypical_download(
    df: pd.DataFrame,
    rules: Dict[str, Any],
    baselines: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Detect atypical download or export volume anomalies.

    Alert reason format:
    "Export of X bytes (Y MB). This user's median single transfer is Z bytes (W MB)."
    """
    rule = rules.get("atypical_download")
    if not rule:
        return []

    thresholds = rule.get("thresholds", {})
    mad_multiplier = thresholds.get("mad_multiplier", 4.0)
    min_bytes = thresholds.get("min_bytes", 50_000_000)
    severity = rule.get("severity", "high")

    df_clean = df.copy()
    df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"])
    transfer_df = df_clean[df_clean["action"].isin(["download", "export"])].sort_values("timestamp")

    alerts = []

    for user_id, user_transfers in transfer_df.groupby("user_id"):
        user_baseline = baselines["user_baselines"].get(user_id)
        if not user_baseline:
            continue

        single_stats = user_baseline["single_download_bytes"]
        median_bytes = single_stats["median"]
        mad_scaled_bytes = single_stats["mad_scaled"]

        # Cutoff: must exceed min_bytes floor and median + k * scaled_mad
        cutoff = max(min_bytes, median_bytes + (mad_multiplier * mad_scaled_bytes))

        for _, row in user_transfers.iterrows():
            bytes_val = row["bytes"]
            if bytes_val >= cutoff:
                pseudonym = pseudonymize_user(user_id)
                action_name = row["action"].capitalize()
                mb_val = bytes_val / (1024 * 1024)
                mb_median = median_bytes / (1024 * 1024)

                reason = (
                    f"{action_name} of {bytes_val:,} bytes ({mb_val:,.1f} MB). "
                    f"This user's median single transfer is {round(median_bytes):,} bytes ({mb_median:,.1f} MB)."
                )
                alert_id = f"alt_{uuid.uuid4().hex[:8]}"

                alerts.append(
                    {
                        "alert_id": alert_id,
                        "rule_id": "atypical_download",
                        "severity": severity,
                        "user_pseudonym": pseudonym,
                        "event_ids": str(row["event_id"]),
                        "reason": reason,
                        "status": "new",
                        "reviewer": None,
                        "reviewer_notes": None,
                        "created_at": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )

    return alerts


def detect_policy_violation(
    df: pd.DataFrame,
    rules: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Detect explicit security policy violations:
      1. Cross-role unauthorized departmental resource access (Scenario C).
      2. Access or download from unmanaged / BYOD devices (Scenario D).
      3. Consecutive failed access/login attempts reaching threshold (Scenario E).
    """
    rule = rules.get("policy_violation")
    if not rule:
        return []

    thresholds = rule.get("thresholds", {})
    consec_thresh = thresholds.get("consecutive_failures", 5)
    blocked_prefixes = tuple(thresholds.get("blocked_device_prefixes", ["BYOD", "UNMANAGED"]))
    role_allowed = thresholds.get("role_allowed_prefixes", {})
    severity = rule.get("severity", "critical")

    df_clean = df.copy()
    df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"])
    df_sorted = df_clean.sort_values("timestamp")

    all_company_prefixes = set()
    for _, prefixes in role_allowed.items():
        all_company_prefixes.update(prefixes)
    company_prefixes_tuple = tuple(all_company_prefixes)

    alerts = []

    # 1. Cross-role resource access (successful access to known departmental resource outside role)
    for user_id, user_df in df_sorted.groupby("user_id"):
        role = user_df["role"].iloc[0]
        allowed = tuple(role_allowed.get(role, []))
        if not allowed:
            continue

        violations = user_df[
            (user_df["outcome"] == "success")
            & (user_df["resource"].str.startswith(company_prefixes_tuple))
            & (~user_df["resource"].str.startswith(allowed))
        ]
        if not violations.empty:
            pseudonym = pseudonymize_user(user_id)
            resources = ", ".join(violations["resource"].unique())
            reason = (
                f"Cross-role policy violation: User with role '{role}' accessed "
                f"unauthorized departmental resource(s): {resources}."
            )
            alerts.append(
                {
                    "alert_id": f"alt_{uuid.uuid4().hex[:8]}",
                    "rule_id": "policy_violation",
                    "severity": severity,
                    "user_pseudonym": pseudonym,
                    "event_ids": ",".join(violations["event_id"].tolist()),
                    "reason": reason,
                    "status": "new",
                    "reviewer": None,
                    "reviewer_notes": None,
                    "created_at": violations["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    # 2. Blocked device prefix violation (BYOD / UNMANAGED)
    for (user_id, dev), dev_df in df_sorted.groupby(["user_id", "device"]):
        if str(dev).startswith(blocked_prefixes):
            pseudonym = pseudonymize_user(user_id)
            count = len(dev_df)
            reason = (
                f"Unauthorized device policy violation: {count} event(s) initiated "
                f"from blocked/unmanaged device '{dev}'."
            )
            alerts.append(
                {
                    "alert_id": f"alt_{uuid.uuid4().hex[:8]}",
                    "rule_id": "policy_violation",
                    "severity": severity,
                    "user_pseudonym": pseudonym,
                    "event_ids": ",".join(dev_df["event_id"].tolist()),
                    "reason": reason,
                    "status": "new",
                    "reviewer": None,
                    "reviewer_notes": None,
                    "created_at": dev_df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    # 3. Consecutive failed access attempts
    for user_id, user_df in df_sorted.groupby("user_id"):
        streak = []
        for _, row in user_df.iterrows():
            if row["outcome"] in ("failure", "denied"):
                streak.append(row)
            else:
                if len(streak) >= consec_thresh:
                    pseudonym = pseudonymize_user(user_id)
                    eids = [r["event_id"] for r in streak]
                    reason = (
                        f"Denial streak policy violation: {len(streak)} consecutive failed attempts "
                        f"detected (threshold: {consec_thresh})."
                    )
                    alerts.append(
                        {
                            "alert_id": f"alt_{uuid.uuid4().hex[:8]}",
                            "rule_id": "policy_violation",
                            "severity": severity,
                            "user_pseudonym": pseudonym,
                            "event_ids": ",".join(eids),
                            "reason": reason,
                            "status": "new",
                            "reviewer": None,
                            "reviewer_notes": None,
                            "created_at": streak[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )
                streak = []
        if len(streak) >= consec_thresh:
            pseudonym = pseudonymize_user(user_id)
            eids = [r["event_id"] for r in streak]
            reason = (
                f"Denial streak policy violation: {len(streak)} consecutive failed attempts "
                f"detected (threshold: {consec_thresh})."
            )
            alerts.append(
                {
                    "alert_id": f"alt_{uuid.uuid4().hex[:8]}",
                    "rule_id": "policy_violation",
                    "severity": severity,
                    "user_pseudonym": pseudonym,
                    "event_ids": ",".join(eids),
                    "reason": reason,
                    "status": "new",
                    "reviewer": None,
                    "reviewer_notes": None,
                    "created_at": streak[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    return alerts


def _usual_hours_window(
    subset_df: pd.DataFrame,
    default_start: int,
    default_end: int,
) -> Optional[Tuple[int, int]]:
    """
    Compute (start_hour, end_hour_exclusive) from hours that appear on >= 20% of active days.
    Returns None if there are no active days.
    """
    if subset_df.empty:
        return None
    active_days = subset_df["timestamp"].dt.date.nunique()
    if active_days == 0:
        return None
    hour_day_counts = (
        subset_df.assign(_date=subset_df["timestamp"].dt.date, _hour=subset_df["timestamp"].dt.hour)
        .groupby("_hour")["_date"]
        .nunique()
    )
    min_days = max(1, int(active_days * 0.2))
    common_hours = [int(h) for h, cnt in hour_day_counts.items() if cnt >= min_days]
    if not common_hours:
        return (default_start, default_end)
    return (min(common_hours), min(24, max(common_hours) + 1))


def detect_off_hours(
    df: pd.DataFrame,
    rules: Dict[str, Any],
    baselines: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Detect activity outside a user's usual active hours (falling back to role baseline,
    then rules.yaml work_start_hour/work_end_hour). Ignores users with < 10 events.
    """
    rule = rules.get("off_hours")
    if not rule:
        return []

    thresholds = rule.get("thresholds", {})
    default_start = int(thresholds.get("work_start_hour", 8))
    default_end = int(thresholds.get("work_end_hour", 18))
    allow_weekend = bool(thresholds.get("allow_weekend", False))
    severity = rule.get("severity", "medium")

    df_clean = df.copy()
    df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"])

    # Precompute role-level usual hours fallback
    role_windows: Dict[str, Tuple[int, int]] = {}
    for role, role_df in df_clean.groupby("role"):
        win = _usual_hours_window(role_df, default_start, default_end)
        role_windows[role] = win if win else (default_start, default_end)

    alerts = []
    for user_id, user_df in df_clean.groupby("user_id"):
        if len(user_df) < 10:
            continue

        user_base = baselines.get("user_baselines", {}).get(user_id)
        role = user_df["role"].iloc[0]
        if user_base and not user_base.get("is_fallback", False):
            win = _usual_hours_window(user_df, default_start, default_end)
            usual_start, usual_end = win if win else role_windows.get(role, (default_start, default_end))
        else:
            usual_start, usual_end = role_windows.get(role, (default_start, default_end))

        hours = user_df["timestamp"].dt.hour
        is_weekend = user_df["timestamp"].dt.weekday >= 5
        outside_hours = (hours < usual_start) | (hours >= usual_end)
        if not allow_weekend:
            off_df = user_df[outside_hours | is_weekend].sort_values("timestamp")
        else:
            off_df = user_df[outside_hours].sort_values("timestamp")

        if off_df.empty:
            continue

        # Group by date so a single off-hours burst produces one alert, not one per event
        for _, day_df in off_df.groupby(off_df["timestamp"].dt.date):
            first_ts = day_df["timestamp"].iloc[0]
            pseudonym = pseudonymize_user(user_id)
            count = len(day_df)
            time_str = first_ts.strftime("%H:%M")
            count_note = f" ({count} events)" if count > 1 else ""
            reason = (
                f"Activity at {time_str}{count_note}, user's usual hours are "
                f"{usual_start:02d}:00 to {usual_end:02d}:00."
            )
            alerts.append(
                {
                    "alert_id": f"alt_{uuid.uuid4().hex[:8]}",
                    "rule_id": "off_hours",
                    "severity": severity,
                    "user_pseudonym": pseudonym,
                    "event_ids": ",".join(day_df["event_id"].astype(str).tolist()),
                    "reason": reason,
                    "status": "new",
                    "reviewer": None,
                    "reviewer_notes": None,
                    "created_at": first_ts.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

    return alerts


def detect_new_sensitive_resource(
    df: pd.DataFrame,
    rules: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Detect the first time a user accesses a resource with high/critical sensitivity
    that they have never accessed in their prior history window.
    """
    rule = rules.get("new_sensitive_resource")
    if not rule:
        return []

    thresholds = rule.get("thresholds", {})
    sensitive_levels = {str(s).lower() for s in thresholds.get("sensitive_levels", ["high", "critical"])}
    severity = rule.get("severity", "high")

    df_clean = df.copy()
    df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"])
    df_sorted = df_clean.sort_values("timestamp")

    alerts = []
    for user_id, user_df in df_sorted.groupby("user_id"):
        seen_resources = set()
        first_ts = user_df["timestamp"].iloc[0]
        pseudonym = pseudonymize_user(user_id)

        for _, row in user_df.iterrows():
            res = str(row.get("resource", "")).strip()
            sens = str(row.get("sensitivity", "")).strip().lower()
            outcome = str(row.get("outcome", "success")).strip().lower()
            if not res:
                continue

            if sens in sensitive_levels and outcome == "success" and res not in seen_resources:
                row_ts = row["timestamp"]
                history_days = max(1, (row_ts.date() - first_ts.date()).days)
                reason = (
                    f"First access to {res} ({sens} sensitivity) "
                    f"in {history_days} days of history."
                )
                alerts.append(
                    {
                        "alert_id": f"alt_{uuid.uuid4().hex[:8]}",
                        "rule_id": "new_sensitive_resource",
                        "severity": severity,
                        "user_pseudonym": pseudonym,
                        "event_ids": str(row["event_id"]),
                        "reason": reason,
                        "status": "new",
                        "reviewer": None,
                        "reviewer_notes": None,
                        "created_at": row_ts.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            seen_resources.add(res)

    return alerts


def run_all_detectors(
    df: pd.DataFrame,
    rules: Dict[str, Any],
    baselines: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Execute all active detection rules."""
    all_alerts = []
    all_alerts.extend(detect_bulk_access(df, rules, baselines))
    all_alerts.extend(detect_atypical_download(df, rules, baselines))
    all_alerts.extend(detect_policy_violation(df, rules))
    all_alerts.extend(detect_off_hours(df, rules, baselines))
    all_alerts.extend(detect_new_sensitive_resource(df, rules))
    return all_alerts


def run_detection_pipeline(
    df: pd.DataFrame,
    org_id: str,
    rules: Optional[Dict[str, Any]] = None,
    org_salt: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Execute detection pipeline scoped to an organization:
      - Uses org-specific rules (or falls back to rules.yaml defaults).
      - Computes baselines (Median & MAD).
      - Runs active detection rules.
      - Sets org_id on all produced alerts.
    """
    if rules is None:
        rules = load_rules("rules.yaml")

    formatted_rules = {}
    if isinstance(rules, dict):
        for rid, val in rules.items():
            if isinstance(val, dict) and "thresholds" in val:
                formatted_rules[rid] = val
            elif isinstance(val, dict):
                formatted_rules[rid] = {"rule_id": rid, "thresholds": val, "severity": "high"}
            else:
                formatted_rules[rid] = val
    else:
        formatted_rules = load_rules("rules.yaml")

    baselines = compute_baselines(df, min_history_days=5)
    alerts = run_all_detectors(df, formatted_rules, baselines)

    for a in alerts:
        a["org_id"] = org_id

    return alerts


def main():
    print("Initializing SQLite database...")
    init_db()
    clear_alerts()

    print("Loading rules from rules.yaml...")
    rules = load_rules("rules.yaml")

    print("Loading logs from logs.csv...")
    df = pd.read_csv("logs.csv")

    print("Computing baselines (Median & MAD)...")
    baselines = compute_baselines(df, min_history_days=5)

    print("Running full detector...")
    alerts = run_all_detectors(df, rules, baselines)

    print(f"\nSaving {len(alerts)} alert(s) to database...")
    save_alerts(alerts)

    print(f"\n--- Produced Alerts ({len(alerts)}) ---")
    for a in alerts:
        event_count = len(a["event_ids"].split(","))
        print(f"Alert ID:        {a['alert_id']}")
        print(f"Rule ID:         {a['rule_id']}")
        print(f"Severity:        {a['severity'].upper()}")
        print(f"User Pseudonym:  {a['user_pseudonym']}")
        print(f"Timestamp:       {a['created_at']}")
        print(f"Reason:          {a['reason']}")
        print(f"Status:          {a['status']}")
        print(f"Events Flagged:  {event_count} event(s)")
        print("-" * 60)

    print("\n--- Alert Count Per Rule ---")
    if alerts:
        rule_counts = pd.Series([a["rule_id"] for a in alerts]).value_counts()
        print(rule_counts.to_string())
    else:
        print("No alerts produced.")


if __name__ == "__main__":
    main()

