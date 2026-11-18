"""Synthetic audit log generator for Insider Threat Monitor prototype."""

import random
import uuid
from datetime import datetime, timedelta
import numpy as np
import pandas as pd

# Set fixed seed for reproducibility
random.seed(42)
np.random.seed(42)

ROLES = ["engineer", "sales", "hr", "analyst"]
USERS_PER_ROLE = 10

ROLE_RESOURCES = {
    "engineer": [
        ("repo/backend_api.git", "medium"),
        ("repo/auth_service.git", "high"),
        ("doc/architecture_specs.docx", "low"),
        ("server/prod_cluster.cfg", "critical"),
        ("repo/frontend_ui.git", "low"),
    ],
    "sales": [
        ("crm/lead_pipeline.csv", "medium"),
        ("doc/client_proposals.docx", "low"),
        ("crm/deal_contracts.pdf", "high"),
        ("doc/pricing_matrix.xlsx", "high"),
        ("report/q3_regional_forecast.pdf", "medium"),
    ],
    "hr": [
        ("portal/employee_directory.xlsx", "low"),
        ("hr/payroll_summary_2026.xlsx", "critical"),
        ("doc/benefits_policy.pdf", "low"),
        ("hr/personnel_evaluations.docx", "high"),
        ("portal/recruiting_applicants.csv", "medium"),
    ],
    "analyst": [
        ("db/analytics_warehouse.sql", "medium"),
        ("report/monthly_kpi_dashboard.pdf", "low"),
        ("db/customer_churn_model.parquet", "medium"),
        ("report/board_financial_deck.pdf", "critical"),
        ("db/raw_telemetry_dump.csv", "high"),
    ],
}

ACTIONS = ["login", "read", "download", "export", "delete", "permission_change"]
ACTION_WEIGHTS = [0.15, 0.45, 0.25, 0.10, 0.04, 0.01]


def build_user_directory():
    """Build a directory of ~40 synthetic users with roles, devices, IPs, and typical daily volumes."""
    users = []
    user_counter = 1
    for role in ROLES:
        for _ in range(USERS_PER_ROLE):
            user_id = f"usr_{user_counter:03d}"
            device_id = f"DEV-CORP-{user_counter:03d}"
            primary_ip = f"10.0.{10 + (user_counter % 5)}.{100 + user_counter}"
            # Typical daily event volume between 15 and 45 events
            daily_mean_volume = random.randint(15, 45)
            users.append(
                {
                    "user_id": user_id,
                    "role": role,
                    "device": device_id,
                    "primary_ip": primary_ip,
                    "daily_mean_volume": daily_mean_volume,
                }
            )
            user_counter += 1
    return users


def sample_timestamp(day_date, is_weekend):
    """Sample realistic timestamp: mostly 8am-6pm on weekdays."""
    if is_weekend:
        hour = random.choice([10, 11, 14, 15, 16, 20])
    else:
        if random.random() < 0.85:
            hour = random.randint(8, 17)
        else:
            hour = random.choice([6, 7, 18, 19, 20, 21, 22])

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day_date.replace(hour=hour, minute=minute, second=second)


def sample_bytes(action, sensitivity):
    """Sample realistic byte transfer based on action and resource sensitivity."""
    if action in ["login", "permission_change"]:
        return 0
    elif action == "delete":
        return 0
    elif action == "read":
        return random.randint(1_000, 50_000)
    elif action == "download":
        multiplier = 2 if sensitivity in ["high", "critical"] else 1
        return random.randint(50_000, 5_000_000) * multiplier
    elif action == "export":
        multiplier = 3 if sensitivity in ["high", "critical"] else 1
        return random.randint(200_000, 15_000_000) * multiplier
    return random.randint(1_000, 100_000)


def generate_normal_logs(days=30):
    """Generate 30 days of baseline normal activity for all users."""
    users = build_user_directory()
    end_date = datetime(2026, 10, 24)
    start_date = end_date - timedelta(days=days)

    records = []

    for day_offset in range(days):
        current_date = start_date + timedelta(days=day_offset)
        is_weekend = current_date.weekday() >= 5

        for user in users:
            if is_weekend and random.random() > 0.10:
                continue

            target_volume = int(
                np.random.poisson(user["daily_mean_volume"] * (0.3 if is_weekend else 1.0))
            )
            target_volume = max(1, target_volume)

            # Daily login record
            login_time = sample_timestamp(current_date, is_weekend)
            records.append(
                {
                    "event_id": uuid.uuid4().hex[:16],
                    "timestamp": login_time,
                    "user_id": user["user_id"],
                    "role": user["role"],
                    "action": "login",
                    "resource": "auth/single_sign_on",
                    "sensitivity": "low",
                    "bytes": 0,
                    "device": user["device"],
                    "source_ip": user["primary_ip"],
                    "outcome": "success" if random.random() < 0.98 else "failure",
                }
            )

            # Activity events throughout the day
            for _ in range(target_volume - 1):
                event_time = sample_timestamp(current_date, is_weekend)
                action = random.choices(ACTIONS, weights=ACTION_WEIGHTS, k=1)[0]

                if action == "login":
                    resource = "auth/single_sign_on"
                    sensitivity = "low"
                else:
                    resource_choice, sensitivity = random.choice(ROLE_RESOURCES[user["role"]])
                    resource = resource_choice

                byte_count = sample_bytes(action, sensitivity)
                outcome = "success" if random.random() < 0.98 else "failure"

                records.append(
                    {
                        "event_id": uuid.uuid4().hex[:16],
                        "timestamp": event_time,
                        "user_id": user["user_id"],
                        "role": user["role"],
                        "action": action,
                        "resource": resource,
                        "sensitivity": sensitivity,
                        "bytes": byte_count,
                        "device": user["device"],
                        "source_ip": user["primary_ip"],
                        "outcome": outcome,
                    }
                )

    df = pd.DataFrame(records)
    return df


def inject_scenarios(users_dir):
    """
    Inject specific threat scenarios into the dataset:
    A. One user reads 5,000 records at 2 a.m.
    B. A user who normally downloads little exports a very large file.
    C. A user accesses a resource outside their role's allowed list.
    D. Restricted data downloaded to an unmanaged device.
    E. Seven denied attempts in a row by one user.
    F. A user touches a sensitive resource for the first time.
    """
    injected_records = []
    ground_truth = []

    # Map users by ID for easy lookup
    user_map = {u["user_id"]: u for u in users_dir}

    # Scenario A: One user reads 5,000 records at 2 a.m.
    # Target: usr_007 (engineer) on 2026-10-15 starting at 02:00:00 AM
    scenario_a_name = "Scenario A: Bulk read at 2 a.m."
    usr_a = user_map["usr_007"]
    base_time_a = datetime(2026, 10, 15, 2, 0, 0)
    for i in range(5000):
        ev_id = uuid.uuid4().hex[:16]
        # Spread over ~30 minutes
        ev_time = base_time_a + timedelta(seconds=int(i * 0.36))
        injected_records.append(
            {
                "event_id": ev_id,
                "timestamp": ev_time,
                "user_id": usr_a["user_id"],
                "role": usr_a["role"],
                "action": "read",
                "resource": "repo/backend_api.git",
                "sensitivity": "medium",
                "bytes": random.randint(2_000, 25_000),
                "device": usr_a["device"],
                "source_ip": usr_a["primary_ip"],
                "outcome": "success",
            }
        )
        ground_truth.append({"event_id": ev_id, "scenario": scenario_a_name})

    # Scenario B: A user who normally downloads little exports a very large file.
    # Target: usr_023 (hr - low typical daily download volume)
    scenario_b_name = "Scenario B: Large file export by low-volume user"
    usr_b = user_map["usr_023"]
    ev_id = uuid.uuid4().hex[:16]
    injected_records.append(
        {
            "event_id": ev_id,
            "timestamp": datetime(2026, 10, 18, 14, 35, 12),
            "user_id": usr_b["user_id"],
            "role": usr_b["role"],
            "action": "export",
            "resource": "hr/payroll_summary_2026.xlsx",
            "sensitivity": "critical",
            "bytes": 1_250_000_000,  # 1.25 GB export
            "device": usr_b["device"],
            "source_ip": usr_b["primary_ip"],
            "outcome": "success",
        }
    )
    ground_truth.append({"event_id": ev_id, "scenario": scenario_b_name})

    # Scenario C: A user accesses a resource outside their role's allowed list.
    # Target: usr_014 (sales) accessing engineering production cluster & HR payroll
    scenario_c_name = "Scenario C: Cross-role resource access"
    usr_c = user_map["usr_014"]
    cross_role_events = [
        ("read", "hr/payroll_summary_2026.xlsx", "critical", datetime(2026, 10, 16, 10, 15, 20)),
        ("read", "server/prod_cluster.cfg", "critical", datetime(2026, 10, 16, 10, 17, 45)),
        ("download", "server/prod_cluster.cfg", "critical", datetime(2026, 10, 16, 10, 20, 10)),
    ]
    for action, res, sens, t in cross_role_events:
        ev_id = uuid.uuid4().hex[:16]
        injected_records.append(
            {
                "event_id": ev_id,
                "timestamp": t,
                "user_id": usr_c["user_id"],
                "role": usr_c["role"],
                "action": action,
                "resource": res,
                "sensitivity": sens,
                "bytes": sample_bytes(action, sens),
                "device": usr_c["device"],
                "source_ip": usr_c["primary_ip"],
                "outcome": "success",
            }
        )
        ground_truth.append({"event_id": ev_id, "scenario": scenario_c_name})

    # Scenario D: Restricted data downloaded to an unmanaged device.
    # Target: usr_004 (engineer) downloading critical config to personal unmanaged device
    scenario_d_name = "Scenario D: Restricted download to unmanaged device"
    usr_d = user_map["usr_004"]
    unmanaged_events = [
        ("download", "server/prod_cluster.cfg", "critical", datetime(2026, 10, 19, 21, 10, 5)),
        ("download", "repo/auth_service.git", "high", datetime(2026, 10, 19, 21, 14, 22)),
    ]
    for action, res, sens, t in unmanaged_events:
        ev_id = uuid.uuid4().hex[:16]
        injected_records.append(
            {
                "event_id": ev_id,
                "timestamp": t,
                "user_id": usr_d["user_id"],
                "role": usr_d["role"],
                "action": action,
                "resource": res,
                "sensitivity": sens,
                "bytes": sample_bytes(action, sens),
                "device": "BYOD-UNMANAGED-LAPTOP",
                "source_ip": "198.51.100.88",  # external IP
                "outcome": "success",
            }
        )
        ground_truth.append({"event_id": ev_id, "scenario": scenario_d_name})

    # Scenario E: Seven denied attempts in a row by one user.
    # Target: usr_011 (sales) attempting unauthorized server access
    scenario_e_name = "Scenario E: Seven consecutive denied attempts"
    usr_e = user_map["usr_011"]
    base_time_e = datetime(2026, 10, 21, 16, 4, 10)
    for i in range(7):
        ev_id = uuid.uuid4().hex[:16]
        ev_time = base_time_e + timedelta(seconds=i * 8)
        injected_records.append(
            {
                "event_id": ev_id,
                "timestamp": ev_time,
                "user_id": usr_e["user_id"],
                "role": usr_e["role"],
                "action": "login" if i % 2 == 0 else "read",
                "resource": "server/prod_cluster.cfg" if i % 2 != 0 else "auth/single_sign_on",
                "sensitivity": "critical" if i % 2 != 0 else "low",
                "bytes": 0,
                "device": usr_e["device"],
                "source_ip": usr_e["primary_ip"],
                "outcome": "failure",
            }
        )
        ground_truth.append({"event_id": ev_id, "scenario": scenario_e_name})

    # Scenario F: A user touches a sensitive resource for the first time.
    # Target: usr_035 (analyst) who never previously touched the board financial deck or vault keys
    scenario_f_name = "Scenario F: First-time sensitive resource access"
    usr_f = user_map["usr_035"]
    ev_id = uuid.uuid4().hex[:16]
    injected_records.append(
        {
            "event_id": ev_id,
            "timestamp": datetime(2026, 10, 22, 15, 12, 44),
            "user_id": usr_f["user_id"],
            "role": usr_f["role"],
            "action": "read",
            "resource": "vault/master_encryption_keys.pem",
            "sensitivity": "critical",
            "bytes": 16_384,
            "device": usr_f["device"],
            "source_ip": usr_f["primary_ip"],
            "outcome": "success",
        }
    )
    ground_truth.append({"event_id": ev_id, "scenario": scenario_f_name})

    return pd.DataFrame(injected_records), pd.DataFrame(ground_truth)


def main():
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", 1000)

    print("Generating synthetic normal audit logs...")
    normal_df = generate_normal_logs(days=30)
    users_dir = build_user_directory()

    print("Injecting threat scenarios A through F...")
    injected_df, ground_truth_df = inject_scenarios(users_dir)

    # Combine normal logs and injected logs, then sort by timestamp
    combined_df = pd.concat([normal_df, injected_df], ignore_index=True)
    combined_df = combined_df.sort_values(by="timestamp").reset_index(drop=True)

    # Save to disk
    combined_df.to_csv("logs.csv", index=False)
    ground_truth_df.to_csv("ground_truth.csv", index=False)

    print(f"\nSaved combined logs to logs.csv ({len(combined_df)} records).")
    print(f"Saved ground truth labels to ground_truth.csv ({len(ground_truth_df)} records).")

    print("\n--- Injected Events Per Scenario ---")
    scenario_counts = ground_truth_df["scenario"].value_counts()
    print(scenario_counts.to_string())
    print(f"Total injected events: {len(ground_truth_df)}")


if __name__ == "__main__":
    main()
