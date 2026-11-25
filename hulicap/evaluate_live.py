"""Live evaluation script comparing HuliCAP company_portal alerts against company_ground_truth.csv."""

from collections import defaultdict
from pathlib import Path
import sys
from typing import Any, Dict, List, Set
import pandas as pd

from hulicap.collector import load_collector_config
from hulicap.db import Event, get_all_alerts, get_org_salt, get_session, init_db, pseudonymize_user_with_salt


def get_portal_event_ids(org_id: str) -> Set[str]:
    """Return all event_ids in the DB belonging to source='company_portal' for org_id."""
    with get_session() as session:
        rows = (
            session.query(Event.event_id)
            .filter(Event.org_id == org_id, Event.source == "company_portal")
            .all()
        )
        return {str(r[0]) for r in rows}


def get_portal_alerts(org_id: str) -> List[Dict[str, Any]]:
    """Return HuliCAP alerts for org_id whose event_ids originate from source='company_portal'."""
    portal_eids = get_portal_event_ids(org_id)
    if not portal_eids:
        return []
    all_alerts = get_all_alerts(org_id=org_id)
    matched = []
    for alert in all_alerts:
        eids = {e.strip() for e in str(alert.get("event_ids", "")).split(",") if e.strip()}
        if eids & portal_eids:
            matched.append(alert)
    return matched


def evaluate_live(
    gt_path: Path | None = None,
    org_id: str | None = None,
) -> Dict[str, Any]:
    """Compare company_portal alerts against company_ground_truth.csv."""
    init_db()
    cfg = load_collector_config()
    target_org_id = org_id or cfg["org_id"]
    org_salt = get_org_salt(target_org_id)
    if not org_salt:
        raise ValueError(f"Organization '{target_org_id}' not found in database.")

    if gt_path is None:
        gt_path = cfg["company_portal_log_path"].parent / "company_ground_truth.csv"
    if not gt_path.exists():
        raise FileNotFoundError(f"Ground truth file not found: {gt_path}")

    gt_df = pd.read_csv(gt_path)
    portal_alerts = get_portal_alerts(target_org_id)

    # Index alerts by (rule_id, user_pseudonym)
    alerts_by_key: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for alert in portal_alerts:
        alerts_by_key[(alert["rule_id"], alert["user_pseudonym"])].append(alert)

    matched_alert_ids: Set[str] = set()
    scenario_rows = []
    total_tp = 0
    total_fn = 0
    total_fp = 0

    for idx, row in gt_df.iterrows():
        rule = str(row["rule"]).strip()
        emp_id = str(row["employee_id"]).strip()
        ts_str = str(row["time"]).strip()
        label = str(row["label"]).strip().upper()
        pseudonym = pseudonymize_user_with_salt(emp_id, org_salt)

        matching = alerts_by_key.get((rule, pseudonym), [])
        for a in matching:
            matched_alert_ids.add(a["alert_id"])

        if label == "TP":
            tp = 1 if matching else 0
            fn = 0 if matching else 1
            fp = 0
            precision = 1.0 if tp > 0 else 0.0
            recall = float(tp)
            status = "CAUGHT" if tp > 0 else "MISSED"
            total_tp += tp
            total_fn += fn
        else:  # Expected FP scenario (e.g. legitimate month-end export)
            tp = 0
            fn = 0
            fp = len(matching)
            precision = 0.0 if fp > 0 else 1.0
            recall = 1.0  # No TP expected
            status = "FP_ALERT" if fp > 0 else "NO_FP"
            total_fp += fp

        scenario_rows.append(
            {
                "scenario": f"{rule} ({emp_id}, {label})",
                "rule": rule,
                "employee_id": emp_id,
                "pseudonym": pseudonym,
                "time": ts_str,
                "expected_label": label,
                "status": status,
                "matched_alerts": len(matching),
                "precision": precision,
                "recall": recall,
            }
        )

    unmatched_alerts = [a for a in portal_alerts if a["alert_id"] not in matched_alert_ids]
    total_fp += len(unmatched_alerts)

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0

    return {
        "org_id": target_org_id,
        "total_portal_alerts": len(portal_alerts),
        "total_tp": total_tp,
        "total_fn": total_fn,
        "total_fp": total_fp,
        "unmatched_alerts": unmatched_alerts,
        "overall_precision": overall_precision,
        "overall_recall": overall_recall,
        "scenarios": scenario_rows,
    }


def main() -> None:
    print("=" * 78)
    print("HULICAP LIVE PORTAL EVALUATION (source = company_portal)")
    print("=" * 78)
    try:
        res = evaluate_live()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Organization:        {res['org_id']}")
    print(f"Company Portal Alerts: {res['total_portal_alerts']}")
    print(f"Overall Precision:   {res['overall_precision']:.2%}")
    print(f"Overall Recall:      {res['overall_recall']:.2%}")
    print("\n--- Per-Scenario Results ---")
    print(f"{'Scenario':<40} {'Status':<10} {'Alerts':<7} {'Precision':<10} {'Recall':<10}")
    print("-" * 78)
    for row in res["scenarios"]:
        print(
            f"{row['scenario']:<40} {row['status']:<10} {row['matched_alerts']:<7} "
            f"{row['precision']:<10.2%} {row['recall']:<10.2%}"
        )

    if res["unmatched_alerts"]:
        print(f"\n--- Unmatched Alerts ({len(res['unmatched_alerts'])}) ---")
        for a in res["unmatched_alerts"]:
            print(f"  - [{a['rule_id']}] {a['user_pseudonym']}: {a['reason']}")


if __name__ == "__main__":
    main()

