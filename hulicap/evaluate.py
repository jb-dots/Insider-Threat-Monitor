"""Evaluation script for Insider Threat Monitor prototype."""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

from hulicap.db import get_all_alerts


def evaluate_detector(
    ground_truth_path: str = "ground_truth.csv",
    db_path: str = "monitor.db",
) -> Dict[str, Any]:
    """
    Compare generated alerts against ground_truth.csv.

    Computes:
      - Per-scenario detection status (Caught vs Missed)
      - Scenario-level precision & recall
      - Alert-level and event-level precision & recall
      - Breakdown of false positives grouped by rule
    """
    gt_file = Path(ground_truth_path)
    if not gt_file.exists():
        raise FileNotFoundError(f"Ground truth file not found: {ground_truth_path}")

    gt_df = pd.read_csv(gt_file)
    scenario_to_events = defaultdict(set)
    event_to_scenario = {}

    for _, row in gt_df.iterrows():
        eid = str(row["event_id"]).strip()
        scen = str(row["scenario"]).strip()
        scenario_to_events[scen].add(eid)
        event_to_scenario[eid] = scen

    total_gt_events = set(event_to_scenario.keys())

    # Load alerts from database
    alerts = get_all_alerts()

    scenario_caught = {scen: False for scen in scenario_to_events}
    scenario_caught_by = defaultdict(set)
    scenario_events_caught = defaultdict(int)

    tp_alerts = 0
    fp_alerts = 0
    false_positives_by_rule = defaultdict(list)

    all_flagged_event_ids = set()

    for alert in alerts:
        raw_eids = [e.strip() for e in str(alert["event_ids"]).split(",") if e.strip()]
        alert_event_set = set(raw_eids)
        all_flagged_event_ids.update(alert_event_set)

        # Check overlap with any ground truth events
        overlapping_scenarios = set()
        for eid in alert_event_set:
            if eid in event_to_scenario:
                scen = event_to_scenario[eid]
                overlapping_scenarios.add(scen)
                scenario_events_caught[scen] += 1

        if overlapping_scenarios:
            tp_alerts += 1
            for scen in overlapping_scenarios:
                scenario_caught[scen] = True
                scenario_caught_by[scen].add(alert["rule_id"])
        else:
            fp_alerts += 1
            false_positives_by_rule[alert["rule_id"]].append(alert)

    # Metrics computation
    total_scenarios = len(scenario_to_events)
    num_scenarios_caught = sum(1 for caught in scenario_caught.values() if caught)
    scenario_recall = (num_scenarios_caught / total_scenarios) if total_scenarios > 0 else 0.0

    total_alerts = len(alerts)
    alert_precision = (tp_alerts / total_alerts) if total_alerts > 0 else 0.0

    tp_events = len(all_flagged_event_ids.intersection(total_gt_events))
    fp_events = len(all_flagged_event_ids - total_gt_events)
    event_precision = (tp_events / len(all_flagged_event_ids)) if all_flagged_event_ids else 0.0
    event_recall = (tp_events / len(total_gt_events)) if total_gt_events else 0.0

    return {
        "scenario_results": [
            {
                "scenario": scen,
                "status": "CAUGHT" if scenario_caught[scen] else "MISSED",
                "total_events": len(scenario_to_events[scen]),
                "events_flagged": scenario_events_caught[scen],
                "caught_by_rules": sorted(list(scenario_caught_by[scen])),
            }
            for scen in sorted(scenario_to_events.keys())
        ],
        "scenario_recall": scenario_recall,
        "scenarios_caught": num_scenarios_caught,
        "total_scenarios": total_scenarios,
        "alert_precision": alert_precision,
        "tp_alerts": tp_alerts,
        "fp_alerts": fp_alerts,
        "total_alerts": total_alerts,
        "event_precision": event_precision,
        "event_recall": event_recall,
        "false_positives_by_rule": dict(false_positives_by_rule),
    }


def main():
    print("=" * 70)
    print("INSIDER THREAT MONITOR - DETECTION BENCHMARK EVALUATION")
    print("=" * 70)

    results = evaluate_detector()

    # 1. Per-scenario performance table
    print("\n--- 1. Per-Scenario Detection Results ---")
    print(f"{'Scenario':<50} | {'Status':<8} | {'Events Flagged':<16} | {'Rules'}")
    print("-" * 95)
    for res in results["scenario_results"]:
        status_str = f"[{res['status']}]"
        events_str = f"{res['events_flagged']}/{res['total_events']}"
        rules_str = ", ".join(res["caught_by_rules"]) if res["caught_by_rules"] else "None (Pending rule)"
        print(f"{res['scenario']:<50} | {status_str:<8} | {events_str:<16} | {rules_str}")

    # 2. Overall Precision and Recall metrics
    print("\n--- 2. Overall Metrics ---")
    print(f"Scenario Recall:  {results['scenario_recall'] * 100:.1f}% ({results['scenarios_caught']}/{results['total_scenarios']} scenarios caught)")
    print(f"Alert Precision:  {results['alert_precision'] * 100:.1f}% ({results['tp_alerts']} true positive alerts, {results['fp_alerts']} false positive alerts)")
    print(f"Event Precision:  {results['event_precision'] * 100:.1f}%")
    print(f"Event Recall:     {results['event_recall'] * 100:.1f}%")

    # 3. False Positives list by rule
    print("\n--- 3. False Positives By Rule (Noise Analysis) ---")
    fp_by_rule = results["false_positives_by_rule"]
    if not fp_by_rule:
        print("No false positives found for any rule (0 false positive alerts).")
    else:
        for rule_id, fp_list in fp_by_rule.items():
            print(f"\nRule: '{rule_id}' -> {len(fp_list)} false positive alert(s):")
            for fp in fp_list:
                print(f"  - Alert ID: {fp['alert_id']} | User: {fp['user_pseudonym']}")
                print(f"    Reason:   {fp['reason']}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
