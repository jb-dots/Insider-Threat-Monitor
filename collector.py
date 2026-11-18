"""Windows Security Event Log collector for HuliCAP Insider Threat Monitor."""

import argparse
import ctypes
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid
import xml.etree.ElementTree as ET
import yaml

from db import (
    filter_new_alerts,
    get_last_record_id,
    get_org_events_df,
    get_org_rules,
    get_org_salt,
    ingest_event,
    ingest_events_batch,
    init_db,
    lookup_resource_sensitivity,
    lookup_user_role,
    pseudonymize_user_with_salt,
    save_org_alerts,
    set_last_record_id,
)
from detector import run_detection_pipeline

CONFIG_PATH = Path("collector_config.yaml")
EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
TARGET_EVENT_IDS = (4624, 4625, 4663)
INTERACTIVE_LOGON_TYPES = {"2", "7", "10", "11"}
SYSTEM_EXACT_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
SYSTEM_PREFIXES = ("DWM-", "UMFD-")


def is_admin() -> bool:
    """Return True if the current process has Windows Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def load_collector_config(config_path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Load collector configuration (org_id, poll_interval_seconds, sources, device)."""
    if not config_path.exists():
        raise FileNotFoundError(
            f"Collector config not found at {config_path}. Create it with 'org_id' set."
        )
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    org_id = (os.environ.get("COLLECTOR_ORG_ID") or str(cfg.get("org_id", ""))).strip()
    if not org_id:
        raise ValueError("collector_config.yaml must specify a non-empty 'org_id'.")

    raw_portal_path = str(cfg.get("company_portal_log_path", "../dunmore_portal/static/company_audit.jsonl"))
    portal_path = Path(raw_portal_path)
    if not portal_path.is_absolute():
        portal_path = (config_path.resolve().parent / portal_path).resolve()

    portal_url = (os.environ.get("COMPANY_PORTAL_URL") or str(cfg.get("company_portal_url", ""))).strip()

    return {
        "org_id": org_id,
        "poll_interval_seconds": int(cfg.get("poll_interval_seconds", 5)),
        "source": str(cfg.get("source", "windows_event_log")),
        "device": str(cfg.get("device", "managed")),
        "enable_company_portal": bool(cfg.get("enable_company_portal", True)),
        "company_portal_log_path": portal_path,
        "company_portal_url": portal_url,
        "enable_windows_event_log": bool(cfg.get("enable_windows_event_log", False)),
    }


def is_system_account(username: str) -> bool:
    """Return True if the Windows account name is a built-in/machine system account."""
    if not username:
        return True
    clean = username.strip()
    if not clean or clean == "-" or clean.endswith("$"):
        return True
    upper = clean.upper()
    if upper in SYSTEM_EXACT_ACCOUNTS:
        return True
    if any(upper.startswith(prefix) for prefix in SYSTEM_PREFIXES):
        return True
    return False


def parse_system_time_to_local(system_time_str: str) -> datetime:
    """
    Parse Windows Event Log UTC SystemTime (ISO-8601) and convert to naive local datetime,
    matching the naive local timestamp convention of logs.csv (YYYY-MM-DD HH:MM:SS).
    """
    raw = system_time_str.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    # Python 3.11+ handles up to 6 fractional digits; truncate 7-digit Windows ticks if needed
    if "." in raw:
        head, tail = raw.split(".", 1)
        tz_idx = max(tail.find("+"), tail.find("-"))
        if tz_idx != -1:
            frac = tail[:tz_idx][:6]
            tz_part = tail[tz_idx:]
            raw = f"{head}.{frac}{tz_part}"
        else:
            raw = f"{head}.{tail[:6]}"
    dt_utc = datetime.fromisoformat(raw)
    if dt_utc.tzinfo is not None:
        dt_local = dt_utc.astimezone().replace(tzinfo=None)
    else:
        dt_local = dt_utc
    return dt_local.replace(microsecond=0)


def _find_el(parent: ET.Element, tag: str) -> Optional[ET.Element]:
    """Find child element with or without the Windows Event XML namespace."""
    el = parent.find(f"e:{tag}", EVENT_NS)
    return el if el is not None else parent.find(tag)


def parse_event_xml(xml_str: str) -> Dict[str, Any]:
    """
    Parse a Windows Event Log XML string into a structured dict using named EventData fields
    (never positional Properties indexing).
    """
    root = ET.fromstring(xml_str)
    system_el = _find_el(root, "System")

    if system_el is None:
        raise ValueError("Invalid Windows Event XML: missing System element.")

    event_id_el = _find_el(system_el, "EventID")
    record_id_el = _find_el(system_el, "EventRecordID")
    time_el = _find_el(system_el, "TimeCreated")

    event_id = int(event_id_el.text.strip()) if event_id_el is not None and event_id_el.text else 0
    record_id = int(record_id_el.text.strip()) if record_id_el is not None and record_id_el.text else 0
    system_time = time_el.attrib.get("SystemTime", "") if time_el is not None else ""

    fields: Dict[str, str] = {}
    event_data_el = _find_el(root, "EventData")
    if event_data_el is not None:
        for data_el in event_data_el:
            name = data_el.attrib.get("Name")
            if name:
                fields[name] = (data_el.text or "").strip()

    return {
        "event_id": event_id,
        "record_id": record_id,
        "system_time": system_time,
        "fields": fields,
    }


def _map_4663_access(accesses_text: str) -> Optional[str]:
    """
    Map Windows 4663 Accesses/AccessList text to HuliCAP action.
    - ReadData or ListDirectory -> read
    - DELETE -> delete
    - WriteData or AppendData -> None (ignored)
    """
    if not accesses_text:
        return None
    text_upper = accesses_text.upper()
    if "DELETE" in text_upper or "%%1537" in text_upper:
        return "delete"
    if "READDATA" in text_upper or "LISTDIRECTORY" in text_upper or "%%4416" in text_upper:
        return "read"
    if (
        "WRITEDATA" in text_upper
        or "APPENDDATA" in text_upper
        or "%%4417" in text_upper
        or "%%4418" in text_upper
    ):
        return None
    return None


def normalize(
    raw_event: Any,
    org_id: Optional[str] = None,
    org_salt: Optional[str] = None,
    role_lookup: Optional[Callable[[str, str], str]] = None,
    sensitivity_lookup: Optional[Callable[[str, str], str]] = None,
    device: str = "managed",
) -> Optional[Dict[str, Any]]:
    """
    Normalize a raw Windows Security Event (XML string or parsed dict) to the HuliCAP schema.
    Returns None if the event should be filtered out (unsupported ID, system account,
    non-interactive 4624 logon type, or ignored 4663 access mask).
    """
    parsed = parse_event_xml(raw_event) if isinstance(raw_event, str) else raw_event
    win_event_id = int(parsed.get("event_id", 0))
    if win_event_id not in TARGET_EVENT_IDS:
        return None

    fields = parsed.get("fields", {})
    if win_event_id in (4624, 4625):
        account_name = fields.get("TargetUserName", "")
    else:
        account_name = fields.get("TargetUserName") or fields.get("SubjectUserName", "")

    if is_system_account(account_name):
        return None

    if win_event_id == 4624:
        logon_type = fields.get("LogonType", "")
        if logon_type not in INTERACTIVE_LOGON_TYPES:
            return None
        action = "login"
        outcome = "success"
        resource = "auth/windows_logon"
    elif win_event_id == 4625:
        action = "login"
        outcome = "denied"
        resource = "auth/windows_logon"
    else:  # 4663
        accesses = fields.get("Accesses") or fields.get("AccessList") or ""
        mapped_action = _map_4663_access(accesses)
        if mapped_action is None:
            return None
        action = mapped_action
        outcome = "success"
        resource = fields.get("ObjectName", "").strip() or "unknown_object"

    active_org_id = org_id or load_collector_config()["org_id"]
    active_salt = org_salt or get_org_salt(active_org_id)
    if not active_salt:
        raise ValueError(f"Organization '{active_org_id}' not found in database.")

    role_fn = role_lookup or lookup_user_role
    sens_fn = sensitivity_lookup or lookup_resource_sensitivity

    user_pseudonym = pseudonymize_user_with_salt(account_name.strip(), active_salt)
    role = role_fn(active_org_id, account_name) if role_fn else "unknown"
    sensitivity = sens_fn(active_org_id, resource) if sens_fn else "normal"

    raw_ip = fields.get("IpAddress", "").strip()
    source_ip = raw_ip if raw_ip and raw_ip != "-" else "127.0.0.1"

    local_dt = parse_system_time_to_local(parsed["system_time"])
    record_id = int(parsed.get("record_id", 0))
    event_id = f"win_{record_id}" if record_id else f"win_{uuid.uuid4().hex[:12]}"

    return {
        "event_id": event_id,
        "timestamp": local_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_pseudonym,
        "role": role,
        "action": action,
        "resource": resource,
        "sensitivity": sensitivity,
        "bytes": 0,
        "device": device,
        "source_ip": source_ip,
        "outcome": outcome,
        "source": "windows_event_log",
    }


class FileAccessDeduplicator:
    """Collapses repeated 4663 events from the same (user_id, resource) within 2 seconds."""

    def __init__(self, window_seconds: int = 2) -> None:
        self.window = timedelta(seconds=window_seconds)
        self._last_seen: Dict[Tuple[str, str], datetime] = {}

    def should_keep(self, event: Dict[str, Any], win_event_id: int) -> bool:
        if win_event_id != 4663:
            return True
        ts = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
        key = (event["user_id"], event["resource"])
        prev = self._last_seen.get(key)
        if prev is not None and (ts - prev) <= self.window:
            return False
        self._last_seen[key] = ts
        return True


def fetch_windows_security_events(
    last_record_id: Optional[int] = None,
    max_events: Optional[int] = None,
) -> List[str]:
    """
    Read local Windows Security Event Log entries via PowerShell Get-WinEvent (JSON output).
    Collects only from this machine's local Security log.
    """
    if max_events is not None:
        ps_query = (
            f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624,4625,4663}} "
            f"-MaxEvents {int(max_events)}"
        )
    else:
        min_id = int(last_record_id or 0)
        ps_query = (
            f"Get-WinEvent -LogName Security "
            f"-FilterXPath '*[System[(EventID=4624 or EventID=4625 or EventID=4663) "
            f"and EventRecordID>{min_id}]]' -Oldest"
        )

    ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $evts = @({ps_query} | ForEach-Object {{ $_.ToXml() }})
    @{{ events = $evts }} | ConvertTo-Json -Compress -Depth 3
}} catch {{
    if ($_.Exception.Message -match 'No events were found') {{
        '{{"events":[]}}'
    }} else {{
        Write-Error $_.Exception.Message
        exit 1
    }}
}}
""".strip()

    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err_msg = (proc.stderr or proc.stdout or "Unknown PowerShell error").strip()
        raise RuntimeError(f"Failed to read Windows Security Event Log: {err_msg}")

    stdout = proc.stdout.strip()
    if not stdout:
        return []
    payload = json.loads(stdout)
    raw_events = payload.get("events", [])
    if isinstance(raw_events, str):
        return [raw_events]
    return [str(x) for x in raw_events if x]


PORTAL_DEPARTMENT_ROLE_MAP = {
    "engineering": "engineer",
    "sales": "sales",
    "hr": "hr",
    "finance": "analyst",
}


def _portal_resource(doc_id: str, action: str) -> str:
    """Map a portal doc_id/action into a department-prefixed resource identifier."""
    clean_id = (doc_id or "").strip()
    if not clean_id or action in ("login", "login_failed"):
        return "auth/portal"
    if clean_id.startswith("DOC-") and clean_id[4:].isdigit():
        num = int(clean_id[4:])
        if 1 <= num <= 7:
            return f"hr/{clean_id}"
        if 8 <= num <= 14:
            return f"db/{clean_id}"
        if 15 <= num <= 21:
            return f"repo/{clean_id}"
        if 22 <= num <= 28:
            return f"crm/{clean_id}"
        return f"shared/{clean_id}"
    return f"doc/{clean_id}"


PORTAL_ACTION_MAP = {
    "view": "read",
}


def normalize_company_portal_event(
    raw: Dict[str, Any],
    org_salt: str,
) -> Optional[Dict[str, Any]]:
    """Normalize a single Dunmore Corp Portal JSONL record to the HuliCAP events schema."""
    employee_id = str(raw.get("employee_id", "")).strip()
    raw_action = str(raw.get("action", "")).strip().lower()
    ts_raw = str(raw.get("timestamp", "")).strip()
    if not employee_id or not raw_action or not ts_raw:
        return None
    action = PORTAL_ACTION_MAP.get(raw_action, raw_action)

    dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")

    dept = str(raw.get("department", "")).strip().lower()
    role = PORTAL_DEPARTMENT_ROLE_MAP.get(dept, dept or "unknown")
    doc_id = str(raw.get("doc_id", "")).strip()
    resource = _portal_resource(doc_id, action)

    raw_sens = str(raw.get("sensitivity", "normal")).strip().lower()
    sensitivity = "high" if raw_sens in ("restricted", "high", "critical") else "low"

    raw_dev = str(raw.get("device", "managed")).strip().lower()
    device = "UNMANAGED" if raw_dev in ("unmanaged", "byod") else "managed"

    return {
        "event_id": str(raw.get("event_id") or f"prt_{uuid.uuid4().hex[:12]}")[:50],
        "timestamp": timestamp,
        "user_id": pseudonymize_user_with_salt(employee_id, org_salt),
        "role": role,
        "action": action,
        "resource": resource,
        "sensitivity": sensitivity,
        "bytes": int(raw.get("bytes", 0) or 0),
        "device": device,
        "source_ip": str(raw.get("source_ip", "127.0.0.1")).strip(),
        "outcome": str(raw.get("outcome", "success")).strip().lower(),
        "source": "company_portal",
    }


def read_new_portal_lines(log_path: Path, last_line: int) -> Tuple[List[Dict[str, Any]], int]:
    """
    Read complete JSON lines from company_audit.jsonl starting after `last_line`.
    Skips a partially written last line (no trailing newline or incomplete JSON) until complete.
    """
    if not log_path.exists():
        return [], last_line

    records: List[Dict[str, Any]] = []
    processed_line = last_line
    with open(log_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if idx <= last_line:
                continue
            if not line.endswith("\n"):
                # Partially written last line; wait until newline is flushed
                break
            stripped = line.strip()
            if not stripped:
                processed_line = idx
                continue
            try:
                records.append(json.loads(stripped))
                processed_line = idx
            except json.JSONDecodeError:
                # Incomplete JSON line; stop and retry on next poll
                break

    return records, processed_line


def read_new_portal_lines_from_url(url: str, last_line: int) -> Tuple[List[Dict[str, Any]], int]:
    """
    Fetch company_audit.jsonl over HTTP(S) and parse complete JSON lines after `last_line`.
    Used when Dunmore Portal and HuliCAP are deployed as separate services (e.g. on Render).
    """
    import requests

    resp = requests.get(url, timeout=15)
    if resp.status_code == 404:
        return [], last_line
    resp.raise_for_status()

    records: List[Dict[str, Any]] = []
    processed_line = last_line
    lines = resp.text.splitlines(keepends=True)
    for idx, line in enumerate(lines, start=1):
        if idx <= last_line:
            continue
        if not line.endswith("\n"):
            break
        stripped = line.strip()
        if not stripped:
            processed_line = idx
            continue
        try:
            records.append(json.loads(stripped))
            processed_line = idx
        except json.JSONDecodeError:
            break
    return records, processed_line


def collect_company_portal_once(
    org_id: str,
    log_path: Optional[Path] = None,
    run_detector: bool = True,
    portal_url: Optional[str] = None,
) -> Tuple[int, int]:
    """Read new lines from company_audit.jsonl (URL or local file), ingest into DB, and optionally run detection."""
    cfg = load_collector_config()
    if portal_url is None:
        portal_url = cfg.get("company_portal_url", "")
    if log_path is None:
        log_path = cfg["company_portal_log_path"]

    org_salt = get_org_salt(org_id)
    if not org_salt:
        raise ValueError(f"Organization '{org_id}' not found in database.")

    last_line = get_last_record_id(org_id, source="company_portal")
    if portal_url:
        raw_records, new_last_line = read_new_portal_lines_from_url(portal_url, last_line)
    else:
        raw_records, new_last_line = read_new_portal_lines(log_path, last_line)

    normalized = []
    for raw in raw_records:
        norm = normalize_company_portal_event(raw, org_salt=org_salt)
        if norm:
            normalized.append(norm)

    ingested_count = ingest_events_batch(org_id, normalized) if normalized else 0
    if new_last_line > last_line:
        set_last_record_id(org_id, new_last_line, source="company_portal")

    new_alerts_count = 0
    if ingested_count > 0 and run_detector:
        new_alerts_count = run_live_detection(org_id, org_salt, source="company_portal")

    return ingested_count, new_alerts_count


def run_once(cfg: Dict[str, Any]) -> None:
    """Read recent events from enabled sources, normalize, and print without writing to DB."""
    org_id = cfg["org_id"]
    org_salt = get_org_salt(org_id)
    if not org_salt:
        print(f"ERROR: Organization '{org_id}' not found in database.")
        sys.exit(1)

    if cfg.get("enable_company_portal"):
        last_line = get_last_record_id(org_id, source="company_portal")
        if cfg.get("company_portal_url"):
            raw_records, _ = read_new_portal_lines_from_url(cfg["company_portal_url"], last_line)
        else:
            raw_records, _ = read_new_portal_lines(cfg["company_portal_log_path"], last_line)
        sample = [
            normalize_company_portal_event(r, org_salt=org_salt)
            for r in raw_records[:50]
        ]
        sample = [s for s in sample if s]
        print(json.dumps(sample, indent=2))
        print(
            f"\n[company_portal] Displayed {len(sample)} normalized event(s) "
            f"(of {len(raw_records)} unread line(s)). No database writes performed."
        )

    if cfg.get("enable_windows_event_log"):
        xml_events = fetch_windows_security_events(max_events=50)
        dedup = FileAccessDeduplicator(window_seconds=2)
        normalized_list: List[Dict[str, Any]] = []

        # Reverse so oldest-first for accurate 2-second deduplication
        for xml_str in reversed(xml_events):
            parsed = parse_event_xml(xml_str)
            norm = normalize(
                parsed,
                org_id=org_id,
                org_salt=org_salt,
                device=cfg["device"],
            )
            if norm and dedup.should_keep(norm, parsed["event_id"]):
                normalized_list.append(norm)

        print(json.dumps(normalized_list, indent=2))
        print(
            f"\n[windows_event_log] Displayed {len(normalized_list)} normalized event(s) "
            f"from last {len(xml_events)} raw Security event(s). No database writes performed."
        )


def run_live_detection(org_id: str, org_salt: str, source: str = "windows_event_log") -> int:
    """Run the detection pipeline on collected events and save any newly triggered alerts."""
    df = get_org_events_df(org_id, source=source)
    if df.empty:
        return 0
    org_rules = get_org_rules(org_id)
    alerts = run_detection_pipeline(df, org_id, org_rules, org_salt)
    new_alerts = filter_new_alerts(org_id, alerts)
    if new_alerts:
        save_org_alerts(new_alerts, org_id)
    return len(new_alerts)


def run_poll_loop(cfg: Dict[str, Any]) -> None:
    """Continuously poll enabled log sources and ingest normalized events."""
    org_id = cfg["org_id"]
    poll_interval = cfg["poll_interval_seconds"]
    use_portal = bool(cfg.get("enable_company_portal"))
    use_windows = bool(cfg.get("enable_windows_event_log"))

    if not use_portal and not use_windows:
        print("ERROR: Both enable_company_portal and enable_windows_event_log are false in collector_config.yaml.")
        sys.exit(1)

    org_salt = get_org_salt(org_id)
    if not org_salt:
        print(f"ERROR: Organization '{org_id}' not found in database.")
        sys.exit(1)

    dedup = FileAccessDeduplicator(window_seconds=2)
    win_last_record_id = get_last_record_id(org_id, source="windows_event_log") if use_windows else 0
    portal_last_line = get_last_record_id(org_id, source="company_portal") if use_portal else 0

    enabled_desc = []
    if use_portal:
        portal_target = cfg.get("company_portal_url") or str(cfg["company_portal_log_path"])
        enabled_desc.append(f"company_portal ({portal_target}, after line {portal_last_line})")
    if use_windows:
        enabled_desc.append(f"windows_event_log (after RecordId {win_last_record_id})")
    print(f"Starting HuliCAP collector for org '{org_id}' every {poll_interval}s: {', '.join(enabled_desc)}...")

    while True:
        try:
            if use_portal:
                ingested_portal, alerts_portal = collect_company_portal_once(
                    org_id=org_id,
                    log_path=cfg["company_portal_log_path"],
                    run_detector=True,
                    portal_url=cfg.get("company_portal_url", ""),
                )
                if ingested_portal > 0:
                    portal_last_line = get_last_record_id(org_id, source="company_portal")
                    print(
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                        f"[company_portal] Ingested {ingested_portal} event(s) (last line={portal_last_line}); "
                        f"{alerts_portal} new alert(s) flagged."
                    )

            if use_windows:
                xml_events = fetch_windows_security_events(last_record_id=win_last_record_id)
                max_seen_id = win_last_record_id
                ingested_win = 0

                for xml_str in xml_events:
                    parsed = parse_event_xml(xml_str)
                    rec_id = int(parsed.get("record_id", 0))
                    if rec_id > max_seen_id:
                        max_seen_id = rec_id

                    norm = normalize(
                        parsed,
                        org_id=org_id,
                        org_salt=org_salt,
                        device=cfg["device"],
                    )
                    if norm and dedup.should_keep(norm, parsed["event_id"]):
                        ingest_event(org_id, norm)
                        ingested_win += 1

                if max_seen_id > win_last_record_id:
                    set_last_record_id(org_id, max_seen_id, source="windows_event_log")
                    win_last_record_id = max_seen_id

                if ingested_win > 0:
                    new_alerts_count = run_live_detection(org_id, org_salt, source="windows_event_log")
                    print(
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                        f"[windows_event_log] Ingested {ingested_win} event(s) (last RecordId={win_last_record_id}); "
                        f"{new_alerts_count} new alert(s) flagged."
                    )
        except KeyboardInterrupt:
            print("\nCollector stopped by user.")
            break
        except Exception as exc:
            print(f"[ERROR] Collector poll failed: {exc}", file=sys.stderr)

        time.sleep(poll_interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="HuliCAP Log Collector (Company Portal & Windows Event Log)")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Read unread events, print normalized output, and exit without writing to DB.",
    )
    args = parser.parse_args()

    cfg = load_collector_config()
    if cfg.get("enable_windows_event_log") and not is_admin():
        print(
            "ERROR: enable_windows_event_log is true, so collector.py must be run as Administrator.\n"
            "Please open an elevated PowerShell/Command Prompt (Run as administrator) and try again,\n"
            "or set enable_windows_event_log: false in collector_config.yaml."
        )
        sys.exit(1)

    init_db()

    if args.once:
        run_once(cfg)
    else:
        run_poll_loop(cfg)


if __name__ == "__main__":
    main()
