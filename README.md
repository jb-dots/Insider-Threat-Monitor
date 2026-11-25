<!-- Insider Threat Monitor: Prototype for monitoring synthetic audit logs and alerting. -->

# HuliCAP Insider Threat Monitor

## Project layout

```
app.py                  Streamlit dashboard (entry point)
hulicap/                Core package
  config.py               Platform limits (events per upload, staff seats)
  session_config.py       Session lifetime and idle timeout values
  db.py                   SQLite/SQLAlchemy models and queries
  detector.py             Five detection rules, median/MAD baselines
  collector.py            Live collector (company portal JSONL, Windows Event Log)
  generate_logs.py        Synthetic log generator + ground truth
  evaluate.py             Precision/recall against ground_truth.csv
  evaluate_live.py        Per-scenario evaluation against the portal's ground truth
  create_superadmin.py    Create or update the platform super-admin
  styles.py, logo_assets.py   UI styling and logo helpers
tests/                  Test scripts
tools/                  Development helpers (not part of the app)
  screenshots/            Playwright screenshot scripts
  logo/                   Logo file generation
  verify/                 Playwright UI checks
rules.yaml              Default detection thresholds
collector_config.yaml   Collector settings
logs.csv, ground_truth.csv   Synthetic demo data
```

## Run (always from the project root)

```powershell
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py --server.port 8502
python -m hulicap.collector          # separate terminal
python -m hulicap.evaluate_live      # after running simulator scenarios
python -m hulicap.generate_logs      # regenerate logs.csv / ground_truth.csv
python -m hulicap.create_superadmin  # needs SUPERADMIN_EMAIL / SUPERADMIN_PASSWORD
```

## Enable auditing

Run the following commands in an **elevated (Administrator) PowerShell** on this Windows machine to enable local logon auditing (Event IDs 4624/4625) and object access auditing (Event ID 4663) for the test folder `C:\HuliCAP_TestData`.

### 1. Enable Logon and File System Auditing

```powershell
# Enable Logon auditing (Success and Failure -> Event IDs 4624 and 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable File System (Object Access) auditing (Success and Failure -> Event ID 4663)
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Verify the audit policy settings:

```powershell
auditpol /get /subcategory:"Logon","File System"
```

### 2. Create `C:\HuliCAP_TestData` and Set the Audit Rule (SACL)

```powershell
# Create the test folder
New-Item -ItemType Directory -Path "C:\HuliCAP_TestData" -Force | Out-Null

# Add a FileSystemAuditRule for ReadData and Delete (Success & Failure)
$acl = Get-Acl "C:\HuliCAP_TestData"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "ReadData,Delete",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success,Failure"
)
$acl.AddAuditRule($rule)
Set-Acl -Path "C:\HuliCAP_TestData" -AclObject $acl
```

### 3. Verify and Run the Collector

Configure `org_id` in `collector_config.yaml`, then run in an **Administrator PowerShell**:

```powershell
# Dry run: read the last 50 Security events, print normalized JSON, and do not write to the DB
.\venv\Scripts\python.exe -m hulicap.collector --once

# Continuous polling (every 5 seconds, persists last RecordId in the database)
.\venv\Scripts\python.exe -m hulicap.collector
```

