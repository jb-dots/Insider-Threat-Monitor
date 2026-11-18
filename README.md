<!-- Insider Threat Monitor: Prototype for monitoring synthetic audit logs and alerting. -->

# HuliCAP Insider Threat Monitor

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
.\venv\Scripts\python.exe collector.py --once

# Continuous polling (every 5 seconds, persists last RecordId in the database)
.\venv\Scripts\python.exe collector.py
```

