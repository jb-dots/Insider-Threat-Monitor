# HuliCAP Test & Demo Accounts

Reference guide for test accounts configured in the local SQLite database (`monitor.db`).

---

## 1. Main Demo Account (Full Console & Demo Alerts)
Use this account to view the **Alert Queue**, triage incidents, inspect timelines, and review rules.
* **Email:** `demo_analyst@hulicap.test`
* **Password:** `DemoPass123!`
* **Role:** Organization Admin
* **Organization:** `Acme Cyber Defense`
* **Loaded Telemetry:** All 5 demo alerts generated from `logs.csv`

---

## 2. Onboarding & Setup Account (New User Flow)
Use this account to test the **4-step progress indicator**, plan tier selection cards, and Community Guidelines acceptance.
* **Email:** `setup_user@hulicap.test`
* **Password:** `SetupPass123!`
* **Status:** Active, guidelines unaccepted
* **Behavior:** Redirects directly to `/setup` upon login

---

## 3. Platform Super-Admin
Use this account to access platform-wide tenant governance and cross-tenant overview.
* **Email:** `superadmin@hulicap.com`
* **Password:** `Password123!`
* **Role:** Platform Super-Admin
* **Scope:** Platform-level monitoring; zero access to tenant-private raw logs or pseudonyms

---

## 4. Multi-Tenant Isolation Testing Accounts
Use these accounts to verify that Organization A cannot query or view alerts from Organization B.

### Organization Alpha
* **Email:** `admin_a_95b43d@alpha.com`
* **Password:** `Password123!`
* **Role:** Organization Admin
* **Organization:** `Alpha Corp`

### Organization Beta
* **Email:** `admin_b_95b43d@beta.com`
* **Password:** `Password123!`
* **Role:** Organization Admin
* **Organization:** `Beta Corp`

---

## 5. Security & Compliance Test Accounts

### Suspended User (Check 3 Verification)
* **Email:** `charlie@enterprise.com`
* **Password:** `SecurePass123!`
* **Status:** Suspended / Banned
* **Expected Result:** Login halts immediately with *"Your account has been suspended. Contact the administrator."*

---

## Quick Reference Table

| Account Purpose | Email Address | Password | Role / Access Level |
| :--- | :--- | :--- | :--- |
| **Alert Queue Demo** | `demo_analyst@hulicap.test` | `DemoPass123!` | Org Admin (`Acme Cyber Defense`) |
| **Setup & Guidelines Flow** | `setup_user@hulicap.test` | `SetupPass123!` | New User (Pending Guidelines) |
| **Super Admin** | `superadmin@hulicap.com` | `Password123!` | Platform Super-Admin |
| **Tenant Alpha Admin** | `admin_a_95b43d@alpha.com` | `Password123!` | Org Admin (`Alpha Corp`) |
| **Tenant Beta Admin** | `admin_b_95b43d@beta.com` | `Password123!` | Org Admin (`Beta Corp`) |
| **Suspended Account** | `charlie@enterprise.com` | `SecurePass123!` | Blocked / Suspended |

