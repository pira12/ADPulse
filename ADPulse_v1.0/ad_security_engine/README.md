# 🛡️ AD Security Continuous Assessment Engine

A **lightweight, automated, read-only** Active Directory security monitoring tool that continuously detects misconfigurations, attack paths, and drift — just run it on a domain-joined Windows VM with read access to AD.

---

## ✅ Key Features

| Feature | Details |
|---------|---------|
| **No service account** | Uses integrated Windows auth — just run on a domain-joined VM with AD read access |
| **Fully automated** | Runs as a Windows Scheduled Task or daemon, zero manual effort |
| **Baseline & delta** | Detects *changes* between scans, not just point-in-time issues |
| **Finding policy lifecycle** | Mark findings as `accepted_risk`, `in_remediation`, or `resolved` via `--policy` CLI |
| **Parallel LDAP scan** | All 28 AD queries run concurrently — faster scans on large environments |
| **Professional reports** | Auto-generates branded PDF and interactive HTML reports with policy badges |
| **Email alerting** | Sends severity-filtered alerts with the PDF attached |
| **SQLite storage** | No external database — single file, zero infrastructure |
| **Cross-platform** | Python — runs on Windows, Linux (for hybrid environments) |

---

## 🔍 What It Detects

### Kerberos Attack Paths
- **Kerberoastable accounts** — users/services with SPNs (offline password cracking risk)
- **AS-REP Roastable accounts** — pre-authentication disabled (no credential needed to attack)
- **Unconstrained delegation** — systems that cache TGTs (full domain takeover risk if compromised)
- **Constrained delegation** — audited and flagged for review

### Privileged Access
- **DCSync rights** — non-DC accounts with DS-Replication-Get-Changes-All (can dump all hashes)
- **Dormant privileged accounts** — admin accounts inactive for 90+ days or never logged on
- **Nested group privilege** — accounts reaching Domain Admins through intermediate group chains
- **Privileged Kerberoastable accounts** — service accounts in privileged groups (crack hash = instant admin)
- **Privileged group changes** — additions/removals from Domain Admins, Enterprise Admins, etc.
- **AdminCount=1 orphans** — former admin accounts with leftover elevated ACLs
- New accounts appearing since last scan

### Password Hygiene
- **Password Never Expires** accounts (especially dangerous if privileged)
- **Stale accounts** — enabled users with no recent logon activity
- **Password policy weaknesses** — short minimum length, no lockout, low history

### Infrastructure
- **Stale computer accounts** — decommissioned machines still in AD
- **End-of-life operating systems** — Windows XP, Server 2003/2008, Windows 7, etc.
- Unconstrained delegation on non-DC machines

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- A domain-joined Windows VM with read access to the AD environment

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure
```bash
cp config.ini.example config.ini
```
Edit `config.ini` — you only need to fill in **server** and **domain**. Leave username/password blank to use integrated Windows auth.

### 4. Where to Find Your Config Values

Open a **Command Prompt** on your Windows VM and run these commands:

| Setting | How to find it | Example value |
|---------|---------------|---------------|
| **server** | Run `nltest /dsgetdc:` — look for the **DC** line. Or run `echo %LOGONSERVER%` (returns `\\DC01`, so your server is `DC01.yourdomain.local`). You can also open **Active Directory Users and Computers** — the DC is shown in the tree root. | `dc01.corp.local` |
| **domain** | Run `echo %USERDNSDOMAIN%` — this prints your domain name directly. Or check **System** > **Full computer name** (e.g. `PC01.corp.local` means domain is `corp.local`). | `corp.local` |
| **username** | Leave blank — integrated auth uses your Windows login automatically. | *(empty)* |
| **password** | Leave blank — same reason. | *(empty)* |
| **port** | Use `389` (default). Only change to `636` if your organization requires encrypted LDAP. | `389` |
| **use_ssl** | Set to `false` for port 389, `true` for port 636. | `false` |

### 5. Test Connection
```bash
python main.py --test-connection
```

### 6. Run Your First Scan
```bash
python main.py
```

Reports appear in `./output/` as both HTML and PDF.

---

## ⚙️ Configuration Reference

```ini
[ldap]
server   = dc01.company.local   # Your domain controller
domain   = company.local         # Your domain
username =                       # Leave blank for integrated Windows auth
password =                       # Leave blank for integrated Windows auth
port     = 389                   # 389 = LDAP, 636 = LDAPS (encrypted)
use_ssl  = false                 # true if using port 636

[scanning]
scan_interval_hours = 6          # For daemon mode
stale_account_days  = 60         # Flag accounts inactive this long
privileged_groups   = Domain Admins,Enterprise Admins,Schema Admins,...

[alerting]
email_enabled       = true
smtp_server         = mail.company.local
alert_recipients    = security-team@company.local
min_alert_severity  = HIGH       # Send email for HIGH and CRITICAL only

[reporting]
company_name = ACME Corp
generate_pdf = true
generate_html = true
output_dir   = ./output
```

---

## 🖥️ Windows Deployment (Recommended)

### Step 1 — Configure
```bash
cp config.ini.example config.ini
```
Fill in **server** and **domain** (see the table above). Leave username/password blank.

### Step 2 — Install as Scheduled Task
```powershell
.\install\install_scheduled_task.ps1 -InstallDir "C:\ADSecurityEngine" -IntervalHours 6
```

The task runs as your current Windows user with integrated AD authentication. No service account needed. Done.

---

## 🔌 Offline / Air-Gapped Deployment

For VMs with **no internet access and no Python installed** (common for read-only AD-joined VMs):

### Step 1 — Build the portable package

**Option A — From Linux (recommended if you develop on Linux):**
```bash
cd ADPulse_v1.0/ad_security_engine/install
chmod +x build_offline_package.sh
./build_offline_package.sh
```

**Option B — From a Windows machine with internet:**
```powershell
cd ADPulse_v1.0\ad_security_engine\install
.\prepare_offline_package.ps1
```

Both produce an `ADPulse_Portable` folder containing:
- **Portable Python** (Windows embeddable — no installer needed)
- **All dependency wheels** pre-installed into the Python environment
- **ADPulse source code**
- **`Run-ADPulse.bat`** — double-click to scan

### Step 2 — Transfer to the air-gapped VM via RDP

1. In your RDP client, enable drive redirection:
   **Local Resources → More → Drives → check your local drive**
2. Connect to the VM
3. Inside the RDP session, open File Explorer and go to `\\tsclient\`
4. Copy the `ADPulse_Portable` folder to `C:\` on the VM

### Step 3 — Run on the VM

```
Double-click Run-ADPulse.bat
```
On first run it creates `config.ini` and opens it in Notepad. Fill in your DC settings, then double-click again to scan. **No installation, no Python setup, no admin rights needed.**

To test connectivity before a full scan:
```
Double-click Test-Connection.bat
```

To set up recurring automated scans:
```
Double-click Install-ScheduledTask.bat
```

---

## 📋 CLI Reference

```bash
python main.py                      # Run a single scan
python main.py --daemon             # Run continuously on schedule
python main.py --test-connection    # Test LDAP connectivity only
python main.py --report-only        # Regenerate report from last scan
python main.py --history            # Show recent scan history
python main.py --diff               # Show what changed between last two scans
python main.py --config /path.ini   # Use a custom config file

# Finding policy management
python main.py --policy list
python main.py --policy accept    KERB-001-STANDARD --reason "Legacy app, accepted risk"
python main.py --policy remediate PRIV-001-DORMANT-ADMIN --reason "Ticket #1234 in progress"
python main.py --policy resolve   ACCT-001-STALE
python main.py --policy clear     KERB-001-STANDARD
```

Policy decisions are stored in `policy.json` alongside `config.ini`. On the next scan:
- `accepted_risk` and `resolved` findings are removed from the active report and appear in the HTML audit trail section.
- `in_remediation` findings remain visible with an **IN REMEDIATION** badge and the reason text.
- If a `resolved` finding reappears, it is automatically demoted back to `in_remediation`.

---

## 📁 Project Structure

```
ad_security_engine/
├── main.py                         # Entry point, orchestrator, --policy CLI
├── config.ini.example              # Configuration template
├── requirements.txt
├── modules/
│   ├── ldap_collector.py           # 28 read-only LDAP queries (parallel via ThreadPoolExecutor)
│   ├── baseline_engine.py          # SQLite baseline & delta detection
│   ├── detections.py               # 30+ security detection methods
│   ├── policy_manager.py           # Finding lifecycle (accepted_risk/in_remediation/resolved)
│   ├── report_generator.py         # HTML (policy badges + audit trail), PDF, CSV, trend dashboard
│   └── notifier.py                 # Console, text, JSON, Event Log, webhook, syslog, email
├── tests/
│   ├── fixtures.py                 # Shared mock AD data for all tests
│   ├── test_detections_new.py      # Tests for new detection methods
│   ├── test_parallel_scan.py       # Tests for parallel LDAP collection
│   ├── test_policy_manager.py      # Tests for PolicyManager
│   ├── test_report_policy.py       # Tests for policy badges in HTML
│   └── test_notifier_policy.py     # Tests for suppressed count in console/PDF
├── install/
│   ├── install_scheduled_task.ps1  # Installs as Windows Scheduled Task
│   ├── build_offline_package.sh    # Linux: builds portable Windows package
│   ├── prepare_offline_package.ps1 # Windows: builds portable package (run with internet)
│   └── install_offline.ps1         # Installs from offline bundle (no internet)
├── output/                         # Generated reports (auto-created)
└── logs/                           # Rotating log files (auto-created)
```

---

## 🔐 Security Design Principles

1. **Read-only** — No writes to Active Directory. Ever.
2. **No service account** — Uses integrated Windows auth via the logged-in user's Kerberos session.
3. **No network listeners** — The tool only makes outbound LDAP connections.
4. **Local storage only** — All data stays in a local SQLite file.

---

## 📊 Report Severity Scoring

| Severity | Score Weight | Examples |
|----------|-------------|---------|
| CRITICAL | ×40 | Unconstrained delegation, privileged Kerberoastable accounts, no lockout policy |
| HIGH | ×15 | AS-REP Roastable accounts, password never expires on privileged accounts |
| MEDIUM | ×5  | Constrained delegation, stale privileged accounts, weak password policy |
| LOW | ×1  | Stale computer accounts, minor policy gaps |
| INFO | ×0  | New accounts created (informational only) |

Maximum risk score: **100**

---

## 🆕 Extending the Tool

To add a new detection, add a method to `modules/detections.py`:

```python
def detect_my_new_check(self, data: list) -> list:
    findings = []
    # ... your detection logic ...
    if something_bad:
        findings.append({
            "finding_id": "MY-001-UNIQUE-ID",
            "category":   "My Category",
            "severity":   "HIGH",
            "title":      "Short Title",
            "description": "Explanation of the risk...",
            "affected":   ["account1", "account2"],
            "details":    {"count": 2},
            "remediation": "Steps to fix this...",
        })
    return findings
```

Then call it in `run_all_detections()`. That's it.

---

## 📄 License

Internal use. All rights reserved.
