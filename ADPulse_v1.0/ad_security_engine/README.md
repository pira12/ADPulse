# 🛡️ AD Security Continuous Assessment Engine

A **lightweight, automated, read-only** Active Directory security monitoring tool that continuously detects misconfigurations, attack paths, and drift — just run it on a domain-joined Windows VM with read access to AD.

---

## ✅ Key Features

| Feature | Details |
|---------|---------|
| **No service account** | Uses integrated Windows auth — just run on a domain-joined VM with AD read access |
| **Fully automated** | Runs as a Windows Scheduled Task or daemon, zero manual effort |
| **Baseline & delta** | Detects *changes* between scans, not just point-in-time issues |
| **Professional reports** | Auto-generates branded PDF and HTML reports |
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

### Step 1 — Build the portable package (on a machine WITH internet)
```
cd ad_security_engine\install
Build-Portable-Package.bat
```
> **Note:** Double-clicking the `.bat` file also works. This avoids PowerShell execution policy issues.
This creates an `ADPulse_Portable` folder containing:
- **Portable Python** (embeddable distribution — no installer needed)
- **All dependency wheels** pre-installed
- **ADPulse source code**
- **`Run-ADPulse.bat`** — double-click to scan

### Step 2 — Transfer to the air-gapped VM
Copy the `ADPulse_Portable` folder via:
- **RDP drive redirection** — access `\\tsclient\C\` from within the RDP session
- **Network file share** — copy to `\\fileserver\share\`
- Any other file transfer method your organization allows

### Step 3 — Run on the VM
```
Double-click Run-ADPulse.bat
```
On first run it opens `config.ini` for you to fill in your domain controller settings. That's it — **no installation, no Python setup, no admin rights needed**.

To set up recurring scans as a scheduled task:
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
python main.py --config /path.ini   # Use a custom config file
```

---

## 📁 Project Structure

```
ad_security_engine/
├── main.py                         # Entry point & orchestrator
├── config.ini.example              # Configuration template
├── requirements.txt
├── modules/
│   ├── ldap_collector.py           # All LDAP queries (read-only)
│   ├── baseline_engine.py          # SQLite baseline & delta detection
│   ├── detections.py               # All security finding detectors
│   ├── alerting.py                 # Email alerting
│   └── report_generator.py        # PDF + HTML report generation
├── install/
│   ├── install_scheduled_task.ps1  # Installs as Windows Scheduled Task
│   ├── prepare_offline_package.ps1 # Builds offline bundle (run with internet)
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
