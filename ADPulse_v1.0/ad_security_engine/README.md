# 🛡️ AD Security Continuous Assessment Engine

A **lightweight, automated, read-only** Active Directory security monitoring tool that continuously detects misconfigurations, attack paths, and drift — using only a standard domain user account.

---

## ✅ Key Features

| Feature | Details |
|---------|---------|
| **Zero admin rights** | Runs as a standard Domain User — LDAP is readable by any authenticated user |
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
- Domain-joined machine (or network access to a DC on port 389/636)
- A standard domain user account (no admin rights)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure
```bash
cp config.ini.example config.ini
# Edit config.ini with your DC address, service account credentials, etc.
```

### 4. Test Connection
```bash
python main.py --test-connection
```

### 5. Run Your First Scan
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
username = svc-secmonitor        # Standard domain user
password = YourStrongPassword
port     = 389                   # 636 for LDAPS (recommended)
use_ssl  = false

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

### Step 1 — Create the service account (run once as Domain Admin)
```powershell
.\install\create_service_account.ps1 -OUPath "OU=ServiceAccounts,DC=company,DC=local"
```
This creates `svc-secmonitor` as a standard domain user with a random strong password.

### Step 2 — Configure
Edit `config.ini` with the generated password and your environment settings.

### Step 3 — Install as Scheduled Task
```powershell
.\install\install_scheduled_task.ps1 `
    -ServiceAccount "CORP\svc-secmonitor" `
    -ServicePassword "YourPassword" `
    -InstallDir "C:\ADSecurityEngine" `
    -IntervalHours 6
```

The tool now runs automatically every 6 hours. Done.

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
│   ├── create_service_account.ps1  # Creates the low-priv service account
│   └── install_scheduled_task.ps1  # Installs as Windows Scheduled Task
├── output/                         # Generated reports (auto-created)
└── logs/                           # Rotating log files (auto-created)
```

---

## 🔐 Security Design Principles

1. **Read-only** — No writes to Active Directory. Ever.
2. **Least privilege** — Standard domain user. LDAP data is readable by design by all domain members.
3. **No network listeners** — The tool only makes outbound LDAP connections.
4. **Local storage only** — All data stays in a local SQLite file.
5. **Credential security** — Service account password is in `config.ini`. Restrict file permissions.

### Securing config.ini on Windows
```powershell
# Restrict config.ini to only the service account and Administrators
$acl = Get-Acl "C:\ADSecurityEngine\config.ini"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "CORP\svc-secmonitor", "Read", "Allow")
$acl.SetAccessRule($rule)
Set-Acl "C:\ADSecurityEngine\config.ini" $acl
```

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
