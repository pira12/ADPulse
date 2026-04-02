# ADPulse

**Active Directory Security Assessment Engine** - Lightweight, automated, read-only AD security monitoring using only standard domain user privileges.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Privileges-Standard%20Domain%20User-green" alt="Privileges">
  <img src="https://img.shields.io/badge/AD%20Access-Read--Only-brightgreen" alt="Read-Only">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## What is ADPulse?

ADPulse continuously monitors your Active Directory environment for security misconfigurations, attack paths, and drift - **without requiring admin rights**. It connects via standard LDAP (readable by any authenticated domain user), detects 30+ security issues, tracks changes between scans, and generates professional reports.

### Why ADPulse?

- **No elevated privileges** - Runs as a standard Domain User. No Domain Admin, no special ACLs.
- **Completely read-only** - Zero writes to Active Directory. Ever.
- **No infrastructure needed** - SQLite database, no external DB or message queue.
- **No email server required** - File-based outputs (HTML, PDF, JSON, TXT) for manual sharing.
- **Automated drift detection** - Tracks changes between scans (new admin group members, new accounts).
- **Interactive HTML reports** - Filter by severity, search findings, collapse/expand cards.
- **SIEM-ready** - JSON export and optional Windows Event Log integration.
- **Multi-domain support** - Scan multiple AD domains in one run.
- **Finding policy lifecycle** - Mark findings as accepted risk, in remediation, or resolved. Suppressed findings appear in an audit trail section of the HTML report.
- **Exclusion lists** - Suppress accepted-risk findings so reports stay actionable.
- **Severity overrides** - Customize finding priorities to match your organization's risk model.
- **CSV export** - Export findings to CSV for spreadsheet analysis.
- **Email notification** - Send scan results with PDF attachment via SMTP.
- **Webhook/syslog integration** - Push alerts to Slack, Teams, or any SIEM via webhook or syslog.
- **Trend dashboard** - Historical risk score charts in a standalone HTML dashboard.
- **Finding diff (`--diff`)** - See exactly what changed between two scans.
- **Database retention auto-cleanup** - Automatically purge old scan data based on configurable retention policy.

---

## Security Detections (30+)

### Kerberos Attack Paths
| Detection | Severity | Description |
|---|---|---|
| Kerberoastable Accounts | CRITICAL/HIGH | Users with SPNs vulnerable to offline password cracking |
| Privileged Kerberoastable Accounts | CRITICAL | Kerberoastable accounts that are also in privileged groups |
| AS-REP Roastable | CRITICAL/HIGH | Pre-auth disabled - attackable without credentials |
| Unconstrained Delegation | CRITICAL | Systems caching TGTs - full domain takeover risk |
| Constrained Delegation | MEDIUM | Service-specific delegation - audit required |

### Password & Account Hygiene
| Detection | Severity | Description |
|---|---|---|
| Password Not Required | CRITICAL/HIGH | Accounts that can have empty passwords |
| Reversible Encryption | HIGH | Near-plaintext password storage |
| Passwords in Descriptions | HIGH | Credentials in world-readable description fields |
| Password Never Expires | HIGH/MEDIUM | Accounts bypassing password rotation |
| Stale Accounts | HIGH/MEDIUM | Inactive accounts expanding attack surface |

### Privileged Access
| Detection | Severity | Description |
|---|---|---|
| DCSync Rights | CRITICAL | Non-DC accounts with domain replication rights (hash dump risk) |
| Dormant Privileged Accounts | HIGH | Admin accounts inactive for 90+ days or never logged on |
| Nested Group Privilege | MEDIUM | Accounts reaching privileged groups through group nesting chains |
| Privileged Group Changes | CRITICAL | New members added to Domain Admins, etc. (delta) |
| SID History | HIGH/MEDIUM | Migration artifacts enabling privilege escalation |
| Protected Users Coverage | MEDIUM | Privileged accounts missing hardened protections |
| AdminCount Orphans | MEDIUM | Former admins with drifted permissions |

### Domain Configuration & Infrastructure
| Detection | Severity | Description |
|---|---|---|
| Account Lockout Disabled | CRITICAL | Unlimited password spray attacks possible |
| Machine Account Quota | MEDIUM | Any user can join computers to the domain |
| Computers Without LAPS | HIGH/MEDIUM | Shared local admin passwords across machines |
| End-of-Life Operating Systems | CRITICAL-MEDIUM | Unsupported OS (XP, 7, Server 2003/2008/2012) |
| Weak Password Policy | HIGH/MEDIUM | Short minimum length, low history |

### Kerberos & Trust Infrastructure
| Detection | Severity | Description |
|---|---|---|
| KRBTGT Password Age | CRITICAL/HIGH | Stale KRBTGT key enables Golden Ticket persistence |
| Trust Relationships without SID Filtering | HIGH | Cross-forest trusts missing SID filtering allow privilege escalation |
| Duplicate SPNs | MEDIUM | Duplicate Service Principal Names cause authentication failures and audit blind spots |
| DES-Only Encryption | HIGH | Accounts restricted to weak DES encryption |
| Tombstone Lifetime | HIGH/MEDIUM | Non-default tombstone lifetime affects AD recovery and replication hygiene |
| FGPP Coverage Gaps | MEDIUM | Privileged accounts not covered by Fine-Grained Password Policies |

See [DETECTIONS.md](ADPulse_v1.0/ad_security_engine/DETECTIONS.md) for the complete detection catalog with LDAP queries, severity logic, and remediation steps.

---

## Quick Start

### Prerequisites
- Python 3.10+
- Network access to a Domain Controller (port 389 or 636)
- A standard domain user account (Domain Users group)

### Installation

```bash
git clone https://github.com/pira12/ADPulse.git
cd ADPulse/ADPulse_v1.0/ad_security_engine

pip install -r requirements.txt

cp config.ini.example config.ini
# Edit config.ini with your domain controller and service account details
chmod 600 config.ini  # Protect credentials (Linux)
```

### Configuration

Edit `config.ini` with your environment details:

```ini
[ldap]
server = dc01.company.local
domain = company.local
username = svc-secmonitor
password = YourPasswordHere
port = 636           # Use 636 for LDAPS (recommended)
use_ssl = true       # Enable TLS encryption

[scanning]
stale_account_days = 60
privileged_groups = Domain Admins,Enterprise Admins,Schema Admins,Administrators
```

### Run

```bash
# Test connectivity first
python main.py --test-connection

# Run a full scan
python main.py

# Other commands
python main.py --report-only    # Regenerate reports from last scan
python main.py --history        # View scan history
python main.py --daemon         # Run continuously (every 6 hours)
python main.py --diff           # Show what changed between the last two scans

# Finding policy management
python main.py --policy list
python main.py --policy accept  KERB-001-STANDARD --reason "Legacy app, waived until Q3"
python main.py --policy remediate PRIV-001-DORMANT-ADMIN --reason "Ticket #1234 open"
python main.py --policy resolve ACCT-001-STALE
python main.py --policy clear   KERB-001-STANDARD
```

---

## Output & Reports

Each scan generates six output files:

| File | Format | Purpose |
|---|---|---|
| `ADPulse_Report_*.html` | Interactive HTML | Web report with filtering, search, collapsible findings |
| `ADPulse_Report_*.pdf` | Branded PDF | Professional report for management and auditors |
| `ADPulse_Summary_*.txt` | Plain text | Copy-paste into Teams, email, or tickets |
| `ADPulse_Export_*.json` | JSON | SIEM ingestion, automation, ticketing integration |
| `ADPulse_Export_*.csv` | CSV | Spreadsheet analysis, pivot tables, data import |
| `ADPulse_Trend_Dashboard.html` | Interactive HTML | Historical risk score charts and trend visualization |

### Interactive HTML Report Features
- **Click severity cards** to filter findings by severity level
- **Search bar** to find findings by keyword (title, description, affected objects)
- **Category filter** dropdown to show specific detection categories
- **New/Recurring filter** to focus on new findings since last scan
- **Collapsible cards** - click finding headers to expand/collapse details
- **Click "show more"** on affected objects to reveal the full list
- **Dark mode toggle** - switch between light and dark themes
- **Copy summary to clipboard** - one-click copy of the executive summary
- **Permalink anchors** - direct link to any individual finding for easy sharing

---

## Notifications

ADPulse supports multiple notification channels to integrate with your existing workflows.

### Webhook (Slack, Teams, etc.)

```ini
[notifications]
webhook_url = https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX
webhook_format = slack   # slack | teams | generic
```

### Syslog

```ini
[notifications]
syslog_host = siem.company.local
syslog_port = 514
syslog_protocol = udp   # udp | tcp
```

### Email (SMTP with PDF attachment)

```ini
[notifications]
email_enabled = true
smtp_server = smtp.company.local
smtp_port = 587
smtp_use_tls = true
smtp_username = adpulse@company.local
smtp_password = YourSMTPPassword
email_to = security-team@company.local
email_subject = ADPulse Scan Report - {domain} - {date}
email_attach_pdf = true
```

---

## Deployment

### Windows (Recommended)

```powershell
# 1. Create a dedicated service account (run as Domain Admin, one-time setup)
.\install\create_service_account.ps1

# 2. Configure
Copy-Item config.ini.example config.ini
notepad config.ini

# 3. Install as Windows Scheduled Task (runs every 6 hours)
.\install\install_scheduled_task.ps1
```

### Linux

```bash
# Install dependencies
pip install -r requirements.txt

# Configure
cp config.ini.example config.ini
vim config.ini
chmod 600 config.ini

# Option A: Cron job (every 6 hours)
echo "0 */6 * * * cd /opt/adpulse && python main.py" | crontab -

# Option B: Daemon mode
python main.py --daemon
```

---

## Architecture

```
main.py                     Entry point & orchestrator (parallel LDAP scan, policy dispatch)
modules/
  ldap_collector.py         28 read-only LDAP queries, parallel execution via ThreadPoolExecutor
  baseline_engine.py        SQLite database for snapshots, drift detection & retention cleanup
  detections.py             30+ security detection methods
  policy_manager.py         Finding lifecycle — accepted_risk, in_remediation, resolved states
  report_generator.py       Interactive HTML (with policy badges), branded PDF, CSV & trend dashboard
  notifier.py               Console, text, JSON, Event Log, webhook, syslog & email output
install/
  install_scheduled_task.ps1    Windows scheduled task deployment
  build_offline_package.sh      Linux: builds portable Windows package
  prepare_offline_package.ps1   Windows: builds portable package
```

See [ARCHITECTURE.md](ADPulse_v1.0/ad_security_engine/ARCHITECTURE.md) for detailed system design, data flow diagrams, and module reference.

---

## Privilege Model

ADPulse requires **only a standard Domain User account**. No special permissions or group memberships needed.

```
REQUIRED:    Domain Users (standard membership)
NOT NEEDED:  Domain Admins, Enterprise Admins, Schema Admins,
             Administrators, Account Operators, Backup Operators
```

**How:** Active Directory exposes most object attributes to any authenticated user via LDAP read access by design. ADPulse leverages this to assess security posture without dangerous privileged access.

---

## Security Considerations

- **Credentials**: `config.ini` contains the service account password. Restrict file permissions (`chmod 600` on Linux, ACL on Windows).
- **Network**: Use LDAPS (port 636) for encrypted communication. ADPulse warns if LDAP (389) is used.
- **Output files**: Reports contain sensitive AD data (account names, vulnerabilities). Treat as confidential.
- **No listeners**: ADPulse only makes outbound LDAP connections. No ports opened.
- **Config warning**: ADPulse warns at startup if config.ini is world-readable.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| [ldap3](https://pypi.org/project/ldap3/) | >= 2.9.1 | Pure-Python LDAP v3 client |
| [reportlab](https://pypi.org/project/reportlab/) | >= 4.0.0 | PDF report generation |
| [pywin32](https://pypi.org/project/pywin32/) | (optional) | Windows Event Log writing |

---

## License

MIT License - Copyright (c) 2026 Piraveen Kandiah

See [LICENSE](LICENSE) for details.
