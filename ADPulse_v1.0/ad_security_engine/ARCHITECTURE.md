# ADPulse Architecture Documentation

## Overview

ADPulse is a lightweight, automated, **read-only** Active Directory security monitoring tool. It connects to one or more AD domains using standard domain user credentials (no admin rights), collects security-relevant data via LDAP, detects misconfigurations and vulnerabilities, tracks drift between scans, and generates professional reports. Multi-domain support allows a single ADPulse instance to monitor multiple domains and forest trusts from a centralized configuration.

**Core Design Principles:**
- Zero admin rights required (standard Domain User)
- All AD operations are strictly read-only
- No network listeners — only outbound LDAP connections
- Local-only data storage (SQLite)
- No email server dependency
- Configurable exclusion lists and severity overrides per finding

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLI / Entry Point                          │
│                            main.py                                  │
│  Parses arguments, loads config, orchestrates the 6-step scan       │
│  Modes: scan | --test-connection | --report-only | --history |      │
│         --daemon                                                    │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────────┐
                ▼               ▼                   ▼
   ┌─────────────────┐ ┌───────────────┐ ┌──────────────────┐
   │ LDAPCollector    │ │ BaselineEngine│ │ DetectionEngine  │
   │ ldap_collector.py│ │ baseline_     │ │ detections.py    │
   │                  │ │ engine.py     │ │                  │
   │ Connects to AD   │ │ SQLite DB     │ │ 26+ security     │
   │ via LDAP/NTLM.   │ │ management.   │ │ detectors.       │
   │ ~26 read-only    │ │ Stores        │ │ Point-in-time &  │
   │ query methods.   │ │ snapshots &   │ │ delta-based      │
   │ Zero writes.     │ │ detects drift │ │ analysis.        │
   └────────┬─────────┘ └───────┬───────┘ └────────┬─────────┘
            │                   │                   │
            └───────────────────┼───────────────────┘
                                │
                ┌───────────────┼───────────────────┐
                ▼                                   ▼
   ┌─────────────────────┐              ┌──────────────────────┐
   │ ReportManager        │              │ OutputNotifier        │
   │ report_generator.py  │              │ notifier.py           │
   │                      │              │                       │
   │ HTML + PDF reports   │              │ Console summary       │
   │ with ADPulse         │              │ Plain-text .txt file  │
   │ branding. Uses       │              │ JSON export (SIEM)    │
   │ ReportLab for PDF.   │              │ Windows Event Log     │
   └──────────────────────┘              └───────────────────────┘
```

---

## Data Flow (6-Step Scan Lifecycle)

### Step 1: Connect to Active Directory
- `LDAPCollector` establishes an NTLM-authenticated connection
- Supports LDAP (port 389) and LDAPS (port 636, recommended)
- Connection timeout is configurable
- Uses `ldap3` library — pure Python, no OS dependencies

### Step 2: Collect AD Data
- ~26 specialized LDAP queries run against the domain controller
- All queries use standard LDAP read operations (no writes)
- Data collected includes: users, computers, groups, delegation, password policies, SPNs, UAC flags, SID History, LAPS status, and more
- Results are returned as lists of dictionaries

### Step 3: Update Baseline Database
- Collected data is stored in a local SQLite database
- Each scan creates a new snapshot (identified by a UUID run_id)
- Previous scan data is preserved for delta comparison
- Tables: `snapshots`, `user_objects`, `group_members`, `computer_objects`, `findings_history`

### Step 4: Run Security Detections
- `DetectionEngine` runs 26+ detection methods against the collected data
- **Point-in-time detections**: Analyze current state (Kerberoasting, weak policies, etc.)
- **Delta detections**: Compare against previous scan (new admin group members, new accounts)
- Each finding is a standardized dict with: `finding_id`, `severity`, `title`, `description`, `affected`, `remediation`
- Findings are deduplicated by `finding_id` and sorted by severity

### Step 5: Generate Reports
- `ReportManager` generates HTML and PDF reports
- Reports include: risk score, severity breakdown, finding details, remediation steps
- PDF uses ReportLab with ADPulse branding
- HTML is self-contained (no external dependencies)

### Step 6: Output & Notifications
- Console summary with ANSI colors (severity-coded)
- Plain-text `.txt` summary file (paste into Teams/email/tickets)
- JSON export file (machine-readable, for SIEM/automation)
- Optional Windows Event Log entry (for Splunk/Sentinel ingestion)
- CSV export for spreadsheet analysis
- Webhook notifications (HTTP POST to Slack/Teams/custom endpoints)
- Syslog forwarding (UDP RFC 5424)
- Email delivery via SMTP with PDF attachment

---

## Module Reference

### `main.py` — Entry Point & Orchestrator

| Function | Purpose |
|---|---|
| `setup_logging()` | Configures rotating file + console log handlers |
| `load_config()` | Reads `config.ini`, warns if world-readable |
| `run_scan()` | Executes the full 6-step scan lifecycle |
| `cmd_test_connection()` | Tests LDAP connectivity without scanning |
| `cmd_report_only()` | Regenerates reports from the last scan |
| `cmd_show_history()` | Displays recent scan history from the database |
| `cmd_daemon()` | Runs scans continuously on a configured interval |

### `modules/ldap_collector.py` — LDAP Data Collection

All methods are **read-only**. No LDAP write operations exist in the codebase.

| Method | What it Queries | LDAP Filter Key |
|---|---|---|
| `get_all_users()` | All user accounts with security attributes | `objectCategory=person` |
| `get_kerberoastable_accounts()` | Users with SPNs (Kerberoasting targets) | `servicePrincipalName=*` |
| `get_asreproastable_accounts()` | Pre-auth disabled accounts | UAC `0x400000` |
| `get_accounts_password_never_expires()` | Accounts bypassing password rotation | UAC `0x10000` |
| `get_admincount_accounts()` | AdminSDHolder-protected accounts | `adminCount=1` |
| `get_privileged_group_members()` | Members of specified privileged groups | `objectClass=group` |
| `get_all_computers()` | All computer accounts | `objectClass=computer` |
| `get_domain_controllers()` | Domain controllers | UAC `0x2000` |
| `get_unconstrained_delegation_accounts()` | TGT-caching delegation (excl. DCs) | UAC `0x80000` |
| `get_constrained_delegation_accounts()` | Service-specific delegation | `msDS-AllowedToDelegateTo=*` |
| `get_password_policy()` | Default domain password policy | `objectClass=domainDNS` |
| `get_gpo_links()` | GPO links at domain/OU level | `gPLink` attribute |
| `get_fine_grained_password_policies()` | Fine-Grained Password Policies (PSOs) | `msDS-PasswordSettings` |
| `get_domain_info()` | Domain metadata & functional levels | `objectClass=domainDNS` |
| `get_password_not_required_accounts()` | Accounts that can have empty passwords | UAC `0x20` |
| `get_reversible_encryption_accounts()` | Passwords stored as near-plaintext | UAC `0x80` |
| `get_accounts_with_sid_history()` | Accounts with SID History (migration risk) | `sIDHistory=*` |
| `get_protected_users_members()` | Members of Protected Users group | `sAMAccountName=Protected Users` |
| `get_users_with_description_passwords()` | Description fields containing password keywords | `description=*pass*` |
| `get_computers_without_laps()` | Machines without LAPS deployed | Missing `ms-Mcs-AdmPwdExpirationTime` |
| `get_krbtgt_account()` | KRBTGT password age | `sAMAccountName=krbtgt` |
| `get_trust_relationships()` | Domain trust enumeration | `objectClass=trustedDomain` |
| `get_tombstone_lifetime()` | Forest tombstone lifetime | `CN=Directory Service,CN=Windows NT` |
| `get_dns_zones()` | AD DNS zones | `objectClass=dnsZone` |
| `get_des_only_accounts()` | DES-only encryption users | UAC `0x200000` |
| `get_expiring_accounts()` | Accounts expiring soon | `accountExpires` attribute |

### `modules/baseline_engine.py` — SQLite Baseline & Delta Detection

**Database Schema:**

```sql
snapshots         — Scan metadata (run_id, status, timestamps, findings count)
user_objects      — User account snapshots per scan run
group_members     — Privileged group membership per scan run
computer_objects  — Computer account snapshots per scan run
findings_history  — All findings ever raised (with first_seen/is_new tracking)
```

**Key Methods:**

| Method | Purpose |
|---|---|
| `start_scan()` / `finish_scan()` / `fail_scan()` | Scan lifecycle management |
| `save_users()` | Store user account snapshot for delta comparison |
| `save_group_members()` | Store privileged group membership snapshot |
| `get_group_member_delta()` | Compare group membership between scans |
| `get_new_users()` / `get_removed_users()` | Detect account creation/deletion |
| `save_findings()` | Persist findings with first_seen/is_new tracking |
| `get_findings_for_run()` | Retrieve findings for a specific scan |
| `get_finding_trend()` | Get historical occurrences of a specific finding |
| `get_finding_diff()` | Compare findings between scans |
| `get_trend_data()` | Historical trend data for dashboard |
| `cleanup_old_scans()` | Database retention cleanup |

### `modules/detections.py` — Security Finding Detectors

See [DETECTIONS.md](DETECTIONS.md) for a complete catalog of all 26+ detections.

### `modules/report_generator.py` — HTML & PDF Reports

- Generates self-contained HTML reports (no external CSS/JS)
- Generates branded PDF reports using ReportLab
- Includes: risk score card, severity breakdown, finding details, remediation steps
- ADPulse branding: Primary Blue `#0053A4`, Orange Accent `#FF8800`

### `modules/notifier.py` — Output & Notifications

| Output | Format | Purpose |
|---|---|---|
| Console Summary | ANSI-colored text | Immediate feedback after scan |
| Summary File | `.txt` | Share via email/Teams/tickets |
| JSON Export | `.json` | SIEM ingestion / automation |
| Windows Event Log | Event ID 1001 | SIEM tools monitoring event logs |
| CSV Export | `.csv` | Spreadsheet-friendly findings export |
| Webhook | HTTP POST | Push notifications to Slack/Teams/custom endpoints |
| Syslog | UDP RFC 5424 | Forward findings to centralized syslog collectors |
| Email | SMTP with PDF attachment | Automated email delivery of scan reports |

---

## Privilege Model

ADPulse is explicitly designed to run with **zero elevated privileges**:

```
┌─────────────────────────────────────────────────────────────────┐
│  REQUIRED: Standard Domain User (Domain Users group)             │
│                                                                  │
│  All LDAP attributes queried are readable by any authenticated   │
│  domain user by default. No special ACLs needed.                 │
│                                                                  │
│  NOT REQUIRED:                                                   │
│    ✗ Domain Admins         ✗ Enterprise Admins                  │
│    ✗ Schema Admins         ✗ Administrators                     │
│    ✗ Account Operators     ✗ Backup Operators                   │
│    ✗ Server Operators      ✗ Any delegated permissions          │
└─────────────────────────────────────────────────────────────────┘
```

**Why this works:** Active Directory exposes most object attributes (user accounts, groups, computers, policies) to any authenticated domain user via LDAP read access. This is by design — AD is a directory service. ADPulse leverages this to assess security posture without requiring dangerous privileged access.

---

## Security Considerations

### Credential Storage
- Service account password is stored in `config.ini`
- The config file **must** be protected with restrictive file permissions
- ADPulse warns at startup if the config file is world-readable
- On Linux: `chmod 600 config.ini`
- On Windows: Restrict ACL to service account + Administrators

### Network Security
- Only outbound LDAP connections (no listeners)
- **Strongly recommend LDAPS** (port 636) for encrypted communication
- NTLM authentication (no Kerberos ticket exposure)

### Data Sensitivity
- The SQLite database contains historical AD security data
- Generated reports contain account names, vulnerabilities, and topology
- All output files should be treated as **CONFIDENTIAL**
- Implement appropriate access controls on the output directory

### Attack Surface
- No remote command execution capability
- No credential storage on the network
- No modification of AD objects (read-only by design)
- Single outbound connection to a domain controller

---

## Configuration Reference

See `config.ini.example` for all available settings. Key sections:

| Section | Purpose |
|---|---|
| `[ldap]` | DC connection settings, credentials, SSL/TLS |
| `[scanning]` | Scan interval, stale thresholds, privileged groups to monitor |
| `[output]` | Minimum severity, Windows Event Log toggle |
| `[reporting]` | Output directory, PDF/HTML toggle, company branding |
| `[database]` | SQLite database path |
| `[logging]` | Log file path, level, rotation settings |

---

## Deployment Models

### Windows (Recommended)
1. Create service account: `install/create_service_account.ps1`
2. Configure: Copy `config.ini.example` to `config.ini`
3. Install scheduled task: `install/install_scheduled_task.ps1`
4. Runs every 6 hours (configurable)

### Linux
1. Install Python 3.10+ and dependencies: `pip install -r requirements.txt`
2. Configure `config.ini`
3. Schedule with cron or systemd timer
4. Or use `--daemon` mode for continuous operation

### CLI Quick Reference
```bash
python main.py                          # Run a single scan
python main.py --test-connection        # Test LDAP connectivity
python main.py --report-only            # Regenerate reports from last scan
python main.py --history                # Show recent scan history
python main.py --daemon                 # Run continuously on schedule
python main.py --config /path/to.ini    # Use custom config file
```

---

## Output Files

Each scan generates the following in the `output/` directory:

| File | Format | Purpose |
|---|---|---|
| `ADPulse_Report_YYYYMMDD_HHMMSS.html` | HTML | Web-viewable report with interactive styling |
| `ADPulse_Report_YYYYMMDD_HHMMSS.pdf` | PDF | Professional branded report for management |
| `ADPulse_Summary_YYYYMMDD_HHMMSS.txt` | Text | Plain-text summary for sharing via email/Teams |
| `ADPulse_Export_YYYYMMDD_HHMMSS.json` | JSON | Machine-readable export for SIEM/automation |
| `ADPulse_Trends_YYYYMMDD_HHMMSS.html` | HTML | Trend dashboard with historical finding charts |

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `ldap3` | >= 2.9.1 | LDAP v3 client for AD communication |
| `reportlab` | >= 4.0.0 | PDF report generation |
| `pywin32` | (optional) | Windows Event Log writing |

**Python:** 3.10+
**External:** Active Directory domain controller (LDAP port 389 or 636)
