# ADPulse Improvements — Design Spec
**Date:** 2026-04-02  
**Environment:** Air-gapped Windows VM, portable Python 3.12, read-only AD, no internet  
**Primary users:** Technical analysts (sysadmins, security analysts)  
**AD size:** Medium — 500–5,000 users, up to two domains  

---

## Overview

Four independent, shippable improvements to ADPulse, each solving a distinct daily frustration for technical analysts. They are ordered by priority and can be shipped one at a time without depending on each other.

| # | Improvement | Primary file(s) changed | New deps |
|---|---|---|---|
| 1 | Parallel scan | `main.py` | None — `concurrent.futures` (stdlib) |
| 2 | Interactive HTML reports | `report_generator.py` | None — vanilla JS embedded in template |
| 3 | Detection gaps (4 new checks) | `ldap_collector.py`, `detections.py`, `main.py` | None — ldap3 + `struct` (stdlib) |
| 4 | Finding lifecycle / policy tracking | new `modules/policy_manager.py`, `main.py`, `report_generator.py`, `notifier.py` | None — stdlib `json` |

---

## Improvement 1 — Parallel Scan

### Problem
The ~25 LDAP collector calls in `run_scan()` run sequentially. Each call waits for the previous to complete. For a 500–5,000 user domain, individual queries take 1–5 seconds each, making total scan time 60–90+ seconds.

### Design
Wrap the independent collector calls in a `ThreadPoolExecutor` from `concurrent.futures` (stdlib). All independent queries submit simultaneously; `run_scan()` waits for all to complete before proceeding to detections.

**Queries that stay sequential** (order-dependent):
- `get_all_users()` — result feeds several detections, must complete before detection phase
- `get_privileged_group_members()` — depends on the configured group list from config

**Queries that run in parallel** (all independent):
- `get_kerberoastable_accounts()`
- `get_asreproastable_accounts()`
- `get_accounts_password_never_expires()`
- `get_admincount_accounts()`
- `get_all_computers()`
- `get_domain_controllers()`
- `get_unconstrained_delegation_accounts()`
- `get_constrained_delegation_accounts()`
- `get_password_policy()`
- `get_gpo_links()`
- `get_fine_grained_password_policies()`
- `get_domain_info()`
- `get_password_not_required_accounts()`
- `get_reversible_encryption_accounts()`
- `get_accounts_with_sid_history()`
- `get_protected_users_members()`
- `get_users_with_description_passwords()`
- `get_computers_without_laps()`
- `get_krbtgt_account()`
- `get_trust_relationships()`
- `get_tombstone_lifetime()`
- `get_dns_zones()`
- `get_des_only_accounts()`
- `get_expiring_accounts()`
- `get_domain_acl()` (new — see Improvement 3)

### Configuration
Add to `[scanning]` in `config.ini`:
```ini
ldap_threads = 8   # max parallel LDAP queries (default: 8)
```

### Expected outcome
Scan time drops from ~60–90s to ~10–20s for a medium AD. No change to detection logic, data model, or output format.

### Failure handling
If any parallel query raises an exception, it is caught per-future, logged as a warning, and the result key is set to an empty list/None — matching current behaviour for failed individual calls. A single failed optional query does not abort the scan.

---

## Improvement 2 — Interactive HTML Reports

### Problem
The current HTML report is fully static. With 30+ findings, analysts must scroll manually. There is no way to filter to just CRITICAL findings or search for a specific account name.

### Design
Embed a self-contained vanilla JS block directly inside the generated HTML file. No CDN, no external files — the report works completely offline. The JS is stored as a multi-line string in `report_generator.py` and injected at render time, the same way the existing CSS is.

### Controls rendered at the top of the findings section

**Severity filter buttons** — one button per severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO). Buttons are toggleable and multi-select. Active state is visually highlighted. All active by default.

**Category filter dropdown** — populated from the actual categories present in the current report (e.g. Kerberos, Privileged Access, Password Policy). Renders `<option>` tags dynamically from data attributes on finding cards. Defaults to "All categories".

**Search box** — plain text input. Filters by finding title, description, and any affected account name as the analyst types. Debounced at 200ms to avoid re-rendering on every keystroke.

**"New findings only" toggle** — checkbox that hides findings marked `is_new = 0`. Useful for triage immediately after a scan — show only what changed.

**Result counter** — live text updated by the JS: `Showing 4 of 23 findings`. Resets when filters change.

### Implementation detail
Each finding card is rendered with HTML data attributes server-side:
```html
<div class="finding-card"
     data-severity="CRITICAL"
     data-category="Kerberos"
     data-new="1"
     data-searchtext="Kerberoastable accounts svc-sql svc-backup ...">
```

The JS reads these attributes to show/hide cards — no JSON blob, no fetch calls, no framework. Pure DOM attribute filtering. This means the filter logic works even if the JS runs before the DOM is fully painted (it operates on existing attributes, not fetched data).

### Files changed
- `report_generator.py` — add data attributes to finding card rendering, inject JS block into HTML template. No changes to any other module.

---

## Improvement 3 — Detection Gaps

### Problem
Four high-value AD attack paths are not currently detected. All are implementable with ldap3 and Python stdlib only — no new dependencies required.

### New detections

#### 3.1 DCSync Rights — `CRITICAL`
**Finding ID:** `ACL-001-DCSYNC`  
**What it detects:** Non-DC principals granted `DS-Replication-Get-Changes-All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) or `DS-Replication-Get-Changes` (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) on the domain NC root object. Any account with these rights can perform a DCSync attack and dump all password hashes without touching a DC directly.  
**How:** New `get_domain_acl()` method in `ldap_collector.py` queries the `nTSecurityDescriptor` attribute on the domain root DN. The raw binary security descriptor is parsed using Python's `struct` module to walk the DACL ACE list and extract ObjectType GUIDs and trustee SIDs. Non-DC SIDs with replication GUIDs are returned as findings.  
**Affected:** List of SAM account names (resolved from SIDs via additional LDAP lookup).

#### 3.2 Dormant Privileged Accounts — `HIGH`
**Finding ID:** `PRIV-001-DORMANT-ADMIN`  
**What it detects:** Enabled accounts in privileged groups whose `lastLogonTimestamp` is older than a configurable threshold. Distinct from the existing stale accounts check (which covers all users) — this specifically targets admin accounts where staleness represents a tier-1 risk (abandoned admin account = free domain admin for an attacker who finds credentials).  
**How:** Cross-reference already-collected `privileged_members` against `lastLogonTimestamp` from `get_all_users()`. No additional LDAP query required.  
**Configuration:** `dormant_admin_days = 90` added to `[scanning]` in `config.ini`.  
**Affected:** List of privileged account SAM names + days since last logon in details.

#### 3.3 Nested Group Privilege Expansion — `MEDIUM`
**Finding ID:** `PRIV-002-NESTED-PRIV`  
**What it detects:** Accounts that reach privileged groups through 2+ levels of group nesting. Example: `jsmith` → `HelpDesk` → `Tier1-Support` → `Administrators`. Currently the tool only checks direct membership.  
**How:** Use the `member` attribute on group objects from `get_all_groups()` — this method exists in `ldap_collector.py` but is not currently called during a scan. It must be added to the parallel query block in Improvement 1. Builds an in-memory adjacency map. Run a recursive expansion (depth-limited to 10 to avoid infinite loops on circular group memberships) for each monitored privileged group. Accounts that appear via indirect paths only are flagged.  
**Affected:** List of `account → chain → privileged group` strings so the analyst can see exactly how the access is granted.

#### 3.4 Service Accounts in Privileged Groups — `CRITICAL`
**Finding ID:** `KERB-003-PRIVESC-SPN`  
**What it detects:** Accounts with SPNs (Kerberoastable) that are also members of privileged groups. An attacker who Kerberoasts the account and cracks the hash gets immediate privileged access — no lateral movement required. This is one of the most dangerous combinations in AD.  
**How:** Intersect `kerberoastable` (already collected) with `privileged_members` (already collected). No additional LDAP query required.  
**Affected:** List of account names with their SPNs and the privileged groups they belong to.

### Files changed
- `ldap_collector.py` — add `get_domain_acl()` method; `get_all_groups()` already exists but must be added to the scan's parallel query block
- `detections.py` — add four new `detect_*` methods
- `main.py` — add `get_domain_acl()` call to parallel query block; add four new detection calls in Step 4
- `config.ini.example` — add `dormant_admin_days = 90` under `[scanning]`

---

## Improvement 4 — Finding Lifecycle / Policy Tracking

### Problem
Findings that are accepted risks or actively being remediated reappear identically in every scan report alongside genuinely new critical findings. Analysts lose trust in the report. There is no audit trail of decisions made about findings.

### Design
A `policy.json` file stored alongside `config.ini`. Analysts record decisions about specific findings using `--policy` CLI subcommands. The policy is applied after findings are assembled and before reports are generated.

### Policy states
| State | Meaning | Report behaviour |
|---|---|---|
| `accepted_risk` | Known, deliberate. Has a reason and optional expiry date. | Badge shown on finding. Excluded from console noise count. Auto-reactivates on expiry. |
| `in_remediation` | Fix in progress. | Badge shown. Still visible but visually distinct (muted style). |
| `resolved` | Analyst confirms fixed. | Removed from finding body. Appears in audit trail section only. |

### policy.json format
```json
{
  "KERB-001-STANDARD": {
    "status": "accepted_risk",
    "reason": "Legacy service, migration planned Q3",
    "set_by": "jsmith",
    "set_on": "2026-03-01",
    "expires": "2026-09-01"
  },
  "ACCT-003-DORMANT": {
    "status": "in_remediation",
    "reason": "Ticket #4421 open with helpdesk",
    "set_by": "jsmith",
    "set_on": "2026-04-01",
    "expires": null
  }
}
```

### CLI interface
```
python main.py --policy list
python main.py --policy accept  <finding_id> --reason "..." [--expires YYYY-MM-DD]
python main.py --policy remediate <finding_id> --reason "..."
python main.py --policy resolve   <finding_id>
python main.py --policy clear     <finding_id>
```

Commands validate the finding ID against the last scan's findings database — analysts cannot add a policy entry for a non-existent finding ID. `--policy list` shows all active entries with their expiry status.

### How policy surfaces in output

**HTML report:**
- Status badge on each affected finding card: `ACCEPTED RISK · expires Sep 2026` or `IN REMEDIATION`
- "New only" filter (Improvement 2) automatically excludes `accepted_risk` findings
- Audit trail section at the bottom of the report lists all policy entries, reasons, and who set them — nothing is silently hidden

**PDF report:**
- Small italic status line rendered under the finding title: `Status: Accepted risk — Legacy service, migration planned Q3 (expires 2026-09-01)`

**Console summary:**
- `accepted_risk` and `resolved` findings are collapsed: `3 findings suppressed by policy (see policy.json)`
- `in_remediation` findings are still listed but prefixed with `[REMEDIATING]`

**Expiry enforcement:**
- At scan time, `policy_manager.py` checks expiry dates. Expired entries are logged as warnings and removed from active policy. The finding reactivates in the report automatically.

**Resolved findings that reappear:**
- If a finding with `resolved` status is detected again in a future scan, the `resolved` policy entry is automatically cleared and the finding is treated as a new occurrence (`is_new = 1`). A warning is logged: `"Finding KERB-001-STANDARD was marked resolved but has reappeared — policy entry cleared."` The analyst must re-triage it. This prevents silently suppressing a recurrence.

### Files changed
- New `modules/policy_manager.py` — load/save/validate `policy.json`, expiry checks, CLI command handlers
- `main.py` — `--policy` subcommand wired to `policy_manager`; policy applied after `_apply_exclusions()` and before report generation
- `report_generator.py` — status badges in HTML, status line in PDF, audit trail section
- `notifier.py` — suppression count line in console summary

---

## What is not changing
- `ldap_collector.py` authentication logic — integrated Windows auth stays as-is
- `baseline_engine.py` — schema unchanged; no new tables needed
- `modules/notifier.py` email/webhook/syslog logic — untouched
- The offline packaging and build scripts — no new Python dependencies means the portable bundle works as-is
- The `--daemon`, `--diff`, `--history`, `--report-only` modes — all continue to work unchanged

---

## Dependency summary
Zero new Python packages. All four improvements use only:
- `concurrent.futures` (stdlib) — parallel scan
- Vanilla JS embedded as string (no package) — interactive HTML
- `struct` (stdlib) — DCSync ACL parsing
- `json` (stdlib) — policy file

The existing portable bundle (`python/Lib/site-packages/`) requires no changes.
