# ADPulse Detection Catalog

Complete reference of all security detections performed by ADPulse.
All detections use **read-only LDAP queries** and require only **standard Domain User** privileges.

---

## Detection Summary

| ID | Category | Severity | Detection |
|---|---|---|---|
| KERB-001-PRIVILEGED | Kerberos | CRITICAL | Kerberoastable Privileged Accounts |
| KERB-001-STANDARD | Kerberos | HIGH | Kerberoastable Service Accounts |
| KERB-002-ASREP | Kerberos | CRITICAL/HIGH | AS-REP Roastable Accounts |
| DELEG-001-UNCONSTRAINED | Delegation | CRITICAL | Unconstrained Kerberos Delegation |
| DELEG-002-CONSTRAINED | Delegation | MEDIUM | Constrained Delegation Configured |
| PWD-001-NEVER-EXPIRES | Password Hygiene | HIGH/MEDIUM | Password Never Expires |
| PWD-002-NOT-REQUIRED | Password Hygiene | CRITICAL/HIGH | Password Not Required Flag |
| PWD-003-REVERSIBLE-ENC | Password Hygiene | HIGH | Reversible Encryption Enabled |
| PWD-004-DESC-PASSWORD | Password Hygiene | HIGH | Passwords in Description Fields |
| ACCT-001-VERY-STALE | Account Hygiene | HIGH | Highly Stale Active Accounts |
| ACCT-001-STALE | Account Hygiene | MEDIUM | Stale Active Accounts |
| PRIV-001-ADMINCOUNT-ORPHAN | Privileged Access | MEDIUM | Orphaned adminCount=1 Accounts |
| PRIV-002-SID-HISTORY | Privileged Access | HIGH/MEDIUM | Accounts with SID History |
| PRIV-003-NO-PROTECTED-USERS | Privileged Access | MEDIUM | Privileged Accounts Not in Protected Users |
| POL-001-NO-POLICY | Password Policy | HIGH | Cannot Retrieve Password Policy |
| POL-002-SHORT-PASSWORD | Password Policy | HIGH/MEDIUM | Weak Minimum Password Length |
| POL-003-LOW-HISTORY | Password Policy | MEDIUM | Low Password History Length |
| POL-004-NO-LOCKOUT | Password Policy | CRITICAL | Account Lockout Disabled |
| POL-005-HIGH-LOCKOUT-THRESHOLD | Password Policy | LOW | High Account Lockout Threshold |
| CONF-001-MACHINE-QUOTA | Domain Configuration | MEDIUM | Machine Account Quota Allows User Joins |
| CONF-002-NO-LAPS | Infrastructure | HIGH/MEDIUM | Computers Without LAPS |
| COMP-001-STALE | Infrastructure | LOW | Stale Computer Accounts |
| OS-001-EOL-CRITICAL | Infrastructure | CRITICAL | End-of-Life OS (XP, Vista, 7, Server 2003) |
| OS-001-EOL-HIGH | Infrastructure | HIGH | End-of-Life OS (Server 2008, Windows 8) |
| OS-001-EOL-MEDIUM | Infrastructure | MEDIUM | End-of-Life OS (Server 2012) |
| DELTA-PRIV-ADD-* | Privileged Access Changes | CRITICAL | New Members Added to Privileged Group |
| DELTA-PRIV-REM-* | Privileged Access Changes | MEDIUM | Members Removed from Privileged Group |
| DELTA-ACCT-NEW | Account Changes | INFO | New User Accounts Created |

---

## Detection Details

### Kerberos Attack Path Detections

#### KERB-001 — Kerberoastable Accounts

**What it detects:** User accounts with Service Principal Names (SPNs) set.

**Why it matters:** Any authenticated domain user can request a Kerberos TGS ticket for accounts with SPNs. The ticket is encrypted with the account's password hash, enabling offline brute-force cracking. If the password is weak, the attacker obtains the account's credentials without triggering account lockouts.

**LDAP Query:**
```
(&(objectCategory=person)(objectClass=user)
  (servicePrincipalName=*)
  (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

**Severity Logic:**
- `CRITICAL` — Account has `adminCount=1` (privileged)
- `HIGH` — Standard service account with SPN

**Remediation:**
1. Remove unnecessary SPNs from privileged accounts
2. Migrate to Group Managed Service Accounts (gMSA) — auto-rotating 120+ char passwords
3. Ensure all remaining service account passwords are 25+ characters
4. Enable AES Kerberos encryption and disable RC4

---

#### KERB-002 — AS-REP Roastable Accounts

**What it detects:** Accounts with Kerberos pre-authentication disabled (UAC flag `0x400000`).

**Why it matters:** Without pre-authentication, an attacker can request an AS-REP message for any of these accounts **without any credentials at all**. The encrypted portion can be cracked offline to recover the password.

**LDAP Query:**
```
(&(objectCategory=person)(objectClass=user)
  (userAccountControl:1.2.840.113556.1.4.803:=4194304)
  (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

**Severity Logic:**
- `CRITICAL` — Any affected account has `adminCount=1`
- `HIGH` — All affected accounts are standard users

---

### Delegation Detections

#### DELEG-001 — Unconstrained Kerberos Delegation

**What it detects:** Non-DC accounts with the `TRUSTED_FOR_DELEGATION` flag (UAC `0x80000`).

**Why it matters:** When a user authenticates to a system with unconstrained delegation, their TGT is cached in that system's memory. An attacker who compromises such a system can extract cached TGTs and impersonate **any user** (including Domain Admins) to **any service** in the domain. This is one of the most dangerous AD misconfigurations.

**Attack techniques:** PrinterBug/SpoolSample, PetitPotam coercion to force high-value targets to authenticate.

**Severity:** Always `CRITICAL`

---

#### DELEG-002 — Constrained Delegation

**What it detects:** Accounts with `msDS-AllowedToDelegateTo` attribute set.

**Why it matters:** Constrained delegation limits which services an account can delegate to, but a compromised account can still be used to access those specific services as any user. With protocol transition (S4U2Self + S4U2Proxy), the account doesn't even need the target user to authenticate first.

**Severity:** `MEDIUM` — Lower risk than unconstrained but should be audited.

---

### Password Hygiene Detections

#### PWD-001 — Password Never Expires

**What it detects:** Enabled accounts with `DONT_EXPIRE_PASSWORD` flag (UAC `0x10000`).

**Why it matters:** These accounts bypass password rotation policies. Passwords may be years old, increasing the window for credential theft, reuse, and offline cracking.

**Severity Logic:**
- `HIGH` — Any affected account has `adminCount=1`
- `MEDIUM` — All standard accounts

---

#### PWD-002 — Password Not Required

**What it detects:** Accounts with `PASSWD_NOTREQD` flag (UAC `0x20`).

**Why it matters:** This flag allows the account to have an **empty password**. If the password is actually blank, the account can be accessed with just the username. This flag is often set during bulk imports or legacy migrations and forgotten.

**Severity Logic:**
- `CRITICAL` — Any affected account is privileged
- `HIGH` — Standard accounts

---

#### PWD-003 — Reversible Encryption

**What it detects:** Accounts with `ENCRYPTED_TEXT_PWD_ALLOWED` flag (UAC `0x80`).

**Why it matters:** Passwords are stored using reversible encryption, which is effectively plaintext. Anyone with access to the AD database (ntds.dit) can recover these passwords without cracking. This setting is only required for CHAP/Digest authentication, which is extremely rare.

**Severity:** `HIGH`

---

#### PWD-004 — Passwords in Description Fields

**What it detects:** User accounts whose `description` attribute contains password-related keywords (pass, pwd, wachtwoord, mot de passe, contraseña).

**Why it matters:** The `description` attribute is readable by **every authenticated domain user**. Storing passwords here is equivalent to posting them on a bulletin board. This is a surprisingly common practice, especially for shared/service accounts.

**Severity:** `HIGH`

---

### Account Hygiene Detections

#### ACCT-001 — Stale Accounts

**What it detects:** Enabled user accounts that haven't logged in for longer than the configured threshold (default: 60 days).

**Why it matters:** Stale accounts expand the attack surface. They are often forgotten by their owners, making them prime targets for attackers — compromised credentials go unnoticed because nobody is actively using the account.

**Severity Logic:**
- `HIGH` — Inactive for 2x the threshold (very stale)
- `MEDIUM` — Inactive for 1x the threshold

---

### Privileged Access Detections

#### PRIV-001 — Orphaned adminCount Accounts

**What it detects:** Accounts with `adminCount=1` that are NOT members of any currently monitored privileged group.

**Why it matters:** When an account is added to a privileged group, `AdminSDHolder` sets `adminCount=1` and applies a locked-down ACL. When removed from the group, `adminCount` is not automatically reset. These "orphaned" accounts retain the restrictive ACL (which prevents inheritance) but are no longer managed by AdminSDHolder, so their permissions may have drifted.

**Severity:** `MEDIUM`

---

#### PRIV-002 — SID History

**What it detects:** Accounts with the `sIDHistory` attribute populated.

**Why it matters:** SID History is used during domain migrations to preserve access to resources in the source domain. After migration, leftover entries can be weaponized — an attacker with write access to an account can inject the SID of Domain Admins into SID History, gaining full domain admin rights.

**Severity Logic:**
- `HIGH` — Any affected account is privileged
- `MEDIUM` — Standard accounts

---

#### PRIV-003 — Protected Users Coverage

**What it detects:** Privileged accounts that are NOT members of the `Protected Users` security group.

**Why it matters:** The Protected Users group enforces hardened security:
- No NTLM authentication (prevents relay attacks)
- No DES or RC4 Kerberos encryption
- No delegation (prevents impersonation)
- No credential caching (prevents offline attacks)
- 4-hour TGT lifetime (limits ticket theft window)

Privileged accounts not in this group are missing these critical protections.

**Severity:** `MEDIUM`

**Note:** Service accounts should NOT be added to Protected Users (delegation and NTLM break).

---

### Domain Configuration Detections

#### CONF-001 — Machine Account Quota

**What it detects:** `ms-DS-MachineAccountQuota` value greater than 0.

**Why it matters:** By default, this is set to 10, meaning any domain user can join up to 10 computers to the domain without admin approval. Attacker-controlled machines can be used for:
- NTLM relay attacks
- Resource-Based Constrained Delegation (RBCD) abuse
- Lateral movement staging

**Severity:** `MEDIUM`

---

#### CONF-002 — Computers Without LAPS

**What it detects:** Computer accounts without the `ms-Mcs-AdmPwdExpirationTime` attribute (indicating LAPS is not deployed).

**Why it matters:** Without LAPS, local administrator passwords are often identical across all workstations (set during imaging). Compromising one machine's local admin password gives the attacker local admin access to every machine with the same password — trivial lateral movement via pass-the-hash.

**Severity Logic:**
- `HIGH` — LAPS coverage below 50%
- `MEDIUM` — LAPS coverage above 50% but not complete

---

### Password Policy Detections

#### POL-002 — Weak Minimum Password Length

**What it detects:** Domain password policy with minimum length below 12 characters.

**Severity Logic:**
- `HIGH` — Minimum length below 8
- `MEDIUM` — Minimum length 8-11

**Reference:** NIST SP 800-63B recommends minimum 12 characters.

---

#### POL-004 — Account Lockout Disabled

**What it detects:** Account lockout threshold set to 0 (disabled).

**Why it matters:** Without lockout, attackers can perform unlimited password spray and brute-force attacks against every account in the domain without triggering any defensive mechanism.

**Severity:** `CRITICAL`

---

### Infrastructure Detections

#### COMP-001 — Stale Computer Accounts

**What it detects:** Computer accounts that haven't authenticated in over 2x the stale threshold.

**Severity:** `LOW`

---

#### OS-001 — End-of-Life Operating Systems

**What it detects:** Computers running unsupported operating systems.

| OS | Severity |
|---|---|
| Windows XP, Vista, 7, Server 2003 | CRITICAL |
| Windows 8, Server 2008 | HIGH |
| Windows Server 2012 | MEDIUM |

---

### Delta-Based Detections

These detections require at least two scans (a baseline to compare against).

#### DELTA-PRIV-ADD — Privileged Group Additions

**What it detects:** New members added to monitored privileged groups since the last scan.

**Why it matters:** Unauthorized additions to groups like Domain Admins are a primary indicator of compromise or privilege escalation. This is one of the most important detections in ADPulse.

**Severity:** `CRITICAL`

**Monitored groups** (configurable): Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Group Policy Creator Owners

---

#### DELTA-PRIV-REM — Privileged Group Removals

**What it detects:** Members removed from monitored privileged groups since the last scan.

**Why it matters:** While removals are generally positive (least privilege), unexpected removals could indicate an attacker covering their tracks after using a temporary privilege escalation.

**Severity:** `MEDIUM`

---

#### DELTA-ACCT-NEW — New User Accounts

**What it detects:** User accounts that exist in the current scan but not in the previous scan.

**Severity:** `INFO` (informational — review for legitimacy)

---

## Risk Scoring

ADPulse calculates a risk score from 0-100 based on finding severity:

| Severity | Weight |
|---|---|
| CRITICAL | x40 |
| HIGH | x15 |
| MEDIUM | x5 |
| LOW | x1 |
| INFO | x0 |

**Score = min(CRITICAL*40 + HIGH*15 + MEDIUM*5 + LOW*1, 100)**

| Score Range | Risk Level |
|---|---|
| 70-100 | CRITICAL |
| 40-69 | HIGH |
| 20-39 | MEDIUM |
| 0-19 | LOW |

---

## Extending Detections

To add a new detection:

1. **Add LDAP query** in `ldap_collector.py` (if new data is needed)
2. **Add detection method** in `detections.py` following the Finding dict schema:
   ```python
   {
       "finding_id": "CATEGORY-NNN-SHORT-NAME",  # Stable ID for tracking
       "category": "Category Name",
       "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
       "title": "Short human-readable title",
       "description": "Explanation of the risk",
       "affected": ["list", "of", "affected", "objects"],
       "details": {"count": 0, "extra": "data"},
       "remediation": "Steps to fix",
   }
   ```
3. **Wire it into `run_all_detections()`** in `detections.py`
4. **Add data collection** in `main.py`'s `ad_data` dictionary
5. **Document it** in this file
