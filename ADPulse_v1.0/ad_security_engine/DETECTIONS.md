# ADPulse Detection Catalog

Complete reference of all 30+ security detections performed by ADPulse.
All detections use **read-only LDAP queries** and require only **standard Domain User** privileges.

---

## Detection Summary

| ID | Category | Severity | Detection |
|---|---|---|---|
| ACL-001-DCSYNC | Privileged Access | CRITICAL | Non-DC Accounts with DCSync Rights |
| KERB-001-PRIVILEGED | Kerberos | CRITICAL | Kerberoastable Privileged Accounts |
| KERB-001-STANDARD | Kerberos | HIGH | Kerberoastable Service Accounts |
| KERB-003-PRIVESC-SPN | Kerberos | CRITICAL | Privileged Kerberoastable Accounts (SPN + Admin Group) |
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
| PRIV-001-DORMANT-ADMIN | Privileged Access | HIGH | Dormant Privileged Accounts (90+ days inactive) |
| PRIV-002-NESTED-PRIV | Privileged Access | MEDIUM | Accounts with Indirect Privileged Access via Group Nesting |
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
| KERB-003-KRBTGT-AGE | Kerberos | CRITICAL/HIGH | KRBTGT Password Not Rotated (>180 days) |
| KERB-004-DUPLICATE-SPN | Kerberos | MEDIUM | Duplicate Service Principal Names |
| KERB-005-DES-ONLY | Kerberos | HIGH | Accounts Using DES-Only Encryption |
| TRUST-001-NO-SID-FILTER | Domain Configuration | HIGH | Trust Relationships Without SID Filtering |
| TRUST-002-INVENTORY | Domain Configuration | INFO | Trust Relationship Inventory |
| CONF-003-TOMBSTONE | Domain Configuration | HIGH/MEDIUM | Short Tombstone Lifetime |
| ACCT-002-EXPIRING | Account Hygiene | INFO | Accounts Expiring Soon |
| POL-006-FGPP-NO-TARGETS | Password Policy | MEDIUM | FGPPs With No Targets |
| POL-007-FGPP-PRIV-GAP | Password Policy | MEDIUM | Privileged Groups Not Covered by FGPP |

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

#### KERB-003 — KRBTGT Password Age

**What it detects:** The KRBTGT account password has not been rotated in over 180 days.

**Why it matters:** The KRBTGT account is used to sign all Kerberos TGTs in the domain. If an attacker obtains the KRBTGT hash, they can forge Golden Tickets granting unrestricted domain access. Regular rotation limits the window of exposure. Microsoft recommends rotating the KRBTGT password at least every 180 days.

**Severity Logic:**
- `CRITICAL` — Password age exceeds 365 days
- `HIGH` — Password age exceeds 180 days

**Remediation:**
1. Rotate the KRBTGT password twice (with a 12+ hour gap between rotations to allow replication)
2. Establish a recurring rotation schedule (at least every 180 days)

---

#### KERB-004 — Duplicate Service Principal Names

**What it detects:** Multiple accounts that share the same Service Principal Name (SPN).

**Why it matters:** Duplicate SPNs cause Kerberos authentication failures for the affected services. They can also indicate misconfiguration or unauthorized SPN registration by an attacker preparing for Kerberoasting or lateral movement.

**Severity:** `MEDIUM`

**Remediation:**
1. Identify and remove duplicate SPN assignments using `setspn -X` across the forest
2. Consolidate SPNs to the correct service accounts

---

#### KERB-005 — DES-Only Encryption Accounts

**What it detects:** Accounts configured to use DES-only Kerberos encryption (UAC flag `0x200000`).

**Why it matters:** DES encryption is cryptographically broken and can be cracked trivially. Accounts restricted to DES-only encryption expose their Kerberos tickets to rapid offline attacks. Modern environments should enforce AES256.

**Severity:** `HIGH`

**Remediation:**
1. Remove the `USE_DES_KEY_ONLY` flag from affected accounts
2. Ensure AES Kerberos encryption is enabled on all accounts
3. Update any legacy applications that require DES

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

#### ACCT-002 — Accounts Expiring Soon

**What it detects:** User accounts with an `accountExpires` date within the near future (configurable, default 30 days).

**Why it matters:** Provides operational awareness of accounts that will soon expire. Useful for proactive account lifecycle management and avoiding unexpected service disruptions from expired service or contractor accounts.

**Severity:** `INFO` (informational — review for planned expirations)

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

#### CONF-003 — Short Tombstone Lifetime

**What it detects:** The AD tombstone lifetime is set below the recommended 180 days.

**Why it matters:** The tombstone lifetime determines how long deleted objects are retained before permanent removal. A short tombstone lifetime can cause lingering objects and replication failures if a domain controller is offline longer than the tombstone period. It also reduces the window for recovering accidentally deleted objects.

**Severity Logic:**
- `HIGH` — Tombstone lifetime below 60 days
- `MEDIUM` — Tombstone lifetime between 60-179 days

**Remediation:**
1. Increase the tombstone lifetime to at least 180 days via `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration`

---

#### TRUST-001 — Trust Relationships Without SID Filtering

**What it detects:** Inter-domain or inter-forest trust relationships that do not have SID filtering (quarantine) enabled.

**Why it matters:** Without SID filtering, a compromised trusted domain can inject arbitrary SIDs (including Domain Admins SIDs from the trusting domain) into Kerberos tickets via SID History. This allows full privilege escalation across the trust boundary. SID filtering should be enabled on all external and forest trusts.

**Severity:** `HIGH`

**Remediation:**
1. Enable SID filtering on external trusts: `netdom trust /domain: /quarantine:yes`
2. Verify SID filtering status on all trust relationships
3. Only disable SID filtering when explicitly required for migration scenarios

---

#### TRUST-002 — Trust Relationship Inventory

**What it detects:** Enumerates all trust relationships configured in the domain.

**Why it matters:** Provides a complete inventory of trust relationships for security review. Trust relationships expand the authentication boundary and should be regularly audited to ensure only necessary trusts exist with appropriate security settings.

**Severity:** `INFO` (informational — review for completeness and necessity)

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

#### POL-006 — FGPPs With No Targets

**What it detects:** Fine-Grained Password Policies (FGPPs) that have no users or groups assigned to them via `msDS-PSOAppliesTo`.

**Why it matters:** An FGPP without targets is effectively unused and provides no security benefit. This may indicate an incomplete deployment or a policy that lost its targets due to group deletion. Unused FGPPs add complexity and may give a false sense of security if administrators assume they are being enforced.

**Severity:** `MEDIUM`

**Remediation:**
1. Assign appropriate user or group targets to the FGPP
2. Remove the FGPP if it is no longer needed

---

#### POL-007 — Privileged Groups Not Covered by FGPP

**What it detects:** Privileged groups (Domain Admins, Enterprise Admins, etc.) that are not targeted by any Fine-Grained Password Policy enforcing stronger password requirements than the default domain policy.

**Why it matters:** Privileged accounts are high-value targets and should be held to stricter password requirements (longer minimum length, shorter maximum age). Without an FGPP targeting these groups, privileged accounts fall back to the default domain password policy, which is typically designed for standard users.

**Severity:** `MEDIUM`

**Remediation:**
1. Create an FGPP with stricter settings (e.g., 20+ character minimum, 90-day max age)
2. Apply the FGPP to all privileged groups

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

---

### Privileged Access — New Detections

#### ACL-001-DCSYNC — Non-DC Accounts with DCSync Rights

**What it detects:** Non-domain-controller accounts that hold the `DS-Replication-Get-Changes-All` extended right on the domain root object.

**Why it matters:** This right, combined with `DS-Replication-Get-Changes`, allows the holder to replicate all password hashes from a Domain Controller — including krbtgt and all user accounts — using the DCSync technique (e.g., Mimikatz `lsadump::dcsync`). No physical access to a DC is required. Any account holding this right is effectively a silent, unchecked Domain Admin.

**How it works:** ADPulse reads the binary security descriptor (`nTSecurityDescriptor`) of the domain root object via LDAP. It parses the DACL to find `ALLOWED_OBJECT_ACE` entries matching the DCSync GUIDs, then resolves each granting SID to a `sAMAccountName`. Domain controllers are excluded from findings as expected holders.

**Severity:** Always `CRITICAL`

**Remediation:**
1. Identify how the permission was granted (deliberate delegation, GPO, legacy tool, or attacker activity).
2. In ADUC: right-click domain root → Properties → Security → find the account → remove `Replicating Directory Changes All`.
3. Investigate whether a DCSync attack has already occurred (check DC logs for suspicious replication requests, look for mimikatz indicators).

---

#### PRIV-001-DORMANT-ADMIN — Dormant Privileged Accounts

**What it detects:** Enabled accounts in privileged groups (Domain Admins, Enterprise Admins, etc.) that have not authenticated in more than `dormant_admin_days` days (default: 90), **or have never logged on at all**.

**Why it matters:** Unused admin accounts are high-value targets. If credentials are compromised (password reuse, phishing, breach), the attacker can use the account without triggering any unusual activity alerts — the account was already silent. Never-logged-on admin accounts are especially dangerous: they may have been created during setup and forgotten, with a default or known password.

**Severity:** `HIGH`

**Configuration:** Set `dormant_admin_days` in `config.ini` under `[scanning]`.

**Remediation:**
1. Confirm with the account owner whether the account is still needed.
2. Disable unused accounts (`Disable-ADAccount`).
3. If legitimately unused, remove privileged group memberships and re-add only when needed (just-in-time access).

---

#### PRIV-002-NESTED-PRIV — Indirect Privileged Access via Group Nesting

**What it detects:** User accounts that are **not direct members** of privileged groups but reach them through one or more intermediate group memberships (e.g., `jsmith → HelpDesk → Domain Admins`).

**Why it matters:** Standard AD access reviews check direct group membership. Nested memberships are invisible to tools that do not recurse group trees. An attacker who discovers a nested path can obtain effective privileged access that defenders have not reviewed and may not know exists.

**How it works:** ADPulse performs a recursive depth-limited traversal (max 10 levels) of all group memberships to find user accounts with indirect paths to privileged groups. Both directions are checked: sub-groups of privileged groups and outer groups that contain privileged groups as members.

**Severity:** `MEDIUM`

**Remediation:**
1. Review each nested membership chain listed in the finding's affected list.
2. Determine whether the indirect access is intentional.
3. Either remove the intermediate group from the privileged group, or remove the user from the intermediate group.
4. Flatten group nesting for privileged groups to make future access reviews straightforward.

---

#### KERB-003-PRIVESC-SPN — Privileged Kerberoastable Accounts

**What it detects:** Accounts with Service Principal Names (SPNs) that are **also members of privileged groups**.

**Why it matters:** Any domain user can request a Kerberos service ticket for any account with an SPN and attempt offline password cracking. When a service account is also a Domain Admin or equivalent, a cracked hash yields immediate full domain compromise with no further exploitation required.

**Severity:** Always `CRITICAL`

**Remediation:**
1. Remove service accounts from privileged groups — service accounts should never be administrators.
2. If admin rights are genuinely required, use a Group Managed Service Account (gMSA) — these have auto-rotating 120+ character passwords and cannot be Kerberoasted.
3. As an interim measure, set a long random password (25+ characters) on the account.
4. Enable `Require Kerberos AES encryption` on the account to prevent RC4-based Kerberoasting while you remediate.
