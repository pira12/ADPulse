"""
detections.py
-------------
All security finding detectors. Each detector takes AD data and returns
a list of standardised Finding dicts.

Severity levels: CRITICAL | HIGH | MEDIUM | LOW | INFO

Finding dict schema:
{
    "finding_id": str,       # Stable unique ID (used to track across scans)
    "category":   str,       # e.g. "Kerberos", "Privileged Access", "Password Policy"
    "severity":   str,       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "title":      str,       # Short human-readable title
    "description": str,      # Explanation of the risk
    "affected":   list[str], # Affected account/object names
    "details":    dict,      # Extra structured data
    "remediation": str,      # What to do about it
}
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Severity ordering for sorting
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Windows UAC flags
UAC_DISABLED          = 0x00000002
UAC_HOMEDIR_REQUIRED  = 0x00000008
UAC_LOCKOUT           = 0x00000010
UAC_PASSWD_NOTREQD    = 0x00000020
UAC_PASSWD_CANT_CHANGE= 0x00000040
UAC_NORMAL_ACCOUNT    = 0x00000200
UAC_DONT_EXPIRE_PASSWD= 0x00010000
UAC_SMARTCARD_REQUIRED= 0x00040000
UAC_TRUSTED_FOR_DELEG = 0x00080000
UAC_NOT_DELEGATED     = 0x00100000
UAC_DONT_REQ_PREAUTH  = 0x00400000
UAC_PASSWORD_EXPIRED  = 0x00800000
UAC_TRUSTED_TO_AUTH   = 0x01000000  # Constrained delegation (protocol transition)


def _uac_flag(uac, flag: int) -> bool:
    try:
        return bool(int(uac or 0) & flag)
    except (TypeError, ValueError):
        return False


def _to_datetime(val) -> Optional[datetime]:
    """Try to parse various datetime representations."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val
    if isinstance(val, str):
        val = val.strip()
        if not val or val in ("None", "0"):
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S+00:00"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return None


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    now = datetime.now(tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days


def _account_name(account: dict) -> str:
    return str(
        account.get("sAMAccountName")
        or account.get("sam_account_name")
        or account.get("dn")
        or "Unknown"
    )


class DetectionEngine:
    """
    Runs all security detectors against collected AD data.
    Returns a deduplicated, sorted list of Finding dicts.
    """

    def __init__(self, config: dict):
        self.stale_days = int(config.get("stale_account_days", 60))
        self.password_age_days = int(config.get("password_age_days", 365))
        privileged_str = config.get(
            "privileged_groups",
            "Domain Admins,Enterprise Admins,Schema Admins,Administrators"
        )
        self.privileged_groups = [g.strip() for g in privileged_str.split(",")]

    # ------------------------------------------------------------------ #
    #  Public Entry Point                                                  #
    # ------------------------------------------------------------------ #

    def run_all_detections(self, ad_data: dict, baseline=None, previous_run_id: str = None) -> list:
        """
        Run all detectors and return a sorted list of findings.

        ad_data keys expected:
          users, kerberoastable, asreproastable, pwd_never_expires,
          admincount_users, privileged_members, computers, domain_controllers,
          unconstrained_delegation, constrained_delegation, password_policy,
          gpo_links, fine_grained_policies
        """
        findings = []

        findings += self.detect_kerberoastable_accounts(ad_data.get("kerberoastable", []))
        findings += self.detect_asreproastable_accounts(ad_data.get("asreproastable", []))
        findings += self.detect_unconstrained_delegation(ad_data.get("unconstrained_delegation", []))
        findings += self.detect_constrained_delegation(ad_data.get("constrained_delegation", []))
        findings += self.detect_password_never_expires(ad_data.get("pwd_never_expires", []))
        findings += self.detect_stale_accounts(ad_data.get("users", []))
        findings += self.detect_admincount_orphans(ad_data.get("admincount_users", []), ad_data.get("privileged_members", {}))
        findings += self.detect_password_policy_weaknesses(ad_data.get("password_policy"))
        findings += self.detect_stale_computers(ad_data.get("computers", []))
        findings += self.detect_old_operating_systems(ad_data.get("computers", []))

        # Delta-based detections (require a baseline)
        if baseline and previous_run_id:
            findings += self.detect_privileged_group_changes(
                ad_data.get("privileged_members", {}), baseline, previous_run_id
            )
            findings += self.detect_new_accounts(
                ad_data.get("users", []), baseline, previous_run_id
            )

        # Deduplicate by finding_id (keep first occurrence)
        seen = set()
        unique_findings = []
        for f in findings:
            if f["finding_id"] not in seen:
                seen.add(f["finding_id"])
                unique_findings.append(f)

        # Sort by severity
        unique_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

        logger.info(f"Detection complete. Total findings: {len(unique_findings)}")
        return unique_findings

    # ------------------------------------------------------------------ #
    #  Kerberos Attack Path Detections                                     #
    # ------------------------------------------------------------------ #

    def detect_kerberoastable_accounts(self, accounts: list) -> list:
        """
        Kerberoastable accounts: user accounts with SPNs set.
        Any domain user can request TGS tickets for these accounts,
        enabling offline password cracking.
        """
        findings = []
        high_value = []   # Accounts with adminCount=1 or privileged group membership
        standard = []

        for acct in accounts:
            name = _account_name(acct)
            admin_count = acct.get("adminCount") or 0
            if int(admin_count) > 0:
                high_value.append(name)
            else:
                standard.append(name)

        if high_value:
            findings.append({
                "finding_id": "KERB-001-PRIVILEGED",
                "category": "Kerberos",
                "severity": "CRITICAL",
                "title": "Kerberoastable Privileged Accounts",
                "description": (
                    f"{len(high_value)} privileged account(s) have Service Principal Names (SPNs) set. "
                    "These accounts are vulnerable to Kerberoasting — any domain user can request a "
                    "Kerberos TGS ticket and attempt offline password cracking. Privileged accounts "
                    "with weak passwords represent an immediate domain compromise risk."
                ),
                "affected": high_value,
                "details": {"count": len(high_value)},
                "remediation": (
                    "1. Remove unnecessary SPNs from privileged accounts.\n"
                    "2. Use Group Managed Service Accounts (gMSA) for services — they have auto-rotating "
                    "120+ character passwords that are computationally infeasible to crack.\n"
                    "3. Ensure all service accounts have passwords of 25+ characters.\n"
                    "4. Enable AES encryption for Kerberos on these accounts."
                ),
            })

        if standard:
            findings.append({
                "finding_id": "KERB-001-STANDARD",
                "category": "Kerberos",
                "severity": "HIGH",
                "title": "Kerberoastable Service Accounts",
                "description": (
                    f"{len(standard)} service account(s) with SPNs are vulnerable to Kerberoasting. "
                    "While not currently privileged, cracked passwords could enable lateral movement "
                    "or escalation if these accounts have excessive permissions."
                ),
                "affected": standard,
                "details": {"count": len(standard)},
                "remediation": (
                    "1. Migrate services to Group Managed Service Accounts (gMSA).\n"
                    "2. Ensure service account passwords are 25+ characters.\n"
                    "3. Enable AES Kerberos encryption and disable RC4.\n"
                    "4. Audit permissions held by each service account."
                ),
            })

        return findings

    def detect_asreproastable_accounts(self, accounts: list) -> list:
        """
        AS-REP Roastable: accounts with Kerberos pre-authentication disabled.
        Attackers can request encrypted AS-REP data without any credentials
        and attempt offline cracking.
        """
        if not accounts:
            return []

        names = [_account_name(a) for a in accounts]
        privileged = [n for a, n in zip(accounts, names) if int(a.get("adminCount") or 0) > 0]

        severity = "CRITICAL" if privileged else "HIGH"

        return [{
            "finding_id": "KERB-002-ASREP",
            "category": "Kerberos",
            "severity": severity,
            "title": "AS-REP Roastable Accounts (Pre-Auth Disabled)",
            "description": (
                f"{len(accounts)} account(s) have Kerberos pre-authentication disabled. "
                "Attackers can request AS-REP messages for these accounts without any credentials, "
                "then crack the encrypted portion offline."
                + (f" {len(privileged)} of these are privileged accounts — this is CRITICAL." if privileged else "")
            ),
            "affected": names,
            "details": {"count": len(accounts), "privileged_count": len(privileged)},
            "remediation": (
                "1. Enable Kerberos pre-authentication on all accounts (remove the DONT_REQUIRE_PREAUTH flag).\n"
                "2. If pre-auth must be disabled for legacy reasons, ensure the account password is "
                "extremely strong (25+ characters).\n"
                "3. Monitor for AS-REP requests to these accounts in security event logs (Event ID 4768)."
            ),
        }]

    def detect_unconstrained_delegation(self, accounts: list) -> list:
        """
        Unconstrained delegation: accounts that receive and cache TGTs from
        any user who authenticates to them. If compromised, attackers can
        impersonate any user in the domain including Domain Admins.
        """
        if not accounts:
            return []

        names = [_account_name(a) for a in accounts]

        return [{
            "finding_id": "DELEG-001-UNCONSTRAINED",
            "category": "Delegation",
            "severity": "CRITICAL",
            "title": "Unconstrained Kerberos Delegation",
            "description": (
                f"{len(accounts)} non-DC account(s) are configured with unconstrained Kerberos delegation. "
                "When any user authenticates to these systems, their TGT is cached in memory. "
                "An attacker who compromises one of these machines can steal those TGTs and "
                "impersonate any user — including Domain Admins — to any service in the domain."
            ),
            "affected": names,
            "details": {"count": len(accounts)},
            "remediation": (
                "1. Replace unconstrained delegation with constrained delegation or resource-based "
                "constrained delegation (RBCD).\n"
                "2. If unconstrained delegation is required, mark the account as 'Account is sensitive "
                "and cannot be delegated' for privileged users.\n"
                "3. Enable 'Protected Users' security group for privileged accounts.\n"
                "4. Monitor for printer bug / SpoolSample exploitation attempts targeting these hosts."
            ),
        }]

    def detect_constrained_delegation(self, accounts: list) -> list:
        """Constrained delegation - lower risk but should be audited."""
        if not accounts:
            return []

        names = [_account_name(a) for a in accounts]

        return [{
            "finding_id": "DELEG-002-CONSTRAINED",
            "category": "Delegation",
            "severity": "MEDIUM",
            "title": "Constrained Delegation Configured",
            "description": (
                f"{len(accounts)} account(s) are configured with constrained Kerberos delegation. "
                "While safer than unconstrained delegation, these accounts can still be abused "
                "if compromised to access specific services on behalf of other users."
            ),
            "affected": names,
            "details": {"count": len(accounts)},
            "remediation": (
                "1. Audit each account's delegation target list to ensure it's minimal and necessary.\n"
                "2. Consider migrating to Resource-Based Constrained Delegation (RBCD).\n"
                "3. Ensure delegating accounts have strong passwords and are monitored."
            ),
        }]

    # ------------------------------------------------------------------ #
    #  Password & Account Hygiene Detections                              #
    # ------------------------------------------------------------------ #

    def detect_password_never_expires(self, accounts: list) -> list:
        """Accounts with Password Never Expires — chronic password hygiene risk."""
        if not accounts:
            return []

        names = [_account_name(a) for a in accounts]
        privileged = [
            _account_name(a) for a in accounts
            if int(a.get("adminCount") or 0) > 0
        ]

        severity = "HIGH" if privileged else "MEDIUM"

        return [{
            "finding_id": "PWD-001-NEVER-EXPIRES",
            "category": "Password Hygiene",
            "severity": severity,
            "title": "Accounts with Password Never Expires",
            "description": (
                f"{len(accounts)} enabled account(s) are configured with 'Password Never Expires'. "
                "These accounts may have passwords that have not changed for years, "
                "significantly increasing the risk of credential compromise."
                + (f" {len(privileged)} privileged account(s) are included — this requires immediate attention." if privileged else "")
            ),
            "affected": names,
            "details": {"count": len(accounts), "privileged_count": len(privileged)},
            "remediation": (
                "1. Remove the 'Password Never Expires' flag from non-service accounts.\n"
                "2. For service accounts, migrate to gMSA (Group Managed Service Accounts).\n"
                "3. Implement a password rotation policy for remaining accounts.\n"
                "4. Audit when these passwords were last set and force resets for old passwords."
            ),
        }]

    def detect_stale_accounts(self, users: list) -> list:
        """
        User accounts that haven't logged in for the configured threshold.
        Stale accounts are prime targets for attackers — they often go unnoticed.
        """
        stale = []
        very_stale = []  # > 2x threshold

        for user in users:
            uac = int(user.get("userAccountControl") or 0)
            # Skip disabled accounts
            if uac & UAC_DISABLED:
                continue

            last_logon = _to_datetime(user.get("lastLogonTimestamp"))
            days = _days_since(last_logon)

            # If no logon ever and account is old, still flag it
            if last_logon is None:
                created = _to_datetime(user.get("whenCreated"))
                if created and _days_since(created) > self.stale_days:
                    name = _account_name(user)
                    stale.append(f"{name} (never logged in)")
            elif days is not None and days >= self.stale_days:
                name = _account_name(user)
                if days >= self.stale_days * 2:
                    very_stale.append(f"{name} ({days}d ago)")
                else:
                    stale.append(f"{name} ({days}d ago)")

        findings = []

        if very_stale:
            findings.append({
                "finding_id": f"ACCT-001-VERY-STALE",
                "category": "Account Hygiene",
                "severity": "HIGH",
                "title": f"Highly Stale Active Accounts (>{self.stale_days * 2} days inactive)",
                "description": (
                    f"{len(very_stale)} enabled account(s) show no logon activity for over "
                    f"{self.stale_days * 2} days. These are prime targets for attackers as they "
                    "are rarely monitored and their credentials may be forgotten by their owners."
                ),
                "affected": very_stale[:50],  # Cap to 50 in report
                "details": {"count": len(very_stale), "threshold_days": self.stale_days * 2},
                "remediation": (
                    "1. Disable accounts that have been inactive beyond your retention policy.\n"
                    "2. Confirm with managers whether these users are still employees.\n"
                    "3. Delete accounts confirmed as no longer needed.\n"
                    "4. Implement an automated account lifecycle management process."
                ),
            })

        if stale:
            findings.append({
                "finding_id": f"ACCT-001-STALE",
                "category": "Account Hygiene",
                "severity": "MEDIUM",
                "title": f"Stale Active Accounts (>{self.stale_days} days inactive)",
                "description": (
                    f"{len(stale)} enabled account(s) have not logged in for more than "
                    f"{self.stale_days} days. Unused accounts expand the attack surface unnecessarily."
                ),
                "affected": stale[:50],
                "details": {"count": len(stale), "threshold_days": self.stale_days},
                "remediation": (
                    "1. Review each account and confirm it is still needed.\n"
                    "2. Disable accounts that have exceeded your inactive account policy.\n"
                    "3. Implement automated alerts when accounts exceed your inactivity threshold."
                ),
            })

        return findings

    def detect_admincount_orphans(self, admincount_users: list, privileged_members: dict) -> list:
        """
        Accounts with adminCount=1 that are NOT members of any privileged group.
        These are 'orphaned' AdminSDHolder accounts — they still have locked-down ACLs
        but AdminSDHolder no longer manages them, so permissions may have drifted.
        """
        # Build set of all current privileged members (extract CN/sam from DNs)
        all_privileged_dns = set()
        for members in privileged_members.values():
            for m in members:
                all_privileged_dns.add(m.lower())

        orphans = []
        for user in admincount_users:
            dn = str(user.get("dn") or user.get("distinguishedName") or "").lower()
            # Check if this user's DN appears in any privileged group
            if dn and dn not in all_privileged_dns:
                orphans.append(_account_name(user))

        if not orphans:
            return []

        return [{
            "finding_id": "PRIV-001-ADMINCOUNT-ORPHAN",
            "category": "Privileged Access",
            "severity": "MEDIUM",
            "title": "Orphaned adminCount=1 Accounts",
            "description": (
                f"{len(orphans)} account(s) have adminCount=1 but are not members of any "
                "currently monitored privileged group. These may be former admin accounts "
                "that were removed from groups but not cleaned up. Their ACLs were set by "
                "AdminSDHolder and may grant excessive permissions."
            ),
            "affected": orphans,
            "details": {"count": len(orphans)},
            "remediation": (
                "1. Review each account's group memberships and permissions.\n"
                "2. If no longer needed as a privileged account, set adminCount=0.\n"
                "3. Review and reset the ACLs on the user object to match standard users.\n"
                "4. Consider running the Active Directory Delegation tool to audit permissions."
            ),
        }]

    # ------------------------------------------------------------------ #
    #  Password Policy Detections                                          #
    # ------------------------------------------------------------------ #

    def detect_password_policy_weaknesses(self, policy: Optional[dict]) -> list:
        """Analyse the default domain password policy for weaknesses."""
        if not policy:
            return [{
                "finding_id": "POL-001-NO-POLICY",
                "category": "Password Policy",
                "severity": "HIGH",
                "title": "Could Not Retrieve Password Policy",
                "description": "The default domain password policy could not be read. This may indicate a permission issue or a query failure.",
                "affected": ["Domain Password Policy"],
                "details": {},
                "remediation": "Verify service account can read domain password policy. Check LDAP query permissions.",
            }]

        findings = []

        # Minimum password length
        min_len = policy.get("minPwdLength") or 0
        try:
            min_len = int(min_len)
        except (TypeError, ValueError):
            min_len = 0

        if min_len < 12:
            findings.append({
                "finding_id": "POL-002-SHORT-PASSWORD",
                "category": "Password Policy",
                "severity": "HIGH" if min_len < 8 else "MEDIUM",
                "title": f"Weak Minimum Password Length (Currently: {min_len})",
                "description": (
                    f"The domain minimum password length is set to {min_len} characters. "
                    "Modern brute-force and spray attacks can trivially defeat short passwords. "
                    "NIST SP 800-63B recommends a minimum of 12 characters."
                ),
                "affected": ["Default Domain Password Policy"],
                "details": {"current_min_length": min_len, "recommended": 14},
                "remediation": (
                    "1. Increase minimum password length to at least 12 characters (14+ recommended).\n"
                    "2. Consider using passphrases instead of complex short passwords.\n"
                    "3. Apply stricter Fine-Grained Password Policies to privileged accounts."
                ),
            })

        # Password history
        history = policy.get("pwdHistoryLength") or 0
        try:
            history = int(history)
        except (TypeError, ValueError):
            history = 0

        if history < 10:
            findings.append({
                "finding_id": "POL-003-LOW-HISTORY",
                "category": "Password Policy",
                "severity": "MEDIUM",
                "title": f"Low Password History Length (Currently: {history})",
                "description": (
                    f"Password history is set to {history}. Users can recycle passwords "
                    "after {history} changes, undermining password rotation controls."
                ),
                "affected": ["Default Domain Password Policy"],
                "details": {"current_history": history, "recommended": 24},
                "remediation": "Set password history to at least 24 (CIS Benchmark recommendation).",
            })

        # Account lockout
        lockout = policy.get("lockoutThreshold") or 0
        try:
            lockout = int(lockout)
        except (TypeError, ValueError):
            lockout = 0

        if lockout == 0:
            findings.append({
                "finding_id": "POL-004-NO-LOCKOUT",
                "category": "Password Policy",
                "severity": "CRITICAL",
                "title": "Account Lockout Disabled",
                "description": (
                    "Account lockout threshold is set to 0 (disabled). Accounts are not locked out "
                    "after failed login attempts, enabling unlimited password spray and brute-force attacks "
                    "against any account in the domain."
                ),
                "affected": ["Default Domain Password Policy"],
                "details": {"lockout_threshold": 0},
                "remediation": (
                    "1. Enable account lockout (recommend threshold of 5-10 attempts).\n"
                    "2. Set lockout duration to at least 15 minutes.\n"
                    "3. Set lockout observation window to at least 15 minutes.\n"
                    "4. Consider Microsoft Entra Password Protection to block common passwords."
                ),
            })
        elif lockout > 10:
            findings.append({
                "finding_id": "POL-005-HIGH-LOCKOUT-THRESHOLD",
                "category": "Password Policy",
                "severity": "LOW",
                "title": f"High Account Lockout Threshold ({lockout} attempts)",
                "description": (
                    f"Account lockout threshold is set to {lockout} attempts. "
                    "Password spray attacks typically stay under 5 attempts to avoid lockouts."
                ),
                "affected": ["Default Domain Password Policy"],
                "details": {"lockout_threshold": lockout},
                "remediation": "Consider reducing the lockout threshold to 5-10 attempts.",
            })

        return findings

    # ------------------------------------------------------------------ #
    #  Computer / Infrastructure Detections                                #
    # ------------------------------------------------------------------ #

    def detect_stale_computers(self, computers: list) -> list:
        """Computer accounts that haven't authenticated recently."""
        stale = []
        threshold = self.stale_days * 2  # Computers are stickier

        for comp in computers:
            uac = int(comp.get("userAccountControl") or 0)
            if uac & UAC_DISABLED:
                continue
            last_logon = _to_datetime(comp.get("lastLogonTimestamp"))
            days = _days_since(last_logon)
            if days is not None and days >= threshold:
                name = comp.get("sAMAccountName") or comp.get("dNSHostName") or "Unknown"
                stale.append(f"{name} ({days}d ago)")

        if not stale:
            return []

        return [{
            "finding_id": "COMP-001-STALE",
            "category": "Infrastructure",
            "severity": "LOW",
            "title": f"Stale Computer Accounts (>{threshold} days)",
            "description": (
                f"{len(stale)} computer account(s) have not authenticated in over {threshold} days. "
                "Stale computer accounts may represent decommissioned machines that were not "
                "properly cleaned up, or machines that have been offline for extended periods."
            ),
            "affected": stale[:30],
            "details": {"count": len(stale), "threshold_days": threshold},
            "remediation": (
                "1. Confirm whether these machines still exist in your environment.\n"
                "2. Disable and then delete computer accounts for decommissioned machines.\n"
                "3. Implement a computer account lifecycle process tied to asset management."
            ),
        }]

    def detect_old_operating_systems(self, computers: list) -> list:
        """Detect computers running end-of-life operating systems."""
        eol_os = {
            "windows xp": "CRITICAL",
            "windows 7": "CRITICAL",
            "windows server 2003": "CRITICAL",
            "windows server 2008": "HIGH",
            "windows 8": "HIGH",
            "windows server 2012": "MEDIUM",
            "windows vista": "CRITICAL",
        }

        by_severity = {}
        for comp in computers:
            os_name = str(comp.get("operatingSystem") or "").lower()
            for eol, sev in eol_os.items():
                if eol in os_name:
                    name = comp.get("sAMAccountName") or comp.get("dNSHostName") or "Unknown"
                    full_os = comp.get("operatingSystem") or eol
                    by_severity.setdefault(sev, []).append(f"{name} ({full_os})")
                    break

        findings = []
        for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            affected = by_severity.get(severity, [])
            if not affected:
                continue
            findings.append({
                "finding_id": f"OS-001-EOL-{severity}",
                "category": "Infrastructure",
                "severity": severity,
                "title": f"End-of-Life Operating Systems Detected ({severity})",
                "description": (
                    f"{len(affected)} computer(s) are running end-of-life or unsupported operating systems. "
                    "These systems no longer receive security patches and represent a significant "
                    "attack surface for known, unpatched vulnerabilities."
                ),
                "affected": affected[:20],
                "details": {"count": len(affected)},
                "remediation": (
                    "1. Immediately isolate systems running critically EOL OS from the network.\n"
                    "2. Plan and execute OS upgrades or system decommissioning.\n"
                    "3. Apply compensating controls (network segmentation, enhanced monitoring) "
                    "for systems that cannot be immediately upgraded."
                ),
            })

        return findings

    # ------------------------------------------------------------------ #
    #  Delta-Based Detections (require baseline comparison)               #
    # ------------------------------------------------------------------ #

    def detect_privileged_group_changes(self, current_members: dict, baseline, previous_run_id: str) -> list:
        """Detect changes in privileged group membership since last scan."""
        delta = baseline.get_group_member_delta(current_members, previous_run_id)
        findings = []

        for group_name, changes in delta.items():
            added = changes.get("added", [])
            removed = changes.get("removed", [])

            if added:
                # Extract readable names from DNs
                added_names = [dn.split(",")[0].replace("CN=", "") for dn in added]
                findings.append({
                    "finding_id": f"DELTA-PRIV-ADD-{group_name.replace(' ', '_').upper()}",
                    "category": "Privileged Access Changes",
                    "severity": "CRITICAL",
                    "title": f"New Members Added to '{group_name}'",
                    "description": (
                        f"{len(added)} account(s) were added to '{group_name}' since the last scan. "
                        "Unauthorised additions to privileged groups are a key indicator of "
                        "privilege escalation or compromise."
                    ),
                    "affected": added_names,
                    "details": {"group": group_name, "added_dns": added},
                    "remediation": (
                        "1. IMMEDIATELY verify whether these additions were authorised.\n"
                        "2. If unauthorised, remove the accounts and initiate incident response.\n"
                        "3. Review who made this change (Event ID 4728/4732 in Security event log).\n"
                        "4. Check for lateral movement or persistence mechanisms."
                    ),
                })

            if removed:
                removed_names = [dn.split(",")[0].replace("CN=", "") for dn in removed]
                findings.append({
                    "finding_id": f"DELTA-PRIV-REM-{group_name.replace(' ', '_').upper()}",
                    "category": "Privileged Access Changes",
                    "severity": "MEDIUM",
                    "title": f"Members Removed from '{group_name}'",
                    "description": (
                        f"{len(removed)} account(s) were removed from '{group_name}' since the last scan. "
                        "While removals are generally positive, unexpected removals could indicate "
                        "an attacker covering their tracks."
                    ),
                    "affected": removed_names,
                    "details": {"group": group_name, "removed_dns": removed},
                    "remediation": (
                        "1. Confirm the removal was planned and authorised.\n"
                        "2. If unexpected, review who performed the change and investigate."
                    ),
                })

        return findings

    def detect_new_accounts(self, current_users: list, baseline, previous_run_id: str) -> list:
        """Detect newly created user accounts since last scan."""
        from modules.baseline_engine import BaselineEngine

        # Get usernames from current scan
        current_names = {_account_name(u) for u in current_users}

        # Get previous usernames from DB directly
        with baseline._conn() as conn:
            prev_rows = conn.execute(
                "SELECT sam_account_name FROM user_objects WHERE run_id=?", (previous_run_id,)
            ).fetchall()
        previous_names = {r["sam_account_name"] for r in prev_rows}

        new_accounts = list(current_names - previous_names)

        if not new_accounts:
            return []

        return [{
            "finding_id": "DELTA-ACCT-NEW",
            "category": "Account Changes",
            "severity": "INFO",
            "title": f"{len(new_accounts)} New User Account(s) Created",
            "description": (
                f"{len(new_accounts)} user account(s) were created since the last scan. "
                "Review to ensure all new accounts follow your provisioning process and are legitimate."
            ),
            "affected": new_accounts[:30],
            "details": {"count": len(new_accounts)},
            "remediation": (
                "1. Verify all new accounts were created through an authorised process.\n"
                "2. Confirm accounts are assigned to real, known individuals.\n"
                "3. Check that new accounts have appropriate permissions (principle of least privilege)."
            ),
        }]
