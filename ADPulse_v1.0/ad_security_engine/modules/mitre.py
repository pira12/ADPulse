"""
mitre.py
--------
Maps ADPulse findings to MITRE ATT&CK techniques.

Each finding is associated with the technique(s) an attacker would use to exploit
the weakness it describes. This lets the reports and exports speak the language
SOC / detection-engineering teams already use, and helps prioritise detections.

The mapping is keyed on the finding_id prefix (stable identifier) so it survives
free-text title/category changes and multi-domain '@domain' suffixes.
"""

# technique tuple: (technique_id, name, tactic)
_T = {
    "kerberoasting":     ("T1558.003", "Kerberoasting", "Credential Access"),
    "asrep":             ("T1558.004", "AS-REP Roasting", "Credential Access"),
    "golden_ticket":     ("T1558.001", "Golden Ticket", "Credential Access"),
    "dcsync":            ("T1003.006", "OS Credential Dumping: DCSync", "Credential Access"),
    "forge_certs":       ("T1649", "Steal or Forge Authentication Certificates", "Credential Access"),
    "sid_history":       ("T1134.005", "Access Token Manipulation: SID-History Injection", "Privilege Escalation"),
    "valid_accounts":    ("T1078", "Valid Accounts", "Defense Evasion"),
    "domain_accounts":   ("T1078.002", "Valid Accounts: Domain Accounts", "Persistence"),
    "brute_force":       ("T1110", "Brute Force", "Credential Access"),
    "password_spray":    ("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    "creds_in_files":    ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    "gpp_passwords":     ("T1552.006", "Unsecured Credentials: Group Policy Preferences", "Credential Access"),
    "unsecured_creds":   ("T1552", "Unsecured Credentials", "Credential Access"),
    "create_account":    ("T1136.002", "Create Account: Domain Account", "Persistence"),
    "account_manip":     ("T1098", "Account Manipulation", "Persistence"),
    "trust_discovery":   ("T1482", "Domain Trust Discovery", "Discovery"),
    "account_discovery": ("T1087.002", "Account Discovery: Domain Account", "Discovery"),
    "use_kerberos":      ("T1550.003", "Use Alternate Authentication Material: Pass the Ticket", "Lateral Movement"),
    "rogue_dc":          ("T1207", "Rogue Domain Controller", "Defense Evasion"),
    "exploit_remote":    ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
}

# finding_id prefix -> list of technique keys. Longest / most-specific prefixes first.
_PREFIX_TECHNIQUES = [
    ("KERB-003-KRBTGT-AGE", ["golden_ticket"]),
    ("KERB-003-PRIVESC-SPN", ["kerberoasting"]),
    ("KERB-001",            ["kerberoasting"]),
    ("KERB-002-ASREP",      ["asrep"]),
    ("KERB-004",            ["kerberoasting"]),
    ("KERB-005",            ["kerberoasting"]),
    ("ACL-001-DCSYNC",      ["dcsync"]),
    ("DELEG-001",           ["use_kerberos", "domain_accounts"]),
    ("DELEG-002",           ["use_kerberos"]),
    ("RBCD-",               ["account_manip", "use_kerberos"]),
    ("ESC",                 ["forge_certs"]),
    ("ADCS-",               ["forge_certs"]),
    ("PRIV-002-SID-HISTORY", ["sid_history"]),
    ("PRIV-001",            ["valid_accounts"]),
    ("PRIV-002",            ["account_manip"]),
    ("PRIV-003",            ["use_kerberos"]),
    ("DELTA-PRIV-",         ["account_manip"]),
    ("OPSGRP-",             ["valid_accounts"]),
    ("PWD-002-NOT-REQUIRED", ["valid_accounts", "brute_force"]),
    ("PWD-003",             ["unsecured_creds"]),
    ("PWD-004",             ["creds_in_files"]),
    ("PWD-001",             ["valid_accounts"]),
    ("GPP-",                ["gpp_passwords"]),
    ("SYSVOL-",             ["creds_in_files"]),
    ("POL-004",             ["password_spray"]),
    ("POL-002",             ["brute_force"]),
    ("POL-",                ["brute_force"]),
    ("CONF-001-MACHINE-QUOTA", ["create_account", "account_manip"]),
    ("CONF-002-NO-LAPS",    ["domain_accounts"]),
    ("ANON-",               ["account_discovery"]),
    ("TRUST-001",           ["sid_history"]),
    ("TRUST-",              ["trust_discovery"]),
    ("ACCT-001",            ["valid_accounts"]),
    ("DELTA-ACCT-",         ["create_account"]),
    ("OS-",                 ["exploit_remote"]),
]


def techniques_for(finding_id: str) -> list:
    """Return a list of ATT&CK technique dicts for a finding_id."""
    base = str(finding_id or "").split("@", 1)[0]
    for prefix, keys in _PREFIX_TECHNIQUES:
        if base.startswith(prefix):
            return [
                {"id": _T[k][0], "name": _T[k][1], "tactic": _T[k][2]}
                for k in keys
            ]
    return []


def attach(findings: list) -> list:
    """
    Idempotently attach a 'mitre' list to each finding (in place) and return it.
    Safe to call multiple times - derived purely from finding_id.
    """
    for f in findings or []:
        f["mitre"] = techniques_for(f.get("finding_id", ""))
    return findings
