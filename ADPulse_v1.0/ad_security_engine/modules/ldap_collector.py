"""
ldap_collector.py
-----------------
Handles all LDAP queries against Active Directory.
Requires only a standard domain user account - NO elevated privileges.

All data is read-only. No writes are performed.
"""

import logging
import socket
from datetime import datetime, timezone
from typing import Optional

from ldap3 import (
    Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
)
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)

# Windows FILETIME epoch offset (difference between 1601-01-01 and 1970-01-01 in 100ns intervals)
WINDOWS_EPOCH_OFFSET = 116444736000000000
NEVER_EXPIRE_VALUE = 9223372036854775807  # Max int64, means "never"


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME (100-ns intervals since 1601) to Python datetime."""
    if filetime in (0, NEVER_EXPIRE_VALUE):
        return None
    try:
        timestamp = (filetime - WINDOWS_EPOCH_OFFSET) / 10_000_000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def domain_to_base_dn(domain: str) -> str:
    """Convert 'company.local' to 'DC=company,DC=local'."""
    parts = domain.strip().split(".")
    return ",".join(f"DC={p}" for p in parts)


class LDAPCollector:
    """
    Connects to an Active Directory domain controller via LDAP and
    collects security-relevant data using only standard user credentials.
    """

    def __init__(self, config: dict):
        self.server_host = config["server"]
        self.domain = config["domain"]
        self.username = config["username"]
        self.password = config["password"]
        self.port = int(config.get("port", 389))
        self.use_ssl = config.get("use_ssl", "false").lower() == "true"
        self.timeout = int(config.get("timeout", 30))
        self.base_dn = domain_to_base_dn(self.domain)
        self.conn: Optional[Connection] = None

    # ------------------------------------------------------------------ #
    #  Connection Management                                               #
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Establish LDAP connection using NTLM authentication."""
        try:
            server = Server(
                self.server_host,
                port=self.port,
                use_ssl=self.use_ssl,
                get_info=ALL,
                connect_timeout=self.timeout,
            )
            # NTLM bind - works with domain\user or UPN
            bind_user = f"{self.domain}\\{self.username}"
            self.conn = Connection(
                server,
                user=bind_user,
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
                raise_exceptions=True,
            )
            logger.info(f"Connected to LDAP server {self.server_host} as {bind_user}")
            return True
        except LDAPException as e:
            logger.error(f"LDAP connection failed: {e}")
            return False
        except socket.error as e:
            logger.error(f"Network error connecting to {self.server_host}: {e}")
            return False

    def disconnect(self):
        """Cleanly close the LDAP connection."""
        if self.conn and self.conn.bound:
            self.conn.unbind()
            logger.info("LDAP connection closed.")

    def _search(self, search_filter: str, attributes: list, search_base: str = None) -> list:
        """
        Generic LDAP search helper.
        Returns a list of entry dicts or empty list on failure.
        """
        if not self.conn or not self.conn.bound:
            logger.error("Not connected to LDAP. Call connect() first.")
            return []

        base = search_base or self.base_dn
        try:
            self.conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
            )
            results = []
            for entry in self.conn.entries:
                row = {"dn": entry.entry_dn}
                for attr in attributes:
                    try:
                        val = getattr(entry, attr, None)
                        row[attr] = val.value if val else None
                    except Exception:
                        row[attr] = None
                results.append(row)
            return results
        except LDAPException as e:
            logger.error(f"LDAP search failed (filter={search_filter}): {e}")
            return []

    # ------------------------------------------------------------------ #
    #  User Account Queries                                                #
    # ------------------------------------------------------------------ #

    def get_all_users(self) -> list:
        """
        Fetch all user accounts with security-relevant attributes.
        Only standard LDAP attributes - readable by any domain user.
        """
        attrs = [
            "sAMAccountName", "displayName", "mail", "userPrincipalName",
            "userAccountControl", "pwdLastSet", "lastLogonTimestamp",
            "adminCount", "memberOf", "servicePrincipalName",
            "whenCreated", "whenChanged", "description",
            "accountExpires", "badPasswordCount", "distinguishedName",
        ]
        # Filter: user objects only (objectCategory=person, objectClass=user)
        search_filter = "(&(objectCategory=person)(objectClass=user))"
        users = self._search(search_filter, attrs)
        logger.info(f"Retrieved {len(users)} user accounts from AD.")
        return users

    def get_kerberoastable_accounts(self) -> list:
        """
        Find accounts with Service Principal Names (SPNs) set - Kerberoasting targets.
        Any domain user can request Kerberos TGS tickets for these accounts.
        """
        attrs = [
            "sAMAccountName", "displayName", "servicePrincipalName",
            "userAccountControl", "adminCount", "pwdLastSet",
            "lastLogonTimestamp", "distinguishedName",
        ]
        # User accounts (not computers) with an SPN set
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"  # Enabled only
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} Kerberoastable accounts.")
        return results

    def get_asreproastable_accounts(self) -> list:
        """
        Find accounts with Kerberos pre-authentication disabled (AS-REP Roasting).
        UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
        """
        attrs = [
            "sAMAccountName", "displayName", "userAccountControl",
            "pwdLastSet", "lastLogonTimestamp", "adminCount", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} AS-REP Roastable accounts.")
        return results

    def get_accounts_password_never_expires(self) -> list:
        """
        Accounts with 'Password Never Expires' flag set.
        UAC flag 0x10000 = DONT_EXPIRE_PASSWORD
        """
        attrs = [
            "sAMAccountName", "displayName", "userAccountControl",
            "pwdLastSet", "lastLogonTimestamp", "adminCount", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with Password Never Expires.")
        return results

    def get_admincount_accounts(self) -> list:
        """
        Accounts with adminCount=1 - previously or currently protected by AdminSDHolder.
        Orphaned adminCount=1 can be a security risk (SDHolder no longer applies
        but permissions may have been set and not cleaned up).
        """
        attrs = [
            "sAMAccountName", "displayName", "adminCount", "memberOf",
            "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with adminCount=1.")
        return results

    # ------------------------------------------------------------------ #
    #  Group & Privileged Access Queries                                   #
    # ------------------------------------------------------------------ #

    def get_privileged_group_members(self, group_names: list) -> dict:
        """
        Retrieve members of specified privileged groups.
        Returns dict: {group_name: [member_dn, ...]}
        """
        result = {}
        for group_name in group_names:
            # Search for the group by name
            group_filter = f"(&(objectClass=group)(sAMAccountName={group_name}))"
            groups = self._search(group_filter, ["member", "distinguishedName", "sAMAccountName"])
            if not groups:
                # Try CN match
                group_filter = f"(&(objectClass=group)(cn={group_name}))"
                groups = self._search(group_filter, ["member", "distinguishedName", "sAMAccountName"])

            if groups:
                members = groups[0].get("member") or []
                if isinstance(members, str):
                    members = [members]
                result[group_name] = members if members else []
                logger.debug(f"Group '{group_name}': {len(result[group_name])} members.")
            else:
                logger.warning(f"Group '{group_name}' not found in AD.")
                result[group_name] = []

        return result

    def get_all_groups(self) -> list:
        """Get all security groups with basic attributes."""
        attrs = [
            "sAMAccountName", "cn", "description", "member",
            "groupType", "adminCount", "whenCreated", "whenChanged", "distinguishedName",
        ]
        search_filter = "(&(objectClass=group)(|(groupType=-2147483646)(groupType=-2147483644)(groupType=-2147483640)))"
        results = self._search(search_filter, attrs)
        logger.info(f"Retrieved {len(results)} security groups.")
        return results

    # ------------------------------------------------------------------ #
    #  Computer Account Queries                                            #
    # ------------------------------------------------------------------ #

    def get_all_computers(self) -> list:
        """Get all computer accounts."""
        attrs = [
            "sAMAccountName", "dNSHostName", "operatingSystem",
            "operatingSystemVersion", "lastLogonTimestamp",
            "whenCreated", "userAccountControl", "distinguishedName",
        ]
        search_filter = "(objectClass=computer)"
        results = self._search(search_filter, attrs)
        logger.info(f"Retrieved {len(results)} computer accounts.")
        return results

    def get_domain_controllers(self) -> list:
        """Identify domain controllers (userAccountControl flag 0x2000 = SERVER_TRUST_ACCOUNT)."""
        attrs = [
            "sAMAccountName", "dNSHostName", "operatingSystem",
            "lastLogonTimestamp", "whenCreated", "distinguishedName",
        ]
        search_filter = (
            "(&(objectClass=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} domain controllers.")
        return results

    # ------------------------------------------------------------------ #
    #  Policy & Configuration Queries                                      #
    # ------------------------------------------------------------------ #

    def get_password_policy(self) -> Optional[dict]:
        """Retrieve the default domain password policy."""
        attrs = [
            "maxPwdAge", "minPwdAge", "minPwdLength",
            "pwdHistoryLength", "pwdProperties", "lockoutThreshold",
            "lockoutDuration", "lockOutObservationWindow",
        ]
        search_filter = "(objectClass=domainDNS)"
        results = self._search(attrs=attrs, search_filter=search_filter, search_base=self.base_dn)
        if results:
            policy = results[0]
            # Convert large integer values to human-readable
            for key in ["maxPwdAge", "minPwdAge", "lockoutDuration", "lockOutObservationWindow"]:
                val = policy.get(key)
                if val and isinstance(val, int) and val < 0:
                    # Stored as negative 100-ns intervals
                    policy[f"{key}_days"] = abs(val) / 864000000000
            logger.info("Retrieved default domain password policy.")
            return policy
        logger.warning("Could not retrieve domain password policy.")
        return None

    def get_gpo_links(self) -> list:
        """Get GPO links at domain and OU level."""
        attrs = ["distinguishedName", "gPLink", "gPOptions", "ou", "dc", "name"]
        search_filter = "(|(objectClass=domain)(objectClass=organizationalUnit))"
        results = self._search(search_filter, attrs)
        logger.info(f"Retrieved {len(results)} GPO-linked containers.")
        return results

    def get_fine_grained_password_policies(self) -> list:
        """Retrieve Fine-Grained Password Policies (PSOs)."""
        pso_container = f"CN=Password Settings Container,CN=System,{self.base_dn}"
        attrs = [
            "cn", "msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
            "msDS-MaximumPasswordAge", "msDS-MinimumPasswordAge",
            "msDS-LockoutThreshold", "msDS-LockoutDuration",
            "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo",
            "msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled",
        ]
        results = self._search(
            search_filter="(objectClass=msDS-PasswordSettings)",
            attributes=attrs,
            search_base=pso_container,
        )
        logger.info(f"Found {len(results)} Fine-Grained Password Policies.")
        return results

    # ------------------------------------------------------------------ #
    #  Delegation Queries                                                  #
    # ------------------------------------------------------------------ #

    def get_unconstrained_delegation_accounts(self) -> list:
        """
        Find accounts (users + computers) with unconstrained delegation.
        UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
        Excludes Domain Controllers (which legitimately have this flag).
        """
        attrs = [
            "sAMAccountName", "displayName", "userAccountControl",
            "servicePrincipalName", "lastLogonTimestamp", "distinguishedName",
        ]
        # Exclude DCs (SERVER_TRUST_ACCOUNT flag 0x2000)
        search_filter = (
            "(&(|(objectClass=user)(objectClass=computer))"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with unconstrained delegation.")
        return results

    def get_constrained_delegation_accounts(self) -> list:
        """
        Find accounts with constrained delegation (msDS-AllowedToDelegateTo).
        """
        attrs = [
            "sAMAccountName", "displayName", "msDS-AllowedToDelegateTo",
            "userAccountControl", "lastLogonTimestamp", "distinguishedName",
        ]
        search_filter = (
            "(&(|(objectClass=user)(objectClass=computer))"
            "(msDS-AllowedToDelegateTo=*))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with constrained delegation.")
        return results

    # ------------------------------------------------------------------ #
    #  Additional Security Queries (Read-Only)                             #
    # ------------------------------------------------------------------ #

    def get_password_not_required_accounts(self) -> list:
        """
        Accounts with PASSWD_NOTREQD flag (UAC 0x20).
        These accounts can have an empty password — a critical misconfiguration.
        """
        attrs = [
            "sAMAccountName", "displayName", "userAccountControl",
            "adminCount", "whenCreated", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=32)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with PASSWD_NOTREQD.")
        return results

    def get_reversible_encryption_accounts(self) -> list:
        """
        Accounts storing passwords with reversible encryption (UAC 0x80).
        Effectively plaintext password storage — a severe weakness.
        """
        attrs = [
            "sAMAccountName", "displayName", "userAccountControl",
            "adminCount", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=128)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with reversible encryption.")
        return results

    def get_accounts_with_sid_history(self) -> list:
        """
        Accounts with SID History attribute set.
        SID History can be abused for cross-domain privilege escalation.
        Readable by any authenticated domain user.
        """
        attrs = [
            "sAMAccountName", "displayName", "sIDHistory",
            "adminCount", "userAccountControl", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)(sIDHistory=*))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with SID History.")
        return results

    def get_protected_users_members(self) -> list:
        """
        Get members of the 'Protected Users' security group.
        Privileged accounts NOT in this group miss important protections.
        """
        group_filter = "(&(objectClass=group)(sAMAccountName=Protected Users))"
        groups = self._search(group_filter, ["member", "distinguishedName"])
        if groups:
            members = groups[0].get("member") or []
            if isinstance(members, str):
                members = [members]
            logger.info(f"Protected Users group has {len(members)} members.")
            return members
        logger.warning("Protected Users group not found.")
        return []

    def get_users_with_description_passwords(self) -> list:
        """
        Find user accounts whose description field contains password-like strings.
        A surprisingly common bad practice — readable by any domain user.
        """
        attrs = [
            "sAMAccountName", "displayName", "description",
            "adminCount", "distinguishedName",
        ]
        # Search for common password indicators in description
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(|(description=*pass*)(description=*pwd*)(description=*wachtwoord*)"
            "(description=*mot de passe*)(description=*contraseña*))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with potential passwords in description.")
        return results

    def get_computers_without_laps(self) -> list:
        """
        Find computer accounts without LAPS (Local Administrator Password Solution).
        Checks for the ms-Mcs-AdmPwdExpirationTime attribute — if absent, LAPS
        is likely not deployed on that machine. Readable by standard users.
        """
        attrs = [
            "sAMAccountName", "dNSHostName", "operatingSystem",
            "ms-Mcs-AdmPwdExpirationTime", "distinguishedName",
        ]
        # Computers without the LAPS expiration attribute (LAPS not deployed)
        search_filter = (
            "(&(objectClass=computer)"
            "(!(ms-Mcs-AdmPwdExpirationTime=*))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"  # Exclude DCs
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} computers without LAPS.")
        return results

    # ------------------------------------------------------------------ #
    #  Domain Info                                                         #
    # ------------------------------------------------------------------ #

    def get_domain_info(self) -> dict:
        """Get high-level domain information."""
        attrs = [
            "name", "distinguishedName", "whenCreated",
            "domainFunctionality", "forestFunctionality",
            "ms-DS-MachineAccountQuota",
        ]
        results = self._search("(objectClass=domainDNS)", attrs)
        if results:
            info = results[0]
            info["base_dn"] = self.base_dn
            info["server"] = self.server_host
            return info
        return {"base_dn": self.base_dn, "server": self.server_host}

    def test_connection(self) -> dict:
        """Test connectivity and return server info."""
        if not self.connect():
            return {"success": False, "error": "Connection failed"}
        info = self.get_domain_info()
        self.disconnect()
        return {"success": True, "domain_info": info}
