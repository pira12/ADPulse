"""
ldap_collector.py
-----------------
Handles all LDAP queries against Active Directory.
Supports two authentication modes:
  1. Integrated Windows auth (default) — uses the logged-in user's Kerberos token.
     Just run the tool on a domain-joined Windows VM with read access to AD.
  2. Explicit credentials — provide username/password in config.ini for remote use.

All data is read-only. No writes are performed.
"""

import logging
import os
import socket
import struct
from datetime import datetime, timezone
from typing import Optional

from ldap3 import (
    Server, Connection, ALL, NTLM, SASL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
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


# DCSync right GUIDs in Windows mixed-endian binary format
# DS-Replication-Get-Changes:     {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
# DS-Replication-Get-Changes-All: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
_DCSYNC_GUIDS = {
    bytes.fromhex("aaf63111079cd111f79f00c04fc2dcd2"),  # Get-Changes
    bytes.fromhex("adf63111079cd111f79f00c04fc2dcd2"),  # Get-Changes-All
}
_ACE_TYPE_ALLOWED_OBJECT = 0x05
_ACE_OBJECT_TYPE_PRESENT = 0x1
_ACE_INHERITED_OBJECT_PRESENT = 0x2


def _parse_dacl_for_dcsync(sd: bytes) -> list:
    """
    Walk a Windows binary SECURITY_DESCRIPTOR_RELATIVE and return raw SID bytes
    for any ACE granting DCSync rights (DS-Replication-Get-Changes or Get-Changes-All).
    Returns list of raw SID bytes. Empty list if none found or on parse error.
    """
    if not sd or len(sd) < 20:
        return []
    try:
        # SD header: Revision(1) Sbz1(1) Control(2) OffOwner(4) OffGroup(4) OffSacl(4) OffDacl(4)
        offset_dacl = struct.unpack_from("<I", sd, 16)[0]
        if offset_dacl == 0 or offset_dacl >= len(sd):
            return []

        # ACL header: Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
        ace_count = struct.unpack_from("<H", sd, offset_dacl + 4)[0]
        ace_offset = offset_dacl + 8

        sid_bytes_list = []
        for _ in range(ace_count):
            if ace_offset + 4 > len(sd):
                break
            ace_type, _ace_flags, ace_size = struct.unpack_from("<BBH", sd, ace_offset)

            if ace_type == _ACE_TYPE_ALLOWED_OBJECT and ace_offset + ace_size <= len(sd):
                # ACCESS_ALLOWED_OBJECT_ACE: Header(4) Mask(4) Flags(4) [ObjectType(16)] [InhType(16)] SID
                flags = struct.unpack_from("<I", sd, ace_offset + 8)[0]
                guid_start = ace_offset + 12

                if flags & _ACE_OBJECT_TYPE_PRESENT:
                    obj_type = sd[guid_start: guid_start + 16]
                    if obj_type in _DCSYNC_GUIDS:
                        # Skip past ObjectType and optional InheritedObjectType to reach SID
                        sid_start = guid_start + 16
                        if flags & _ACE_INHERITED_OBJECT_PRESENT:
                            sid_start += 16
                        if sid_start < ace_offset + ace_size:
                            sid_size = 8 + sd[sid_start + 1] * 4
                            sid_bytes_list.append(bytes(sd[sid_start: sid_start + sid_size]))

            ace_offset += ace_size
            if ace_size == 0:
                break
        return sid_bytes_list
    except (struct.error, IndexError):
        return []


def _sid_bytes_to_str(sid_bytes: bytes) -> str:
    """Convert raw Windows SID bytes to S-R-A-SA... string."""
    if len(sid_bytes) < 8:
        return "S-?"
    revision = sid_bytes[0]
    sub_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], "big")
    subs = struct.unpack_from(f"<{sub_count}I", sid_bytes, 8)
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)


def _sid_bytes_to_ldap_filter(sid_bytes: bytes) -> str:
    """Escape SID bytes for use in an LDAP search filter."""
    return "".join(f"\\{b:02x}" for b in sid_bytes)


class LDAPCollector:
    """
    Connects to an Active Directory domain controller via LDAP and
    collects security-relevant data.

    Authentication modes:
      - Integrated Windows auth: leave username/password blank in config.
        Uses the logged-in Windows user's Kerberos session (SASL + GSS-SPNEGO).
      - Explicit credentials: set username/password in config for NTLM bind.
    """

    def __init__(self, config: dict):
        self.server_host = config["server"]
        self.domain = config["domain"]
        self.username = config.get("username", "").strip()
        self.password = config.get("password", "").strip()
        self.port = int(config.get("port", 389))
        self.use_ssl = config.get("use_ssl", "false").lower() == "true"
        self.timeout = int(config.get("timeout", 30))
        self.base_dn = domain_to_base_dn(self.domain)
        self.conn: Optional[Connection] = None
        self.use_integrated_auth = not self.username or not self.password

    # ------------------------------------------------------------------ #
    #  Connection Management                                               #
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """
        Establish LDAP connection.
        Uses integrated Windows auth (Kerberos) when no credentials are configured,
        or NTLM when explicit username/password are provided.
        """
        try:
            server = Server(
                self.server_host,
                port=self.port,
                use_ssl=self.use_ssl,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            if self.use_integrated_auth:
                # Integrated Windows authentication — uses the logged-in user's
                # Kerberos ticket. Works on domain-joined Windows machines.
                self.conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism="GSS-SPNEGO",
                    auto_bind=True,
                    raise_exceptions=True,
                )
                whoami = os.environ.get("USERNAME", os.environ.get("USER", "current user"))
                logger.info(
                    f"Connected to LDAP server {self.server_host} "
                    f"using integrated Windows auth ({whoami})"
                )
            else:
                # Explicit NTLM bind with username/password from config
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
            if self.use_integrated_auth:
                logger.error(
                    "Integrated auth failed. Make sure you are running on a "
                    "domain-joined Windows machine with a valid Kerberos ticket, "
                    "or provide explicit username/password in config.ini."
                )
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
    #  Domain Info & Configuration Queries                                 #
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

    def get_krbtgt_account(self) -> Optional[dict]:
        """
        Get the krbtgt account — the Kerberos ticket-granting service account.
        Its password age is a critical security indicator.
        """
        attrs = [
            "sAMAccountName", "pwdLastSet", "whenChanged",
            "whenCreated", "distinguishedName",
        ]
        results = self._search(
            "(&(objectClass=user)(sAMAccountName=krbtgt))", attrs
        )
        if results:
            logger.info("Retrieved krbtgt account info.")
            return results[0]
        logger.warning("krbtgt account not found.")
        return None

    def get_trust_relationships(self) -> list:
        """
        Enumerate domain trust relationships.
        Readable by any authenticated domain user.
        """
        attrs = [
            "cn", "trustPartner", "trustDirection", "trustType",
            "trustAttributes", "whenCreated", "whenChanged",
            "flatName", "distinguishedName",
        ]
        results = self._search("(objectClass=trustedDomain)", attrs)
        logger.info(f"Found {len(results)} trust relationships.")
        return results

    def get_tombstone_lifetime(self) -> Optional[int]:
        """
        Get the tombstone lifetime for the forest.
        Read from CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration.
        """
        config_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{self.base_dn}"
        results = self._search(
            "(objectClass=nTDSService)",
            ["tombstoneLifetime"],
            search_base=config_dn,
        )
        if results and results[0].get("tombstoneLifetime") is not None:
            val = results[0]["tombstoneLifetime"]
            try:
                lifetime = int(val)
                logger.info(f"Tombstone lifetime: {lifetime} days.")
                return lifetime
            except (TypeError, ValueError):
                pass
        logger.debug("Could not retrieve tombstone lifetime.")
        return None

    def get_dns_zones(self) -> list:
        """
        Enumerate DNS zones stored in AD.
        Readable by any authenticated domain user.
        """
        dns_base = f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"
        attrs = [
            "dc", "name", "distinguishedName", "whenCreated",
        ]
        results = self._search(
            "(objectClass=dnsZone)", attrs, search_base=dns_base
        )
        # Fallback to forest DNS partition
        if not results:
            dns_base = f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.base_dn}"
            results = self._search(
                "(objectClass=dnsZone)", attrs, search_base=dns_base
            )
        logger.info(f"Found {len(results)} DNS zones.")
        return results

    def get_des_only_accounts(self) -> list:
        """
        Accounts with USE_DES_KEY_ONLY flag (UAC 0x200000).
        DES encryption is trivially breakable.
        """
        attrs = [
            "sAMAccountName", "displayName", "userAccountControl",
            "adminCount", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        logger.info(f"Found {len(results)} accounts with DES-only encryption.")
        return results

    def get_expiring_accounts(self, days_ahead: int = 30) -> list:
        """
        Find accounts expiring within the specified number of days.
        Uses the accountExpires attribute (Windows FILETIME format).
        """
        # We fetch all users with accountExpires set and filter in Python
        # because LDAP range filters on large integers are complex
        attrs = [
            "sAMAccountName", "displayName", "accountExpires",
            "userAccountControl", "distinguishedName",
        ]
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(accountExpires>=1)(!(accountExpires=9223372036854775807))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._search(search_filter, attrs)
        # Filter to only accounts expiring within the window
        expiring = []
        now = datetime.now(tz=timezone.utc)
        for r in results:
            exp = r.get("accountExpires")
            if exp:
                dt = filetime_to_datetime(int(exp)) if isinstance(exp, (int, str)) else None
                if dt and dt > now and (dt - now).days <= days_ahead:
                    r["_expires_dt"] = dt.isoformat()
                    r["_expires_days"] = (dt - now).days
                    expiring.append(r)
        logger.info(f"Found {len(expiring)} accounts expiring within {days_ahead} days.")
        return expiring

    def test_connection(self) -> dict:
        """Test connectivity and return server info."""
        if not self.connect():
            return {"success": False, "error": "Connection failed"}
        info = self.get_domain_info()
        self.disconnect()
        return {"success": True, "domain_info": info}

    def get_domain_acl(self) -> list:
        """
        Query the nTSecurityDescriptor on the domain root and return a list of
        dicts for accounts with DCSync rights (non-DC principals only).

        Each dict: {"sam_account_name": str, "sid": str, "dn": str}
        Returns empty list if the attribute is inaccessible or unparseable.
        """
        try:
            from ldap3 import BASE
            self.conn.search(
                search_base=self.base_dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["nTSecurityDescriptor"],
            )
            if not self.conn.entries:
                return []

            sd = self.conn.entries[0]["nTSecurityDescriptor"].value
            if not sd:
                return []

            # Parse out raw SID bytes for DCSync ACEs
            sid_bytes_list = _parse_dacl_for_dcsync(bytes(sd))
            if not sid_bytes_list:
                return []

            results = []
            for sid_bytes in sid_bytes_list:
                sid_str = _sid_bytes_to_str(sid_bytes)
                # Resolve SID → sAMAccountName via LDAP
                ldap_filter = _sid_bytes_to_ldap_filter(sid_bytes)
                self.conn.search(
                    self.base_dn,
                    f"(objectSid={ldap_filter})",
                    attributes=["sAMAccountName", "distinguishedName"],
                )
                if self.conn.entries:
                    entry = self.conn.entries[0]
                    results.append({
                        "sam_account_name": str(entry["sAMAccountName"].value or ""),
                        "sid": sid_str,
                        "dn": str(entry["distinguishedName"].value or ""),
                    })
                else:
                    results.append({"sam_account_name": sid_str, "sid": sid_str, "dn": ""})

            return results
        except Exception as e:
            logger.warning(f"get_domain_acl failed: {e}")
            return []
