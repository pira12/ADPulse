"""Shared mock AD data for all tests."""
from datetime import datetime, timezone, timedelta


def make_user(sam, enabled=True, admin_count=0, spn=None, last_logon_days_ago=10,
              pwd_last_set_days_ago=30, no_preauth=False, uac=None):
    """Build a minimal user dict matching what ldap_collector returns."""
    now = datetime.now(tz=timezone.utc)
    last_logon = now - timedelta(days=last_logon_days_ago)
    pwd_last_set = now - timedelta(days=pwd_last_set_days_ago)

    base_uac = 0x200  # NORMAL_ACCOUNT
    if not enabled:
        base_uac |= 0x2
    if no_preauth:
        base_uac |= 0x400000
    if uac is not None:
        base_uac = uac

    return {
        "sAMAccountName": sam,
        "displayName": sam,
        "userAccountControl": base_uac,
        "adminCount": admin_count,
        "lastLogonTimestamp": last_logon,
        "pwdLastSet": pwd_last_set,
        "servicePrincipalName": spn or [],
        "dn": f"CN={sam},OU=Users,DC=corp,DC=local",
    }


def make_computer(sam, os="Windows Server 2022", last_logon_days_ago=5, enabled=True):
    now = datetime.now(tz=timezone.utc)
    return {
        "sAMAccountName": sam,
        "dNSHostName": f"{sam}.corp.local",
        "operatingSystem": os,
        "operatingSystemVersion": "10.0 (20348)",
        "lastLogonTimestamp": now - timedelta(days=last_logon_days_ago),
        "userAccountControl": 0x1000 if enabled else 0x1002,
        "dn": f"CN={sam},OU=Computers,DC=corp,DC=local",
    }


SAMPLE_PRIVILEGED_MEMBERS = {
    "Domain Admins": [
        "CN=admin1,OU=Users,DC=corp,DC=local",
        "CN=admin2,OU=Users,DC=corp,DC=local",
    ],
    "Enterprise Admins": [
        "CN=entadmin,OU=Users,DC=corp,DC=local",
    ],
}

SAMPLE_KERBEROASTABLE = [
    {
        "sAMAccountName": "svc-sql",
        "servicePrincipalName": ["MSSQLSvc/db01.corp.local:1433"],
        "adminCount": 0,
        "userAccountControl": 0x200,
        "lastLogonTimestamp": datetime.now(tz=timezone.utc) - timedelta(days=10),
        "pwdLastSet": datetime.now(tz=timezone.utc) - timedelta(days=30),
        "dn": "CN=svc-sql,OU=ServiceAccounts,DC=corp,DC=local",
    }
]

SAMPLE_GROUPS = [
    {
        "sAMAccountName": "Domain Admins",
        "member": ["CN=admin1,OU=Users,DC=corp,DC=local"],
        "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
    },
    {
        "sAMAccountName": "HelpDesk",
        "member": ["CN=jsmith,OU=Users,DC=corp,DC=local",
                   "CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        "dn": "CN=HelpDesk,OU=Groups,DC=corp,DC=local",
    },
]

SAMPLE_DOMAIN_CONTROLLERS = [
    {
        "sAMAccountName": "DC01$",
        "dNSHostName": "dc01.corp.local",
        "dn": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
    }
]
