"""Tests for new security detections added in Improvement 3."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timezone, timedelta
from modules.detections import DetectionEngine
from tests.fixtures import (
    make_user, SAMPLE_PRIVILEGED_MEMBERS, SAMPLE_KERBEROASTABLE,
    SAMPLE_GROUPS, SAMPLE_DOMAIN_CONTROLLERS,
)

CFG = {
    "stale_account_days": "60",
    "password_age_days": "365",
    "privileged_groups": "Domain Admins,Enterprise Admins",
    "dormant_admin_days": "90",
}
engine = DetectionEngine(CFG)


# ── DCSync ──────────────────────────────────────────────────────────────────

def test_dcsync_flags_non_dc_account():
    """A non-DC account with DCSync rights should produce a CRITICAL finding."""
    domain_acl = [
        {"sam_account_name": "rogue-svc", "sid": "S-1-5-21-1-2-3-500", "dn": "CN=rogue-svc,..."},
    ]
    domain_controllers = SAMPLE_DOMAIN_CONTROLLERS  # DC01$ — not rogue-svc

    findings = engine.detect_dcsync_rights(domain_acl, domain_controllers)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["finding_id"] == "ACL-001-DCSYNC"
    assert "rogue-svc" in findings[0]["affected"]


def test_dcsync_ignores_dc_accounts():
    """Domain controllers with DCSync rights are expected — not flagged."""
    domain_acl = [
        {"sam_account_name": "DC01$", "sid": "S-1-5-21-1-2-3-1000", "dn": "CN=DC01,..."},
    ]
    findings = engine.detect_dcsync_rights(domain_acl, SAMPLE_DOMAIN_CONTROLLERS)
    assert findings == []


def test_dcsync_empty_acl():
    """Empty domain ACL produces no findings."""
    assert engine.detect_dcsync_rights([], SAMPLE_DOMAIN_CONTROLLERS) == []


# ── Dormant Privileged Accounts ──────────────────────────────────────────────

def test_dormant_admin_flagged():
    """A privileged account inactive for >90 days should be flagged."""
    users = [
        make_user("admin1", last_logon_days_ago=95),   # dormant
        make_user("admin2", last_logon_days_ago=10),   # active
    ]
    # admin1 is in Domain Admins
    priv = {"Domain Admins": ["CN=admin1,OU=Users,DC=corp,DC=local"]}

    findings = engine.detect_dormant_privileged_accounts(users, priv)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["finding_id"] == "PRIV-001-DORMANT-ADMIN"
    assert "admin1" in findings[0]["affected"]
    assert "admin2" not in findings[0]["affected"]


def test_active_admin_not_flagged():
    """A recently active privileged account must not be flagged."""
    users = [make_user("admin1", last_logon_days_ago=5)]
    priv = {"Domain Admins": ["CN=admin1,OU=Users,DC=corp,DC=local"]}
    assert engine.detect_dormant_privileged_accounts(users, priv) == []


def test_dormant_non_admin_not_flagged():
    """A dormant account that is not privileged must not be flagged."""
    users = [make_user("jsmith", last_logon_days_ago=200)]
    priv = {"Domain Admins": []}  # jsmith not in any privileged group
    assert engine.detect_dormant_privileged_accounts(users, priv) == []


# ── Nested Group Privilege ───────────────────────────────────────────────────

def test_nested_privilege_flagged():
    """jsmith → HelpDesk → Domain Admins should be flagged."""
    # SAMPLE_GROUPS: HelpDesk has member jsmith AND Domain Admins
    # Domain Admins is a monitored privileged group
    priv = {"Domain Admins": ["CN=admin1,OU=Users,DC=corp,DC=local"]}

    findings = engine.detect_nested_privilege(SAMPLE_GROUPS, priv)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "PRIV-002-NESTED-PRIV"
    assert findings[0]["severity"] == "MEDIUM"
    # The affected entry should describe the chain
    assert any("jsmith" in a for a in findings[0]["affected"])


def test_direct_member_not_nested():
    """A direct member of a privileged group is not a nested finding."""
    groups = [
        {
            "sAMAccountName": "Domain Admins",
            "member": ["CN=admin1,OU=Users,DC=corp,DC=local"],
            "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        }
    ]
    priv = {"Domain Admins": ["CN=admin1,OU=Users,DC=corp,DC=local"]}
    findings = engine.detect_nested_privilege(groups, priv)
    # admin1 is a direct member, not nested
    assert findings == []


def test_no_groups_no_findings():
    assert engine.detect_nested_privilege([], SAMPLE_PRIVILEGED_MEMBERS) == []


# ── Service Accounts in Privileged Groups ───────────────────────────────────

def test_privileged_spn_flagged():
    """A kerberoastable account that is also in a privileged group → CRITICAL."""
    kerberoastable = [
        {
            "sAMAccountName": "svc-sql",
            "servicePrincipalName": ["MSSQLSvc/db01:1433"],
            "dn": "CN=svc-sql,OU=ServiceAccounts,DC=corp,DC=local",
        }
    ]
    priv = {"Domain Admins": ["CN=svc-sql,OU=ServiceAccounts,DC=corp,DC=local"]}

    findings = engine.detect_privileged_spn(kerberoastable, priv)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["finding_id"] == "KERB-003-PRIVESC-SPN"
    assert "svc-sql" in findings[0]["affected"]


def test_non_privileged_kerberoastable_not_flagged():
    """A Kerberoastable account that is NOT in any privileged group → not flagged."""
    kerberoastable = [
        {
            "sAMAccountName": "svc-web",
            "servicePrincipalName": ["HTTP/web01:80"],
            "dn": "CN=svc-web,OU=ServiceAccounts,DC=corp,DC=local",
        }
    ]
    priv = {"Domain Admins": ["CN=admin1,OU=Users,DC=corp,DC=local"]}
    assert engine.detect_privileged_spn(kerberoastable, priv) == []


def test_privileged_spn_empty_inputs():
    assert engine.detect_privileged_spn([], SAMPLE_PRIVILEGED_MEMBERS) == []
    assert engine.detect_privileged_spn(SAMPLE_KERBEROASTABLE, {}) == []
