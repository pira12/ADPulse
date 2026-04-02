"""Tests for parallel AD data collection."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import MagicMock, patch
from main import _collect_ad_data


def _make_mock_collector(fail_key=None):
    """Return a mock LDAPCollector where all methods return empty lists."""
    c = MagicMock()
    c.get_all_users.return_value = [{"sAMAccountName": "user1"}]
    c.get_kerberoastable_accounts.return_value = []
    c.get_asreproastable_accounts.return_value = []
    c.get_accounts_password_never_expires.return_value = []
    c.get_admincount_accounts.return_value = []
    c.get_all_computers.return_value = []
    c.get_domain_controllers.return_value = []
    c.get_unconstrained_delegation_accounts.return_value = []
    c.get_constrained_delegation_accounts.return_value = []
    c.get_password_policy.return_value = {}
    c.get_gpo_links.return_value = []
    c.get_fine_grained_password_policies.return_value = []
    c.get_domain_info.return_value = {}
    c.get_password_not_required_accounts.return_value = []
    c.get_reversible_encryption_accounts.return_value = []
    c.get_accounts_with_sid_history.return_value = []
    c.get_protected_users_members.return_value = []
    c.get_users_with_description_passwords.return_value = []
    c.get_computers_without_laps.return_value = []
    c.get_krbtgt_account.return_value = None
    c.get_trust_relationships.return_value = []
    c.get_tombstone_lifetime.return_value = None
    c.get_dns_zones.return_value = []
    c.get_des_only_accounts.return_value = []
    c.get_expiring_accounts.return_value = []
    c.get_all_groups.return_value = []
    c.get_privileged_group_members.return_value = {}
    c.get_domain_acl.return_value = []

    if fail_key:
        getattr(c, fail_key).side_effect = Exception("simulated failure")
    return c


SCANNING_CFG = {
    "ldap_threads": "4",
    "expiring_account_days": "30",
    "privileged_groups": "Domain Admins,Enterprise Admins",
}


def test_all_expected_keys_present():
    """All keys that detections depend on must be in the result."""
    collector = _make_mock_collector()
    result = _collect_ad_data(collector, SCANNING_CFG)

    required_keys = [
        "users", "kerberoastable", "asreproastable", "pwd_never_expires",
        "admincount_users", "privileged_members", "computers", "domain_controllers",
        "unconstrained_delegation", "constrained_delegation", "password_policy",
        "gpo_links", "fine_grained_policies", "domain_info", "pwd_not_required",
        "reversible_encryption", "sid_history", "protected_users", "description_passwords",
        "computers_without_laps", "krbtgt", "trusts", "tombstone_lifetime", "dns_zones",
        "des_only_accounts", "expiring_accounts", "all_groups", "domain_acl",
    ]
    for key in required_keys:
        assert key in result, f"Missing key: {key}"


def test_failed_query_does_not_abort():
    """A single failing query returns an empty list, not an exception."""
    collector = _make_mock_collector(fail_key="get_kerberoastable_accounts")
    result = _collect_ad_data(collector, SCANNING_CFG)
    assert result["kerberoastable"] == []
    # All other keys still populated
    assert result["users"] == [{"sAMAccountName": "user1"}]


def test_users_result_is_correct():
    """get_all_users result is passed through unchanged."""
    collector = _make_mock_collector()
    collector.get_all_users.return_value = [{"sAMAccountName": "alice"}, {"sAMAccountName": "bob"}]
    result = _collect_ad_data(collector, SCANNING_CFG)
    assert len(result["users"]) == 2
