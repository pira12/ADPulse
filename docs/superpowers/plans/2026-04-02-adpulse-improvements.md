# ADPulse Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add parallel LDAP scanning, four new security detections, and a finding lifecycle/policy system to ADPulse.

**Architecture:** Three independent work streams — (1) parallel scan via `concurrent.futures`, (2) four new detect_* methods added to DetectionEngine, (3) a new `PolicyManager` class with CLI subcommand and report surfacing. All changes stay within the existing module boundaries. Zero new Python packages.

**Tech Stack:** Python 3.12 stdlib only (`concurrent.futures`, `struct`, `json`). Tests use `unittest.mock`. Run with `python -m pytest tests/ -v` from `ADPulse_v1.0/ad_security_engine/`.

> **NOTE — Improvement 2 (Interactive HTML) is already implemented.** The existing `report_generator.py` already has full severity filtering, category filtering, search, new/recurring toggle, dark mode, collapse/expand, copy to clipboard, and permalink support. No work is needed for Improvement 2.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `tests/__init__.py` | Create | Test package marker |
| `tests/fixtures.py` | Create | Shared mock AD data for all tests |
| `tests/test_parallel_scan.py` | Create | Tests for `_collect_ad_data()` |
| `tests/test_detections_new.py` | Create | Tests for 4 new detect_* methods |
| `tests/test_policy_manager.py` | Create | Tests for PolicyManager CRUD + expiry |
| `tests/test_report_policy.py` | Create | Tests for policy badges in HTML output |
| `main.py` | Modify | Extract `_collect_ad_data()`, parallel execution, `--policy` subcommand, apply policy in `run_scan()` |
| `modules/ldap_collector.py` | Modify | Add `get_domain_acl()` and wire `get_all_groups()` |
| `modules/detections.py` | Modify | Add 4 new `detect_*` methods + calls in `run_all_detections()` |
| `modules/policy_manager.py` | Create | PolicyManager class — load/save/validate/apply policy.json |
| `modules/report_generator.py` | Modify | Policy badge on finding cards, `in_remediation` style, audit trail section |
| `modules/notifier.py` | Modify | Suppression count line in console summary |
| `config.ini.example` | Modify | Add `ldap_threads`, `dormant_admin_days` |

---

## Task 1: Test Infrastructure

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/fixtures.py`

- [ ] **Step 1: Create test package**

```bash
mkdir -p ADPulse_v1.0/ad_security_engine/tests
touch ADPulse_v1.0/ad_security_engine/tests/__init__.py
```

- [ ] **Step 2: Create shared fixtures**

Create `ADPulse_v1.0/ad_security_engine/tests/fixtures.py`:

```python
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
```

- [ ] **Step 3: Verify fixtures import cleanly**

```bash
cd ADPulse_v1.0/ad_security_engine
python -c "from tests.fixtures import make_user, SAMPLE_GROUPS; print('OK')"
```
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/tests/
git commit -m "test: add test infrastructure and shared AD fixtures"
```

---

## Task 2: Parallel Scan

**Files:**
- Modify: `main.py`
- Modify: `config.ini.example`
- Create: `tests/test_parallel_scan.py`

The key change: extract the sequential `ad_data = {...}` dict-build inside `run_scan()` into a standalone `_collect_ad_data(collector, scanning_cfg)` function that uses `ThreadPoolExecutor`. This makes it independently testable.

- [ ] **Step 1: Write the failing test**

Create `ADPulse_v1.0/ad_security_engine/tests/test_parallel_scan.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_parallel_scan.py -v
```
Expected: `ImportError: cannot import name '_collect_ad_data' from 'main'`

- [ ] **Step 3: Implement `_collect_ad_data()` in main.py**

Add this import at the top of `main.py` (after existing imports):
```python
from concurrent.futures import ThreadPoolExecutor, as_completed
```

Add this function to `main.py` just before `run_scan()`:

```python
# Default empty results for each key (used when a query fails or returns None)
_AD_DATA_DEFAULTS = {
    "users": [], "kerberoastable": [], "asreproastable": [], "pwd_never_expires": [],
    "admincount_users": [], "privileged_members": {}, "computers": [],
    "domain_controllers": [], "unconstrained_delegation": [], "constrained_delegation": [],
    "password_policy": None, "gpo_links": [], "fine_grained_policies": [],
    "domain_info": {}, "pwd_not_required": [], "reversible_encryption": [],
    "sid_history": [], "protected_users": [], "description_passwords": [],
    "computers_without_laps": [], "krbtgt": None, "trusts": [],
    "tombstone_lifetime": None, "dns_zones": [], "des_only_accounts": [],
    "expiring_accounts": [], "all_groups": [], "domain_acl": [],
}


def _collect_ad_data(collector, scanning_cfg: dict) -> dict:
    """
    Run all AD LDAP queries. Independent queries run in parallel via ThreadPoolExecutor.
    A failed query logs a warning and returns an empty result for that key — it never
    aborts the scan.
    """
    expiring_days = int(scanning_cfg.get("expiring_account_days", 30))
    privileged_groups = [
        g.strip() for g in scanning_cfg.get(
            "privileged_groups",
            "Domain Admins,Enterprise Admins,Schema Admins,Administrators"
        ).split(",")
    ]
    max_workers = int(scanning_cfg.get("ldap_threads", 8))

    # All queries are independent — run them all in parallel
    tasks = {
        "users":                    lambda: collector.get_all_users(),
        "kerberoastable":           lambda: collector.get_kerberoastable_accounts(),
        "asreproastable":           lambda: collector.get_asreproastable_accounts(),
        "pwd_never_expires":        lambda: collector.get_accounts_password_never_expires(),
        "admincount_users":         lambda: collector.get_admincount_accounts(),
        "privileged_members":       lambda: collector.get_privileged_group_members(privileged_groups),
        "computers":                lambda: collector.get_all_computers(),
        "domain_controllers":       lambda: collector.get_domain_controllers(),
        "unconstrained_delegation": lambda: collector.get_unconstrained_delegation_accounts(),
        "constrained_delegation":   lambda: collector.get_constrained_delegation_accounts(),
        "password_policy":          lambda: collector.get_password_policy(),
        "gpo_links":                lambda: collector.get_gpo_links(),
        "fine_grained_policies":    lambda: collector.get_fine_grained_password_policies(),
        "domain_info":              lambda: collector.get_domain_info(),
        "pwd_not_required":         lambda: collector.get_password_not_required_accounts(),
        "reversible_encryption":    lambda: collector.get_reversible_encryption_accounts(),
        "sid_history":              lambda: collector.get_accounts_with_sid_history(),
        "protected_users":          lambda: collector.get_protected_users_members(),
        "description_passwords":    lambda: collector.get_users_with_description_passwords(),
        "computers_without_laps":   lambda: collector.get_computers_without_laps(),
        "krbtgt":                   lambda: collector.get_krbtgt_account(),
        "trusts":                   lambda: collector.get_trust_relationships(),
        "tombstone_lifetime":       lambda: collector.get_tombstone_lifetime(),
        "dns_zones":                lambda: collector.get_dns_zones(),
        "des_only_accounts":        lambda: collector.get_des_only_accounts(),
        "expiring_accounts":        lambda: collector.get_expiring_accounts(days_ahead=expiring_days),
        "all_groups":               lambda: collector.get_all_groups(),
        "domain_acl":               lambda: collector.get_domain_acl(),
    }

    results = dict(_AD_DATA_DEFAULTS)  # start with safe defaults

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_key = {executor.submit(fn): key for key, fn in tasks.items()}
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                logger.warning(f"LDAP query '{key}' failed: {exc}. Using empty result.")

    return results
```

- [ ] **Step 4: Replace the sequential `ad_data = {...}` block in `run_scan()`**

In `run_scan()`, find the block starting with:
```python
            ad_data = {
                "users":                 collector.get_all_users(),
```
and ending with the closing `}` after `"_domain_label": domain_label`. Replace that entire `ad_data = {…}` assignment with:

```python
            ad_data = _collect_ad_data(collector, scanning_cfg)
            ad_data["_domain_label"] = domain_label
```

Also remove the now-unused `privileged_groups` list that was previously computed just before the domain loop (it's now computed inside `_collect_ad_data`).

Also remove this block that previously extracted the logger line:
```python
            logger.info(
                f"  → Users: {len(ad_data['users'])} | "
                ...
            )
```
Replace with:
```python
            logger.info(
                f"  → Users: {len(ad_data.get('users', []))} | "
                f"Computers: {len(ad_data.get('computers', []))} | "
                f"DCs: {len(ad_data.get('domain_controllers', []))} | "
                f"Kerberoastable: {len(ad_data.get('kerberoastable', []))} | "
                f"AS-REP: {len(ad_data.get('asreproastable', []))}"
            )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_parallel_scan.py -v
```
Expected: 3 tests PASS

- [ ] **Step 6: Add config keys to config.ini.example**

Find the `[scanning]` section in `config.ini.example` and add after `scan_interval_hours`:
```ini
# Maximum number of parallel LDAP queries during a scan (default: 8)
ldap_threads = 8

# Days since last logon before a privileged account is flagged as dormant
dormant_admin_days = 90
```

- [ ] **Step 7: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/main.py \
        ADPulse_v1.0/ad_security_engine/config.ini.example \
        ADPulse_v1.0/ad_security_engine/tests/test_parallel_scan.py
git commit -m "feat: parallelize LDAP data collection with ThreadPoolExecutor"
```

---

## Task 3: New LDAP Methods — get_domain_acl() and get_all_groups() wiring

**Files:**
- Modify: `modules/ldap_collector.py`

`get_all_groups()` already exists in `ldap_collector.py` — it just needs no changes since `_collect_ad_data()` now calls it. `get_domain_acl()` is new.

- [ ] **Step 1: Add module-level helpers for binary security descriptor parsing**

At the top of `modules/ldap_collector.py`, after existing imports, add:

```python
import struct

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
```

- [ ] **Step 2: Add `get_domain_acl()` method to LDAPCollector**

Inside the `LDAPCollector` class in `modules/ldap_collector.py`, after `get_dns_zones()`, add:

```python
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
```

- [ ] **Step 3: Verify the module imports cleanly**

```bash
cd ADPulse_v1.0/ad_security_engine
python -c "from modules.ldap_collector import LDAPCollector, _parse_dacl_for_dcsync; print('OK')"
```
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/ldap_collector.py
git commit -m "feat: add get_domain_acl() with binary security descriptor parsing for DCSync"
```

---

## Task 4: Detection — DCSync Rights

**Files:**
- Modify: `modules/detections.py`
- Create: `tests/test_detections_new.py`

- [ ] **Step 1: Write the failing test**

Create `ADPulse_v1.0/ad_security_engine/tests/test_detections_new.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py::test_dcsync_flags_non_dc_account -v
```
Expected: `AttributeError: 'DetectionEngine' object has no attribute 'detect_dcsync_rights'`

- [ ] **Step 3: Implement `detect_dcsync_rights()` in detections.py**

Inside the `DetectionEngine` class in `modules/detections.py`, after `detect_fgpp_coverage_gaps()`, add:

```python
    # ------------------------------------------------------------------ #
    #  New Detections — Improvement 3                                      #
    # ------------------------------------------------------------------ #

    def detect_dcsync_rights(self, domain_acl: list, domain_controllers: list) -> list:
        """
        ACL-001-DCSYNC: Non-DC accounts with DCSync replication rights.
        Any account with DS-Replication-Get-Changes-All can dump all AD hashes.
        """
        dc_names = {
            str(dc.get("sAMAccountName", "")).lower().rstrip("$")
            for dc in domain_controllers
        }
        flagged = [
            entry["sam_account_name"]
            for entry in domain_acl
            if entry.get("sam_account_name", "").lower().rstrip("$") not in dc_names
            and entry.get("sam_account_name")
        ]
        if not flagged:
            return []
        return [{
            "finding_id":   "ACL-001-DCSYNC",
            "category":     "Privileged Access",
            "severity":     "CRITICAL",
            "title":        f"{len(flagged)} Account(s) Have DCSync Rights",
            "description": (
                "The following non-DC accounts have DS-Replication-Get-Changes-All "
                "permission on the domain root. This grants the ability to perform a "
                "DCSync attack — extracting all password hashes from AD without "
                "logging on to a Domain Controller."
            ),
            "affected":     flagged,
            "details":      {"count": len(flagged)},
            "remediation": (
                "1. Remove DCSync rights from all non-DC accounts.\n"
                "2. In ADUC: right-click domain root → Properties → Security → "
                "   find the account → remove 'Replicating Directory Changes All'.\n"
                "3. Investigate how this permission was granted and whether a DCSync "
                "   attack has already occurred (check logs for mimikatz indicators)."
            ),
        }]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "dcsync" -v
```
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/detections.py \
        ADPulse_v1.0/ad_security_engine/tests/test_detections_new.py
git commit -m "feat: add DCSync rights detection (ACL-001-DCSYNC, CRITICAL)"
```

---

## Task 5: Detection — Dormant Privileged Accounts

**Files:**
- Modify: `modules/detections.py`
- Modify: `tests/test_detections_new.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_detections_new.py`:

```python
# ── Dormant Privileged Accounts ──────────────────────────────────────────────

def test_dormant_admin_flagged():
    """A privileged account inactive for >90 days should be flagged."""
    now = datetime.now(tz=timezone.utc)
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "dormant" -v
```
Expected: `AttributeError: 'DetectionEngine' object has no attribute 'detect_dormant_privileged_accounts'`

- [ ] **Step 3: Implement `detect_dormant_privileged_accounts()` in detections.py**

`DetectionEngine.__init__` already reads `stale_account_days`. Add `dormant_admin_days` to `__init__`:

In `DetectionEngine.__init__`, after the `self.privileged_groups = ...` line, add:
```python
        self.dormant_admin_days = int(config.get("dormant_admin_days", 90))
```

Then inside the class after `detect_dcsync_rights()`, add:

```python
    def detect_dormant_privileged_accounts(self, users: list, privileged_members: dict) -> list:
        """
        PRIV-001-DORMANT-ADMIN: Enabled privileged accounts inactive for
        more than dormant_admin_days days. An unused admin account is a
        free credential for an attacker who finds the password.
        """
        # Build a set of sAMAccountNames that appear in any privileged group
        priv_accounts = set()
        for members in privileged_members.values():
            for dn in members:
                # Extract CN from DN: "CN=admin1,OU=..." → "admin1"
                cn = dn.split(",")[0].replace("CN=", "").replace("cn=", "").strip().lower()
                priv_accounts.add(cn)

        dormant = []
        for u in users:
            sam = _account_name(u).lower()
            if sam not in priv_accounts:
                continue
            uac = u.get("userAccountControl") or 0
            try:
                uac = int(uac)
            except (TypeError, ValueError):
                uac = 0
            if uac & UAC_DISABLED:
                continue  # disabled accounts are not a login risk

            days = _days_since(_to_datetime(u.get("lastLogonTimestamp")))
            if days is not None and days > self.dormant_admin_days:
                dormant.append(f"{_account_name(u)} ({days}d ago)")

        if not dormant:
            return []
        return [{
            "finding_id":   "PRIV-001-DORMANT-ADMIN",
            "category":     "Privileged Access",
            "severity":     "HIGH",
            "title":        f"{len(dormant)} Dormant Privileged Account(s)",
            "description": (
                f"{len(dormant)} enabled account(s) in privileged groups have not "
                f"authenticated in more than {self.dormant_admin_days} days. "
                "Unused admin accounts are high-value targets — if credentials are "
                "compromised the account can be used without triggering normal activity alerts."
            ),
            "affected":     dormant,
            "details":      {"count": len(dormant), "threshold_days": self.dormant_admin_days},
            "remediation": (
                "1. Confirm with the account owner whether the account is still needed.\n"
                "2. Disable accounts no longer required: Disable-ADAccount.\n"
                "3. If the account is legitimately unused, consider removing its group memberships "
                "   and re-adding when needed (just-in-time access).\n"
                f"4. Adjust dormant_admin_days in config.ini if the {self.dormant_admin_days}-day "
                "   threshold does not match your environment."
            ),
        }]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "dormant" -v
```
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/detections.py \
        ADPulse_v1.0/ad_security_engine/tests/test_detections_new.py
git commit -m "feat: add dormant privileged accounts detection (PRIV-001-DORMANT-ADMIN, HIGH)"
```

---

## Task 6: Detection — Nested Group Privilege Expansion

**Files:**
- Modify: `modules/detections.py`
- Modify: `tests/test_detections_new.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_detections_new.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "nested" -v
```
Expected: `AttributeError: 'DetectionEngine' object has no attribute 'detect_nested_privilege'`

- [ ] **Step 3: Implement `detect_nested_privilege()` in detections.py**

Add after `detect_dormant_privileged_accounts()`:

```python
    def detect_nested_privilege(self, all_groups: list, privileged_members: dict) -> list:
        """
        PRIV-002-NESTED-PRIV: Accounts reaching privileged groups through
        2+ levels of group nesting (e.g., jsmith → HelpDesk → Domain Admins).
        Only direct members are tracked in privileged_members — indirect paths are missed.
        """
        if not all_groups:
            return []

        # Build adjacency map: dn → list of member DNs
        dn_to_members: dict[str, list] = {}
        dn_to_sam: dict[str, str] = {}
        for g in all_groups:
            dn = str(g.get("dn") or g.get("distinguishedName") or "")
            members = g.get("member") or []
            if isinstance(members, str):
                members = [members]
            dn_to_members[dn.lower()] = [m.lower() for m in members]
            sam = str(g.get("sAMAccountName") or "")
            if sam:
                dn_to_sam[dn.lower()] = sam

        # Build set of direct privileged member DNs (already known)
        direct_priv_dns: set = set()
        for members in privileged_members.values():
            for dn in members:
                direct_priv_dns.add(dn.lower())

        # For each privileged group, recursively expand membership
        # and collect accounts that are NOT direct members
        def expand(group_dn: str, depth: int, visited: set) -> set:
            """Return all member DNs reachable from group_dn, recursively."""
            if depth > 10 or group_dn in visited:
                return set()
            visited = visited | {group_dn}
            members = dn_to_members.get(group_dn, [])
            result = set(members)
            for m in members:
                if m in dn_to_members:  # m is a group
                    result |= expand(m, depth + 1, visited)
            return result

        priv_group_dns = {
            g["dn"].lower()
            for g in all_groups
            if g.get("sAMAccountName", "") in privileged_members
        }

        nested_findings = []
        for priv_dn in priv_group_dns:
            all_reachable = expand(priv_dn, 0, set())
            priv_sam = dn_to_sam.get(priv_dn, priv_dn)
            direct = set(dn_to_members.get(priv_dn, []))

            # Indirect members = reachable but not direct
            indirect = all_reachable - direct - {priv_dn}
            for dn in indirect:
                # Only flag user accounts (not sub-groups)
                if dn not in dn_to_members:
                    cn = dn.split(",")[0].replace("cn=", "").strip()
                    # Find the path through intermediate group
                    path = f"{cn} → ... → {priv_sam}"
                    nested_findings.append(path)

        if not nested_findings:
            return []
        return [{
            "finding_id":   "PRIV-002-NESTED-PRIV",
            "category":     "Privileged Access",
            "severity":     "MEDIUM",
            "title":        f"{len(nested_findings)} Account(s) Have Indirect Privileged Access",
            "description": (
                f"{len(nested_findings)} account(s) reach privileged groups through 2 or more "
                "levels of group nesting. These accounts have effective privileged access but "
                "do not appear in direct membership checks — they are easy to overlook during "
                "access reviews."
            ),
            "affected":     nested_findings[:50],
            "details":      {"count": len(nested_findings)},
            "remediation": (
                "1. Review each nested membership chain listed above.\n"
                "2. Determine whether the indirect access is intentional.\n"
                "3. Either remove the intermediate group from the privileged group, "
                "   or remove the user from the intermediate group.\n"
                "4. Consider flattening group nesting for privileged groups to make "
                "   access reviews straightforward."
            ),
        }]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "nested" -v
```
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/detections.py \
        ADPulse_v1.0/ad_security_engine/tests/test_detections_new.py
git commit -m "feat: add nested group privilege expansion detection (PRIV-002-NESTED-PRIV, MEDIUM)"
```

---

## Task 7: Detection — Service Accounts in Privileged Groups

**Files:**
- Modify: `modules/detections.py`
- Modify: `tests/test_detections_new.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_detections_new.py`:

```python
# ── Service Accounts in Privileged Groups ───────────────────────────────────

def test_privileged_spn_flagged():
    """A kerberoastable account that is also in a privileged group → CRITICAL."""
    # svc-sql is kerberoastable (has SPN)
    # admin1 is in Domain Admins — but svc-sql might be too
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "privileged_spn" -v
```
Expected: `AttributeError: 'DetectionEngine' object has no attribute 'detect_privileged_spn'`

- [ ] **Step 3: Implement `detect_privileged_spn()` in detections.py**

Add after `detect_nested_privilege()`:

```python
    def detect_privileged_spn(self, kerberoastable: list, privileged_members: dict) -> list:
        """
        KERB-003-PRIVESC-SPN: Kerberoastable accounts that are also members
        of privileged groups. An attacker who cracks the service account hash
        gets immediate privileged access — no lateral movement required.
        """
        if not kerberoastable or not privileged_members:
            return []

        # Build set of privileged member DNs (lowercase)
        priv_dns: set = set()
        for members in privileged_members.values():
            for dn in members:
                priv_dns.add(dn.lower())

        flagged = []
        for acct in kerberoastable:
            dn = str(acct.get("dn") or acct.get("distinguishedName") or "").lower()
            if dn in priv_dns:
                sam = _account_name(acct)
                spns = acct.get("servicePrincipalName") or []
                if isinstance(spns, str):
                    spns = [spns]
                flagged.append(f"{sam} (SPNs: {', '.join(spns[:3])})")

        if not flagged:
            return []
        return [{
            "finding_id":   "KERB-003-PRIVESC-SPN",
            "category":     "Kerberos",
            "severity":     "CRITICAL",
            "title":        f"{len(flagged)} Privileged Kerberoastable Account(s)",
            "description": (
                f"{len(flagged)} account(s) with Service Principal Names (SPNs) are also members "
                "of privileged groups. Any domain user can request a Kerberos service ticket for "
                "these accounts and attempt offline password cracking. A cracked hash yields "
                "immediate privileged access — no further exploitation required."
            ),
            "affected":     flagged,
            "details":      {"count": len(flagged)},
            "remediation": (
                "1. Remove service accounts from privileged groups — service accounts "
                "   should never be administrators.\n"
                "2. If admin rights are genuinely required, use a Group Managed Service Account "
                "   (gMSA) — these have auto-rotating 120+ character passwords.\n"
                "3. As an interim measure, set a long random password (25+ chars) on the account.\n"
                "4. Enable 'Require Kerberos AES encryption' on the account to prevent "
                "   RC4-based Kerberoasting while you remediate."
            ),
        }]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -k "privileged_spn" -v
```
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/detections.py \
        ADPulse_v1.0/ad_security_engine/tests/test_detections_new.py
git commit -m "feat: add privileged service account detection (KERB-003-PRIVESC-SPN, CRITICAL)"
```

---

## Task 8: Wire New Detections into run_all_detections()

**Files:**
- Modify: `modules/detections.py`

- [ ] **Step 1: Add the four new calls to `run_all_detections()`**

In `modules/detections.py`, find the block:
```python
        # Delta-based detections (require a baseline)
        if baseline and previous_run_id:
```

Insert before it:
```python
        # New detections — Improvement 3
        findings += self.detect_dcsync_rights(
            ad_data.get("domain_acl", []),
            ad_data.get("domain_controllers", []),
        )
        findings += self.detect_dormant_privileged_accounts(
            ad_data.get("users", []),
            ad_data.get("privileged_members", {}),
        )
        findings += self.detect_nested_privilege(
            ad_data.get("all_groups", []),
            ad_data.get("privileged_members", {}),
        )
        findings += self.detect_privileged_spn(
            ad_data.get("kerberoastable", []),
            ad_data.get("privileged_members", {}),
        )
```

Also update the docstring at the top of `run_all_detections()` to add the new keys:
```python
        ad_data keys expected:
          ...existing keys...
          domain_acl, all_groups  (new in Improvement 3)
```

- [ ] **Step 2: Run the full detection test suite**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_detections_new.py -v
```
Expected: all tests PASS

- [ ] **Step 3: Verify run_all_detections handles missing new keys gracefully**

```bash
cd ADPulse_v1.0/ad_security_engine
python -c "
from modules.detections import DetectionEngine
e = DetectionEngine({'stale_account_days':'60','password_age_days':'365','privileged_groups':'Domain Admins'})
# Pass ad_data with no domain_acl or all_groups keys — should not raise
result = e.run_all_detections({'users':[], 'kerberoastable':[], 'asreproastable':[], 'pwd_never_expires':[], 'admincount_users':[], 'privileged_members':{}, 'computers':[], 'domain_controllers':[], 'unconstrained_delegation':[], 'constrained_delegation':[], 'password_policy':None, 'gpo_links':[], 'fine_grained_policies':[], 'pwd_not_required':[], 'reversible_encryption':[], 'sid_history':[], 'description_passwords':[], 'protected_users':[], 'computers_without_laps':[], 'krbtgt':None, 'trusts':[], 'tombstone_lifetime':None, 'dns_zones':[], 'des_only_accounts':[], 'expiring_accounts':[], 'domain_info':None}, baseline=None)
print('OK:', len(result), 'findings')
"
```
Expected: `OK: 0 findings`

- [ ] **Step 4: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/detections.py
git commit -m "feat: wire new detections into run_all_detections()"
```

---

## Task 9: Policy Manager — Core

**Files:**
- Create: `modules/policy_manager.py`
- Create: `tests/test_policy_manager.py`

- [ ] **Step 1: Write the failing tests**

Create `ADPulse_v1.0/ad_security_engine/tests/test_policy_manager.py`:

```python
"""Tests for PolicyManager CRUD, expiry, and finding application."""
import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import date, timedelta
from modules.policy_manager import PolicyManager


def _pm(tmp_path=None):
    """Create a PolicyManager backed by a temp file."""
    if tmp_path is None:
        tmp_path = tempfile.mktemp(suffix=".json")
    return PolicyManager(tmp_path), tmp_path


def test_set_and_get():
    pm, _ = _pm()
    pm.set_status("KERB-001", "accepted_risk", "Legacy app", "alice", "2030-01-01")
    entry = pm.get("KERB-001")
    assert entry["status"] == "accepted_risk"
    assert entry["reason"] == "Legacy app"
    assert entry["set_by"] == "alice"
    assert entry["expires"] == "2030-01-01"


def test_persists_to_disk():
    _, path = _pm()
    pm1 = PolicyManager(path)
    pm1.set_status("ACL-001", "in_remediation", "Ticket open", "bob")
    # Create a new instance from same path
    pm2 = PolicyManager(path)
    assert pm2.get("ACL-001")["status"] == "in_remediation"


def test_clear_removes_entry():
    pm, _ = _pm()
    pm.set_status("FOO-001", "resolved", "Fixed")
    pm.clear("FOO-001")
    assert pm.get("FOO-001") is None


def test_clear_missing_key_is_safe():
    pm, _ = _pm()
    pm.clear("NONEXISTENT")  # should not raise


def test_invalid_status_raises():
    pm, _ = _pm()
    try:
        pm.set_status("X-001", "invalid_state", "reason")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_expiry_removes_expired_entries():
    pm, _ = _pm()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    pm.set_status("OLD-001", "accepted_risk", "Expired", expires=yesterday)
    pm.set_status("NEW-001", "accepted_risk", "Not expired", expires="2099-01-01")

    expired = pm.check_expiry()
    assert "OLD-001" in expired
    assert pm.get("OLD-001") is None   # removed
    assert pm.get("NEW-001") is not None  # still there


def test_resolved_reappearance_clears_entry():
    pm, _ = _pm()
    pm.set_status("KERB-001", "resolved", "Fixed last week")
    cleared = pm.handle_resolved_reappearance({"KERB-001", "OTHER-001"})
    assert "KERB-001" in cleared
    assert pm.get("KERB-001") is None


def test_apply_to_findings_splits_correctly():
    pm, _ = _pm()
    pm.set_status("KERB-001", "accepted_risk", "Known")
    pm.set_status("ACCT-001", "in_remediation", "In progress")
    pm.set_status("COMP-001", "resolved", "Fixed")

    findings = [
        {"finding_id": "KERB-001", "severity": "HIGH", "title": "Kerberoastable"},
        {"finding_id": "ACCT-001", "severity": "MEDIUM", "title": "Stale account"},
        {"finding_id": "COMP-001", "severity": "LOW", "title": "Stale computer"},
        {"finding_id": "NEW-001",  "severity": "CRITICAL", "title": "New finding"},
    ]
    active, suppressed = pm.apply_to_findings(findings)

    # accepted_risk and resolved are suppressed
    suppressed_ids = {f["finding_id"] for f in suppressed}
    assert "KERB-001" in suppressed_ids
    assert "COMP-001" in suppressed_ids

    # in_remediation stays active but gets policy_status field
    active_ids = {f["finding_id"] for f in active}
    assert "ACCT-001" in active_ids
    assert "NEW-001" in active_ids

    acct = next(f for f in active if f["finding_id"] == "ACCT-001")
    assert acct["policy_status"] == "in_remediation"
    assert acct["policy_reason"] == "In progress"

    # Unaffected finding has no policy fields
    new = next(f for f in active if f["finding_id"] == "NEW-001")
    assert "policy_status" not in new


def test_list_all_includes_all_entries():
    pm, _ = _pm()
    pm.set_status("A-001", "accepted_risk", "reason a")
    pm.set_status("B-001", "in_remediation", "reason b")
    entries = pm.list_all()
    ids = {e["finding_id"] for e in entries}
    assert "A-001" in ids
    assert "B-001" in ids
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_policy_manager.py -v
```
Expected: `ModuleNotFoundError: No module named 'modules.policy_manager'`

- [ ] **Step 3: Implement `modules/policy_manager.py`**

Create `ADPulse_v1.0/ad_security_engine/modules/policy_manager.py`:

```python
"""
policy_manager.py
-----------------
Manages the finding lifecycle policy stored in policy.json.

Analysts record decisions about specific findings (accepted_risk,
in_remediation, resolved). Policy is applied after findings are assembled
and before reports are generated.
"""

import json
import logging
from datetime import date
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

VALID_STATUSES = {"accepted_risk", "in_remediation", "resolved"}


class PolicyManager:
    """
    Load, save, and apply finding policy from a JSON file.

    File format:
    {
      "KERB-001-STANDARD": {
        "status":   "accepted_risk",
        "reason":   "Legacy service, migration planned Q3",
        "set_by":   "jsmith",
        "set_on":   "2026-03-01",
        "expires":  "2026-09-01"   # or null
      }
    }
    """

    def __init__(self, policy_path: str):
        self.path = Path(policy_path)
        self._policy: dict = self._load()

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not load policy.json: {e}. Starting with empty policy.")
            return {}

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._policy, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save policy.json: {e}")

    # ------------------------------------------------------------------ #
    #  CRUD                                                                #
    # ------------------------------------------------------------------ #

    def get(self, finding_id: str) -> Optional[dict]:
        """Return the policy entry for a finding ID, or None."""
        return self._policy.get(finding_id)

    def set_status(self, finding_id: str, status: str, reason: str,
                   set_by: str = "", expires: Optional[str] = None):
        """Create or replace a policy entry. Raises ValueError for invalid status."""
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}"
            )
        self._policy[finding_id] = {
            "status":  status,
            "reason":  reason,
            "set_by":  set_by,
            "set_on":  date.today().isoformat(),
            "expires": expires,
        }
        self._save()

    def clear(self, finding_id: str):
        """Remove a policy entry. Safe to call even if the ID is not present."""
        if finding_id in self._policy:
            del self._policy[finding_id]
            self._save()

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def check_expiry(self) -> list:
        """
        Remove policy entries whose expiry date has passed.
        Returns list of finding IDs that were removed.
        Logs a warning for each.
        """
        today = date.today().isoformat()
        expired = [
            fid for fid, entry in self._policy.items()
            if entry.get("expires") and entry["expires"] < today
        ]
        for fid in expired:
            logger.warning(
                f"Policy entry for {fid} has expired ({self._policy[fid]['expires']}) "
                "and has been removed. Finding reactivated."
            )
            del self._policy[fid]
        if expired:
            self._save()
        return expired

    def handle_resolved_reappearance(self, current_finding_ids: set) -> list:
        """
        If a finding marked 'resolved' reappears in the current scan, clear
        its policy entry and return its ID. Logs a warning for each.
        """
        cleared = [
            fid for fid, entry in self._policy.items()
            if entry.get("status") == "resolved" and fid in current_finding_ids
        ]
        for fid in cleared:
            logger.warning(
                f"Finding {fid} was marked resolved but has reappeared. "
                "Policy entry cleared — please re-triage."
            )
            del self._policy[fid]
        if cleared:
            self._save()
        return cleared

    def apply_to_findings(self, findings: list) -> tuple:
        """
        Apply policy to a findings list.

        Returns (active_findings, suppressed_findings):
          - active_findings: findings visible in reports.
            'in_remediation' findings have policy_status/policy_reason fields added.
          - suppressed_findings: 'accepted_risk' and 'resolved' findings,
            excluded from the main report body but listed in the audit trail.
        """
        active = []
        suppressed = []
        for f in findings:
            fid = f["finding_id"]
            entry = self._policy.get(fid)
            if entry:
                f = dict(f)  # copy — do not mutate the original
                f["policy_status"] = entry["status"]
                f["policy_reason"] = entry.get("reason", "")
                f["policy_expires"] = entry.get("expires")
                f["policy_set_by"] = entry.get("set_by", "")
                if entry["status"] in ("accepted_risk", "resolved"):
                    suppressed.append(f)
                else:
                    active.append(f)  # in_remediation stays visible
            else:
                active.append(f)
        return active, suppressed

    # ------------------------------------------------------------------ #
    #  Listing                                                             #
    # ------------------------------------------------------------------ #

    def list_all(self) -> list:
        """Return all policy entries as a list of dicts, sorted by finding_id."""
        today = date.today().isoformat()
        result = []
        for fid, entry in self._policy.items():
            item = dict(entry)
            item["finding_id"] = fid
            item["expired"] = bool(entry.get("expires") and entry["expires"] < today)
            result.append(item)
        return sorted(result, key=lambda x: x["finding_id"])
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_policy_manager.py -v
```
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/policy_manager.py \
        ADPulse_v1.0/ad_security_engine/tests/test_policy_manager.py
git commit -m "feat: add PolicyManager with CRUD, expiry, and finding lifecycle"
```

---

## Task 10: Policy CLI Subcommand and run_scan() Integration

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add `--policy` args to argument parser in `main()`**

In `main.py`, inside the `main()` function, add after the existing `parser.add_argument("--diff", ...)`:

```python
    parser.add_argument(
        "--policy", nargs="+", metavar=("ACTION", "FINDING_ID"),
        help=(
            "Manage finding policy. Actions:\n"
            "  list                             List all policy entries\n"
            "  accept  <FINDING_ID> --reason    Mark as accepted risk\n"
            "  remediate <FINDING_ID> --reason  Mark as in remediation\n"
            "  resolve <FINDING_ID>             Mark as resolved\n"
            "  clear   <FINDING_ID>             Remove policy entry"
        ),
    )
    parser.add_argument("--reason", default="", help="Reason for policy decision")
    parser.add_argument(
        "--expires", default=None,
        help="Expiry date for accepted_risk entries (YYYY-MM-DD)"
    )
```

- [ ] **Step 2: Add `cmd_policy()` function to main.py**

Add this function just before `main()`:

```python
def cmd_policy(cfg: configparser.ConfigParser, config_path: str,
               action: str, finding_id: str, reason: str, expires: str):
    """Handle --policy subcommands."""
    import os
    from modules.policy_manager import PolicyManager

    policy_path = str(Path(config_path).parent / "policy.json")
    pm = PolicyManager(policy_path)

    if action == "list":
        entries = pm.list_all()
        if not entries:
            print("\n  No policy entries.\n")
            return
        print(f"\n  {'Finding ID':<32} {'Status':<16} {'Set By':<12} {'Expires':<12} Reason")
        print("  " + "-" * 90)
        for e in entries:
            exp = e.get("expires") or "none"
            expired_tag = " [EXPIRED]" if e.get("expired") else ""
            print(f"  {e['finding_id']:<32} {e['status']:<16} {e.get('set_by',''):<12} "
                  f"{exp:<12} {e.get('reason','')}{expired_tag}")
        print()
        return

    if not finding_id:
        print(f"ERROR: '--policy {action}' requires a finding ID.")
        print(f"  Example: python main.py --policy {action} KERB-001-STANDARD --reason \"...\"")
        sys.exit(1)

    # Validate finding_id against last scan
    db_path = cfg["database"].get("db_path", "./ad_baseline.db")
    from modules.baseline_engine import BaselineEngine
    baseline = BaselineEngine(db_path)
    last_run = baseline.get_last_successful_run_id()
    if last_run:
        known_ids = {f["finding_id"] for f in baseline.get_findings_for_run(last_run)}
        existing_ids = {e["finding_id"] for e in pm.list_all()}
        all_known = known_ids | existing_ids
        if finding_id not in all_known:
            print(f"ERROR: Finding ID '{finding_id}' not found in last scan or policy file.")
            print("  Run 'python main.py --policy list' to see existing entries.")
            print("  Run 'python main.py --report-only' to see current findings.")
            sys.exit(1)

    set_by = os.environ.get("USERNAME", os.environ.get("USER", ""))

    if action == "accept":
        if not reason:
            print("ERROR: --reason is required for 'accept'.")
            sys.exit(1)
        pm.set_status(finding_id, "accepted_risk", reason, set_by, expires or None)
        msg = f"  [OK] {finding_id} → accepted_risk"
        if expires:
            msg += f" (expires {expires})"
        print(msg)

    elif action == "remediate":
        if not reason:
            print("ERROR: --reason is required for 'remediate'.")
            sys.exit(1)
        pm.set_status(finding_id, "in_remediation", reason, set_by, None)
        print(f"  [OK] {finding_id} → in_remediation")

    elif action == "resolve":
        pm.set_status(finding_id, "resolved", reason or "Manually resolved", set_by, None)
        print(f"  [OK] {finding_id} → resolved")

    elif action == "clear":
        pm.clear(finding_id)
        print(f"  [OK] Policy entry for {finding_id} removed.")

    else:
        print(f"ERROR: Unknown action '{action}'. Valid: list, accept, remediate, resolve, clear")
        sys.exit(1)
```

- [ ] **Step 3: Wire `--policy` dispatch in `main()`**

In `main()`, inside the `if args.test_connection:` block chain, add at the top (before `if args.test_connection:`):

```python
    if args.policy:
        action    = args.policy[0]
        finding_id = args.policy[1] if len(args.policy) > 1 else ""
        cmd_policy(cfg, args.config, action, finding_id, args.reason, args.expires)
        return
```

- [ ] **Step 4: Apply policy inside `run_scan()`**

In `run_scan()`, locate the line:
```python
    findings = baseline.get_findings_for_run(run_id)
```

After it, add:

```python
        # Apply policy (accepted_risk → suppressed, in_remediation → badge, resolved → audit trail)
        from modules.policy_manager import PolicyManager
        policy_path = cfg.get("policy", "policy_path", fallback="./policy.json")
        pm = PolicyManager(policy_path)

        expired = pm.check_expiry()
        current_ids = {f["finding_id"] for f in findings}
        reappeared = pm.handle_resolved_reappearance(current_ids)
        for fid in reappeared:
            logger.warning(f"Finding {fid} was marked resolved but has reappeared.")

        findings, suppressed_findings = pm.apply_to_findings(findings)

        if suppressed_findings:
            logger.info(
                f"  → Policy: {len(suppressed_findings)} finding(s) suppressed "
                f"(accepted_risk/resolved)."
            )
```

Then pass `suppressed_findings` to the reporter and notifier. Update the reporter call:
```python
        report_paths = reporter.generate_all(
            findings=findings,
            run_id=run_id,
            domain_info=primary.get("domain_info"),
            baseline=baseline,
            suppressed=suppressed_findings,
        )
```

Update the notifier call:
```python
        notifier.notify(
            findings=findings,
            run_id=run_id,
            report_paths=report_paths,
            domain_info=primary.get("domain_info"),
            suppressed_count=len(suppressed_findings),
        )
```

Update the return dict to include suppressed count:
```python
        return {
            "success":           True,
            "run_id":            run_id,
            "findings":          findings,
            "findings_count":    len(findings),
            "suppressed_count":  len(suppressed_findings),
            "report_paths":      report_paths,
            "elapsed_sec":       elapsed,
            "stats":             counts,
        }
```

Also add `[policy]` fallback section to `config.ini.example` at the end:
```ini
# [policy]
# Path to the finding policy file (default: ./policy.json, relative to config.ini)
# policy_path = ./policy.json
```

- [ ] **Step 5: Verify the policy CLI works end-to-end (smoke test)**

```bash
cd ADPulse_v1.0/ad_security_engine
python main.py --policy list
```
Expected: `No policy entries.` (or a table if a prior scan exists)

- [ ] **Step 6: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/main.py \
        ADPulse_v1.0/ad_security_engine/config.ini.example
git commit -m "feat: add --policy CLI subcommand and apply policy in run_scan()"
```

---

## Task 11: Policy Surfacing in HTML Report

**Files:**
- Modify: `modules/report_generator.py`
- Create: `tests/test_report_policy.py`

- [ ] **Step 1: Write the failing test**

Create `ADPulse_v1.0/ad_security_engine/tests/test_report_policy.py`:

```python
"""Tests for policy badge and audit trail rendering in the HTML report."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import tempfile
from modules.report_generator import HTMLReportGenerator

BASE_FINDING = {
    "finding_id": "KERB-001",
    "category": "Kerberos",
    "severity": "HIGH",
    "title": "Kerberoastable Account",
    "description": "SPN set on account.",
    "affected": ["svc-sql"],
    "details": {},
    "remediation": "Rotate password.",
    "is_new": 1,
    "first_seen": "2026-04-01",
}


def _generate(findings, suppressed=None):
    """Generate HTML and return the string."""
    gen = HTMLReportGenerator()
    tmp = tempfile.mktemp(suffix=".html")
    gen.generate(
        findings=findings,
        run_id="test-run-id",
        output_path=tmp,
        suppressed=suppressed or [],
    )
    with open(tmp, "r", encoding="utf-8") as f:
        return f.read()


def test_in_remediation_badge_shown():
    """A finding with policy_status=in_remediation shows an IN REMEDIATION badge."""
    finding = dict(BASE_FINDING)
    finding["policy_status"] = "in_remediation"
    finding["policy_reason"] = "Ticket #4421 open"
    finding["policy_set_by"] = "jsmith"
    finding["policy_expires"] = None

    html = _generate([finding])
    assert "IN REMEDIATION" in html
    assert "Ticket #4421 open" in html


def test_suppressed_finding_not_in_main_body():
    """An accepted_risk finding should NOT appear in the main findings list."""
    active = dict(BASE_FINDING)
    active["finding_id"] = "ACTIVE-001"

    suppressed = dict(BASE_FINDING)
    suppressed["finding_id"] = "SUPP-001"
    suppressed["title"] = "Suppressed Finding"
    suppressed["policy_status"] = "accepted_risk"
    suppressed["policy_reason"] = "Known risk"
    suppressed["policy_set_by"] = "alice"
    suppressed["policy_expires"] = "2027-01-01"

    html = _generate([active], suppressed=[suppressed])

    # Active finding is present in main body
    assert "ACTIVE-001" in html
    # Suppressed title should appear only in audit trail, not as a finding card id
    assert 'id="SUPP-001"' not in html
    # Audit trail section present
    assert "Policy Audit Trail" in html
    assert "Known risk" in html


def test_no_suppressed_no_audit_trail():
    """When there are no suppressed findings, the audit trail section is omitted."""
    html = _generate([dict(BASE_FINDING)])
    assert "Policy Audit Trail" not in html
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_report_policy.py -v
```
Expected: `TypeError` because `generate()` does not accept `suppressed` parameter yet.

- [ ] **Step 3: Update `HTMLReportGenerator.generate()` signature**

In `modules/report_generator.py`, change:
```python
    def generate(self, findings, run_id, output_path, company_name="Your Organisation",
                 domain_info=None, scan_stats=None):
        html = self._build(findings, run_id, company_name, domain_info)
```
to:
```python
    def generate(self, findings, run_id, output_path, company_name="Your Organisation",
                 domain_info=None, scan_stats=None, suppressed=None):
        html = self._build(findings, run_id, company_name, domain_info,
                           suppressed=suppressed or [])
```

Change `_build()` signature:
```python
    def _build(self, findings, run_id, company_name, domain_info, suppressed=None):
```

- [ ] **Step 4: Add `in_remediation` badge to finding cards in `_build()`**

In `_build()`, find the line:
```python
            new_badge  = '<span class="new-badge">NEW</span>' if is_new else '<span class="rec-badge">RECURRING</span>'
```

After it, add:
```python
            policy_badge = ""
            policy_status = f.get("policy_status", "")
            if policy_status == "in_remediation":
                policy_reason = f.get("policy_reason", "")
                policy_badge = (
                    f'<span class="policy-badge remediation-badge" '
                    f'title="In remediation: {policy_reason}">&#128295; IN REMEDIATION</span>'
                )
```

Then in the finding card HTML, add `{policy_badge}` next to `{new_badge}`:

Find:
```python
                  {new_badge}
                  <span class="finding-title-preview">{f.get('title','')}</span>
```
Change to:
```python
                  {new_badge}
                  {policy_badge}
                  <span class="finding-title-preview">{f.get('title','')}</span>
```

Also add the `in_remediation` reason line inside the finding body, after the title and before the description. Find:
```python
                <h3 class="finding-title">{f.get('title','')}</h3>
                <p class="finding-desc">{f.get('description','')}</p>
```
Change to:
```python
                <h3 class="finding-title">{f.get('title','')}</h3>
                {f'<p class="policy-note"><em>&#128295; In remediation: {f.get("policy_reason","")}'
                 f'{(" &mdash; expires " + f["policy_expires"]) if f.get("policy_expires") else ""}'
                 f'</em></p>' if f.get("policy_status") == "in_remediation" else ''}
                <p class="finding-desc">{f.get('description','')}</p>
```

- [ ] **Step 5: Add audit trail section and CSS for policy badges**

At the end of `_build()`, just before the `return f"""<!DOCTYPE html>...` string, add the audit trail HTML:

```python
        # Build audit trail for suppressed findings
        suppressed = suppressed or []
        audit_trail_html = ""
        if suppressed:
            rows = ""
            for f in suppressed:
                status = f.get("policy_status", "")
                reason = f.get("policy_reason", "")
                exp    = f.get("policy_expires") or "—"
                by     = f.get("policy_set_by") or "—"
                sev    = f.get("severity", "INFO")
                col    = SEVERITY_HEX.get(sev, "#666")
                rows += f"""
                <tr>
                  <td><code style="font-size:11px;">{f.get('finding_id','')}</code></td>
                  <td style="color:{col};font-weight:700;">{sev}</td>
                  <td>{f.get('title','')}</td>
                  <td><span class="policy-status-tag">{status.replace('_',' ').upper()}</span></td>
                  <td>{reason}</td>
                  <td>{by}</td>
                  <td>{exp}</td>
                </tr>"""
            audit_trail_html = f"""
            <div class="section-header" style="margin-top:40px;">
              <h2>Policy Audit Trail</h2>
              <span class="count-badge">{len(suppressed)} suppressed</span>
            </div>
            <div style="background:white;border-radius:10px;padding:20px;
                        box-shadow:0 2px 8px rgba(0,83,164,0.07);overflow-x:auto;margin-bottom:24px;">
              <p style="font-size:13px;color:#8a99b0;margin-bottom:12px;">
                These findings are suppressed by policy. Nothing is hidden from this report —
                all decisions are logged here for audit purposes.
              </p>
              <table style="width:100%;border-collapse:collapse;font-size:12px;">
                <thead>
                  <tr style="background:#f0f4f8;text-transform:uppercase;font-size:10px;
                             letter-spacing:0.5px;color:#8a99b0;">
                    <th style="padding:8px;text-align:left;">Finding ID</th>
                    <th style="padding:8px;text-align:left;">Severity</th>
                    <th style="padding:8px;text-align:left;">Title</th>
                    <th style="padding:8px;text-align:left;">Status</th>
                    <th style="padding:8px;text-align:left;">Reason</th>
                    <th style="padding:8px;text-align:left;">Set By</th>
                    <th style="padding:8px;text-align:left;">Expires</th>
                  </tr>
                </thead>
                <tbody>{rows}</tbody>
              </table>
            </div>"""
```

Add CSS for policy badges by appending to the `css = f"""..."""` string just before its closing `"""`:

```css
/* ── Policy badges ── */
.policy-badge {{
  font-size: 9px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase;
  padding: 3px 8px; border-radius: 20px; white-space: nowrap;
}}
.remediation-badge {{
  background: #e8f4fd; color: #0053A4; border: 1px solid #b3d9f7;
}}
.policy-note {{
  font-size: 12px; color: #0053A4; background: #e8f4fd;
  border-left: 3px solid #0053A4; padding: 6px 10px;
  border-radius: 0 4px 4px 0; margin-bottom: 10px;
}}
.policy-status-tag {{
  font-size: 10px; font-weight: 700; padding: 2px 6px;
  border-radius: 10px; background: #f0f4f8; color: #0053A4;
}}
```

Also add `{audit_trail_html}` to the HTML template, just before the footer:

Find in the template string:
```python
</div>

<div class="footer">
```
Change to:
```python
  {audit_trail_html}
</div>

<div class="footer">
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/test_report_policy.py -v
```
Expected: all 3 tests PASS

- [ ] **Step 7: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/report_generator.py \
        ADPulse_v1.0/ad_security_engine/tests/test_report_policy.py
git commit -m "feat: add policy badges and audit trail section to HTML report"
```

---

## Task 12: Policy Surfacing in PDF and Console

**Files:**
- Modify: `modules/report_generator.py` (PDF section)
- Modify: `modules/notifier.py`

- [ ] **Step 1: Update `ReportManager.generate_all()` to accept and pass `suppressed`**

In `modules/report_generator.py`, find the `ReportManager` class (near the bottom). Update `generate_all()` signature:

```python
    def generate_all(self, findings, run_id, domain_info=None, baseline=None, suppressed=None):
```

Pass `suppressed` to the HTML generator call inside `generate_all()`:
```python
        if self.gen_html:
            path = self._html.generate(
                findings, run_id,
                str(self.output_dir / f"ADPulse_Report_{ts}.html"),
                self.company_name, domain_info,
                suppressed=suppressed or [],
            )
            paths["html"] = path
```

- [ ] **Step 2: Add policy status line to PDF findings**

In `modules/report_generator.py`, inside the `PDFReportGenerator` class, find where individual findings are rendered into PDF flowables (look for where `f.get("title")` or `f.get("description")` is used in the PDF section, typically after `for f in findings:`).

After the finding title paragraph is built, add a policy note paragraph for `in_remediation` findings:

```python
                # Policy status note (in_remediation only)
                if f.get("policy_status") == "in_remediation":
                    pol_style = ParagraphStyle(
                        "PolicyNote",
                        parent=styles["Normal"],
                        fontSize=8,
                        textColor=colors.HexColor("#0053A4"),
                        leftIndent=6,
                        backColor=colors.HexColor("#e8f4fd"),
                        borderPad=4,
                        spaceAfter=4,
                    )
                    policy_reason = f.get("policy_reason", "")
                    policy_expires = f.get("policy_expires", "")
                    exp_str = f" — expires {policy_expires}" if policy_expires else ""
                    story.append(Paragraph(
                        f"&#128295; In remediation: {policy_reason}{exp_str}",
                        pol_style,
                    ))
```

- [ ] **Step 3: Update `OutputNotifier.notify()` to accept `suppressed_count`**

In `modules/notifier.py`, change `notify()` signature from:
```python
    def notify(self, findings: list, run_id: str, report_paths: dict, domain_info: dict = None) -> str:
```
to:
```python
    def notify(self, findings: list, run_id: str, report_paths: dict,
               domain_info: dict = None, suppressed_count: int = 0) -> str:
```

Pass `suppressed_count` to `_print_console_summary()`:
```python
        self._print_console_summary(findings, run_id, report_paths, domain_info, suppressed_count)
```

- [ ] **Step 4: Add suppression count line to `_print_console_summary()`**

In `modules/notifier.py`, change `_print_console_summary()` signature:
```python
    def _print_console_summary(self, findings, run_id, report_paths, domain_info, suppressed_count=0):
```

Find the line just before the closing `print(_c("BLUE", "=" * w))` in `_print_console_summary()`:
```python
        print(_c("BLUE", "=" * w))
        print()
```

Insert before it:
```python
        if suppressed_count > 0:
            print(_c("DIM",
                f"  {suppressed_count} finding(s) suppressed by policy "
                f"(accepted_risk/resolved). See policy.json or HTML report audit trail."
            ))
            print()
```

- [ ] **Step 5: Run all tests to verify nothing broke**

```bash
cd ADPulse_v1.0/ad_security_engine
python -m pytest tests/ -v
```
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add ADPulse_v1.0/ad_security_engine/modules/report_generator.py \
        ADPulse_v1.0/ad_security_engine/modules/notifier.py
git commit -m "feat: surface policy status in PDF report and console suppression count"
```

---

## Self-Review

### Spec coverage check

| Spec requirement | Task |
|---|---|
| Parallel LDAP via ThreadPoolExecutor | Task 2 |
| `ldap_threads` config key | Task 2 Step 6 |
| Failure of one query does not abort scan | Task 2 (test + implementation) |
| `get_domain_acl()` with binary SD parsing | Task 3 |
| `get_all_groups()` wired into scan | Task 2 (`_collect_ad_data`) |
| DCSync detection CRITICAL | Task 4 |
| Dormant privileged accounts HIGH | Task 5 |
| `dormant_admin_days` config key | Task 5 Step 3 |
| Nested group privilege expansion MEDIUM | Task 6 |
| Service accounts in privileged groups CRITICAL | Task 7 |
| Four new detections in run_all_detections() | Task 8 |
| PolicyManager CRUD | Task 9 |
| Expiry checking + auto-removal | Task 9 |
| Resolved findings reappearance handling | Task 9 |
| `--policy list/accept/remediate/resolve/clear` CLI | Task 10 |
| Validation against last scan's finding IDs | Task 10 |
| Policy applied in run_scan() | Task 10 |
| `in_remediation` badge in HTML | Task 11 |
| Suppressed findings excluded from main finding body | Task 11 |
| Audit trail section in HTML | Task 11 |
| Policy status line in PDF | Task 12 |
| Suppression count in console summary | Task 12 |
| Zero new Python packages | All tasks ✓ |
| Improvement 2 (interactive HTML) | Already done — no task needed |

### Placeholder scan
No TBDs, TODOs, or "similar to above" references. Every step has complete code.

### Type consistency
- `_collect_ad_data(collector, scanning_cfg: dict) -> dict` — used consistently in Task 2 test and implementation
- `PolicyManager.apply_to_findings(findings: list) -> tuple` returns `(active, suppressed)` — used correctly in Tasks 9, 10, 11
- `generate_all(..., suppressed=None)` — signature updated in Task 12 Step 1, matches call site in Task 10 Step 4
- `notify(..., suppressed_count: int = 0)` — matches call in Task 10 Step 4
- `detect_dcsync_rights(domain_acl, domain_controllers)` — matches call in Task 8
- `detect_dormant_privileged_accounts(users, privileged_members)` — matches call in Task 8
- `detect_nested_privilege(all_groups, privileged_members)` — matches call in Task 8
- `detect_privileged_spn(kerberoastable, privileged_members)` — matches call in Task 8
