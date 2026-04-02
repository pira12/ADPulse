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
