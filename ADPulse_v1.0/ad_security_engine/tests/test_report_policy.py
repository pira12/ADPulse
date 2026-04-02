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
    # Suppressed finding ID should not appear as a card anchor
    assert 'id="SUPP-001"' not in html
    # Audit trail section present
    assert "Policy Audit Trail" in html
    assert "Known risk" in html


def test_no_suppressed_no_audit_trail():
    """When there are no suppressed findings, the audit trail section is omitted."""
    html = _generate([dict(BASE_FINDING)])
    assert "Policy Audit Trail" not in html
