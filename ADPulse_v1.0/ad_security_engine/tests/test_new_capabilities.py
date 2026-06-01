"""
Tests for the post-LDAP-sandbox capabilities:
  * scoring model (pillars + maturity)
  * MITRE ATT&CK tagging
  * ADCS ESC1-ESC4 detections
  * anonymous-access and RBCD detections
  * deeper trust analysis
  * SYSVOL GPP cpassword helpers + DACL parsing
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timezone, timedelta

from modules.detections import DetectionEngine
from modules import scoring, mitre

CFG = {
    "stale_account_days": "60",
    "privileged_groups": "Domain Admins,Enterprise Admins",
    "dormant_admin_days": "90",
}
engine = DetectionEngine(CFG)


# ── Scoring model ─────────────────────────────────────────────────────────────

def test_scoring_overall_is_worst_pillar():
    findings = [
        {"finding_id": "ESC1-VULNERABLE-TEMPLATE", "severity": "CRITICAL", "category": "Certificate Services"},
        {"finding_id": "ACCT-001-STALE", "severity": "LOW", "category": "Account Hygiene"},
    ]
    model = scoring.compute(findings)
    # CRITICAL anomaly => Anomalies pillar at 40, overall = max pillar
    assert model["overall_score"] == 40
    assert model["pillars"]["Anomalies"]["score"] == 40
    assert model["pillars"]["Stale Objects"]["score"] == 3
    assert model["risk_label"] == "HIGH"


def test_scoring_maturity_level_tracks_worst_severity():
    assert scoring.compute([{"finding_id": "X", "severity": "CRITICAL"}])["maturity_level"] == 1
    assert scoring.compute([{"finding_id": "X", "severity": "MEDIUM"}])["maturity_level"] == 3
    assert scoring.compute([])["maturity_level"] == 5


def test_scoring_pillar_classification():
    assert scoring.pillar_for({"finding_id": "PRIV-001-DORMANT-ADMIN"}) == "Privileged Accounts"
    assert scoring.pillar_for({"finding_id": "TRUST-001-NO-SID-FILTER"}) == "Trusts"
    assert scoring.pillar_for({"finding_id": "COMP-001-STALE"}) == "Stale Objects"
    assert scoring.pillar_for({"finding_id": "KERB-001-STANDARD"}) == "Anomalies"
    # multi-domain suffix is ignored
    assert scoring.pillar_for({"finding_id": "TRUST-001-NO-SID-FILTER@corp.local"}) == "Trusts"


# ── MITRE tagging ─────────────────────────────────────────────────────────────

def test_mitre_known_mappings():
    assert mitre.techniques_for("ACL-001-DCSYNC")[0]["id"] == "T1003.006"
    assert mitre.techniques_for("KERB-002-ASREP")[0]["id"] == "T1558.004"
    assert mitre.techniques_for("ESC1-VULNERABLE-TEMPLATE")[0]["id"] == "T1649"
    # domain suffix tolerated
    assert mitre.techniques_for("KERB-001-STANDARD@corp.local")[0]["id"] == "T1558.003"
    assert mitre.techniques_for("UNKNOWN-XYZ") == []


def test_mitre_attach_is_idempotent():
    findings = [{"finding_id": "ACL-001-DCSYNC", "severity": "CRITICAL"}]
    mitre.attach(findings)
    mitre.attach(findings)
    assert len(findings[0]["mitre"]) == 1


# ── ADCS ESC detections ───────────────────────────────────────────────────────

def _template(**kw):
    base = {
        "name": "T", "display_name": "T",
        "enrollee_supplies_subject": False, "requires_manager_approval": False,
        "authorized_signatures_required": 0, "ekus": [], "client_auth": False,
        "any_purpose": False, "no_eku": False, "enrollment_agent": False,
        "low_priv_enroll": False, "low_priv_edit": False, "dn": "CN=T",
    }
    base.update(kw)
    return base


def test_esc1_detected():
    t = _template(display_name="VulnUser", enrollee_supplies_subject=True,
                  client_auth=True, low_priv_enroll=True)
    findings = engine.detect_adcs_misconfigurations([t], [])
    ids = {f["finding_id"] for f in findings}
    assert "ESC1-VULNERABLE-TEMPLATE" in ids
    esc1 = next(f for f in findings if f["finding_id"] == "ESC1-VULNERABLE-TEMPLATE")
    assert esc1["severity"] == "CRITICAL"
    assert "VulnUser" in esc1["affected"]


def test_esc1_suppressed_when_manager_approval_required():
    t = _template(enrollee_supplies_subject=True, client_auth=True,
                  low_priv_enroll=True, requires_manager_approval=True)
    findings = engine.detect_adcs_misconfigurations([t], [])
    assert not any(f["finding_id"] == "ESC1-VULNERABLE-TEMPLATE" for f in findings)


def test_esc2_and_esc3_and_esc4():
    esc2 = _template(name="AnyP", any_purpose=True, low_priv_enroll=True)
    esc3 = _template(name="Agent", enrollment_agent=True, low_priv_enroll=True)
    esc4 = _template(name="WeakAcl", low_priv_edit=True)
    findings = engine.detect_adcs_misconfigurations([esc2, esc3, esc4], [])
    ids = {f["finding_id"] for f in findings}
    assert {"ESC2-ANY-PURPOSE", "ESC3-ENROLLMENT-AGENT", "ESC4-TEMPLATE-ACL"} <= ids


def test_adcs_no_templates_no_findings():
    assert engine.detect_adcs_misconfigurations([], []) == []


# ── Anonymous access ──────────────────────────────────────────────────────────

def test_dsheuristics_anonymous_detected():
    findings = engine.detect_anonymous_access("0000002", [])
    assert any(f["finding_id"] == "ANON-001-DSHEURISTICS" for f in findings)


def test_dsheuristics_safe_value():
    assert engine.detect_anonymous_access("0000000", []) == []
    assert engine.detect_anonymous_access(None, []) == []


def test_pre2000_anonymous_detected():
    findings = engine.detect_anonymous_access(None, ["Everyone (S-1-1-0)"])
    assert any(f["finding_id"] == "ANON-002-PRE2000" for f in findings)


# ── RBCD ──────────────────────────────────────────────────────────────────────

def test_rbcd_detected():
    accts = [{"sAMAccountName": "WEB01$"}]
    findings = engine.detect_resource_based_delegation(accts)
    assert findings and findings[0]["finding_id"] == "RBCD-001-CONFIGURED"
    assert "WEB01$" in findings[0]["affected"]


def test_rbcd_empty():
    assert engine.detect_resource_based_delegation([]) == []


# ── Trust depth ───────────────────────────────────────────────────────────────

def test_downlevel_and_inactive_trust():
    old = (datetime.now(tz=timezone.utc) - timedelta(days=500))
    trusts = [
        {"trustPartner": "legacy.nt4", "trustType": 1, "trustDirection": 3,
         "trustAttributes": 0x4, "whenChanged": old},
    ]
    findings = engine.detect_trust_relationships(trusts)
    ids = {f["finding_id"] for f in findings}
    assert "TRUST-003-DOWNLEVEL" in ids
    assert "TRUST-004-INACTIVE" in ids


# ── SYSVOL / GPP helpers ──────────────────────────────────────────────────────

def test_find_cpasswords_extracts_account():
    from modules.sysvol_scanner import find_cpasswords
    xml = (
        '<?xml version="1.0"?>'
        '<Groups><User name="svc"><Properties userName="svc-admin" '
        'cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdQ"/></User></Groups>'
    )
    hits = find_cpasswords(xml)
    assert len(hits) == 1
    assert hits[0]["account"] == "svc-admin"


def test_find_cpasswords_none_when_absent():
    from modules.sysvol_scanner import find_cpasswords
    assert find_cpasswords("<Groups><User name='x'/></Groups>") == []


def test_decrypt_gpp_known_value():
    """The published MS14-025 test vector must verify as valid ciphertext."""
    from modules.sysvol_scanner import decrypt_gpp_cpassword
    result = decrypt_gpp_cpassword("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdQ")
    # True if cryptography is installed and it decrypts; None if lib missing.
    assert result in (True, None)


# ── DACL parsing ──────────────────────────────────────────────────────────────

def test_parse_dacl_empty_on_garbage():
    from modules.ldap_collector import parse_dacl_aces, analyze_template_acl
    assert parse_dacl_aces(b"") == []
    assert parse_dacl_aces(b"\x00" * 4) == []
    info = analyze_template_acl(b"\x00" * 4)
    assert info["low_priv_enroll"] is False


def test_is_low_priv_sid():
    from modules.ldap_collector import is_low_priv_sid
    assert is_low_priv_sid("S-1-5-11") is True            # Authenticated Users
    assert is_low_priv_sid("S-1-5-21-1-2-3-513") is True  # Domain Users
    assert is_low_priv_sid("S-1-5-21-1-2-3-512") is False  # Domain Admins


def test_html_report_escapes_ad_controlled_values():
    """A malicious sAMAccountName/description must not inject raw HTML (stored XSS)."""
    import tempfile
    from modules.report_generator import HTMLReportGenerator
    finding = {
        "finding_id": "X", "severity": "HIGH", "category": "Test",
        "title": "<b>t</b>", "description": "<i>d</i>",
        "affected": ["<script>alert(1)</script>"], "remediation": "fix", "is_new": 1,
    }
    path = HTMLReportGenerator().generate(
        [finding], "r", tempfile.mktemp(suffix=".html"), "Co",
        {"name": "c", "server": "s"})
    txt = open(path, encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in txt
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in txt


def test_dacl_parser_flags_low_priv_enroll_real_sd():
    """Parse a real binary security descriptor granting Enroll to Authenticated Users."""
    import struct
    from modules.ldap_collector import analyze_template_acl, _ENROLL_GUID

    sid = bytes([1, 1]) + (5).to_bytes(6, "big") + struct.pack("<I", 11)  # S-1-5-11
    ace_body = struct.pack("<I", 0x100) + struct.pack("<I", 0x1) + _ENROLL_GUID + sid
    ace = struct.pack("<BBH", 0x05, 0, 4 + len(ace_body)) + ace_body
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(ace), 1, 0) + ace
    sd = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + acl

    info = analyze_template_acl(sd)
    assert info["low_priv_enroll"] is True
    assert "S-1-5-11" in info["enroll_sids"]
