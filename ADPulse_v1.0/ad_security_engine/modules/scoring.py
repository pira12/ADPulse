"""
scoring.py
----------
Risk scoring and AD security maturity model for ADPulse.

This centralises the risk-score calculation (previously duplicated inline in the
HTML report, the PDF report, and the trend dashboard) and adds a PingCastle-style
assessment model on top:

  * Per-pillar scoring across four risk pillars
        - Privileged Accounts
        - Trusts
        - Stale Objects
        - Anomalies
    Each pillar is scored 0-100 (higher = worse). The overall domain score is the
    MAXIMUM of the four pillar scores — a single critical weakness in any one area
    is enough to make the whole domain high-risk. This mirrors the methodology used
    by established AD assessment tools and avoids a flood of low findings masking a
    single domain-compromise issue.

  * A 1-5 maturity level (1 = worst, 5 = best) derived from the most severe
    outstanding finding, giving a single at-a-glance grade for management.

The functions here are pure (no I/O) so they are trivially unit-testable and can be
called from any report generator or the baseline trend builder.
"""

from typing import Iterable

# Points contributed to a pillar by a single finding of each severity.
# Tuned so that one CRITICAL alone pushes a pillar into the CRITICAL band (>=70),
# while a handful of MEDIUMs accumulate gradually.
SEVERITY_POINTS = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":      3,
    "INFO":     0,
}

# The four risk pillars (display order preserved).
PILLARS = ["Privileged Accounts", "Trusts", "Stale Objects", "Anomalies"]

# Map a finding's ID prefix to a pillar. Prefix matching is used because
# finding_ids are stable identifiers (categories are free-text and may drift).
# Order matters: the first matching prefix wins.
_PREFIX_PILLAR = [
    ("ACL-001-DCSYNC",      "Privileged Accounts"),
    ("PRIV-",               "Privileged Accounts"),
    ("DELTA-PRIV-",         "Privileged Accounts"),
    ("OPSGRP-",             "Privileged Accounts"),
    ("TRUST-",              "Trusts"),
    ("ACCT-",               "Stale Objects"),
    ("COMP-",               "Stale Objects"),
    ("OS-",                 "Stale Objects"),
    ("DELTA-ACCT-",         "Stale Objects"),
    # Everything credential / config / certificate / kerberos related is an anomaly.
    ("KERB-",               "Anomalies"),
    ("DELEG-",              "Anomalies"),
    ("PWD-",                "Anomalies"),
    ("POL-",                "Anomalies"),
    ("CONF-",               "Anomalies"),
    ("ESC",                 "Anomalies"),
    ("ADCS-",               "Anomalies"),
    ("ANON-",               "Anomalies"),
    ("RBCD-",               "Anomalies"),
    ("GPP-",                "Anomalies"),
    ("SYSVOL-",             "Anomalies"),
]

# Map free-text category to a pillar as a fallback when no prefix matches.
_CATEGORY_PILLAR = {
    "Privileged Access":         "Privileged Accounts",
    "Privileged Access Changes": "Privileged Accounts",
    "Account Hygiene":           "Stale Objects",
    "Account Changes":           "Stale Objects",
    "Infrastructure":            "Stale Objects",
    "Kerberos":                  "Anomalies",
    "Delegation":                "Anomalies",
    "Password Hygiene":          "Anomalies",
    "Password Policy":           "Anomalies",
    "Domain Configuration":      "Anomalies",
    "Certificate Services":      "Anomalies",
}

# Maturity level: 1 (worst) .. 5 (best), driven by the worst outstanding severity.
_MATURITY_BY_WORST = {
    "CRITICAL": 1,
    "HIGH":     2,
    "MEDIUM":   3,
    "LOW":      4,
}
MATURITY_LABELS = {
    1: "Level 1 — Critical exposure: domain compromise is likely with minimal effort.",
    2: "Level 2 — High exposure: significant attack paths exist.",
    3: "Level 3 — Developing: notable weaknesses remain to be hardened.",
    4: "Level 4 — Managed: only minor hygiene issues outstanding.",
    5: "Level 5 — Optimised: no material findings detected.",
}


def _strip_domain_suffix(finding_id: str) -> str:
    """Multi-domain runs append '@domain' to finding_ids — ignore it for mapping."""
    return finding_id.split("@", 1)[0]


def pillar_for(finding: dict) -> str:
    """Classify a finding into one of the four risk pillars."""
    fid = _strip_domain_suffix(str(finding.get("finding_id", "")))
    for prefix, pillar in _PREFIX_PILLAR:
        if fid.startswith(prefix):
            return pillar
    return _CATEGORY_PILLAR.get(finding.get("category", ""), "Anomalies")


def risk_label(score: int) -> str:
    """Map a 0-100 score to a severity band (kept consistent across all reports)."""
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def compute(findings: Iterable[dict]) -> dict:
    """
    Compute the full risk model for a set of findings.

    Returns a dict:
      {
        "overall_score":   int (0-100),
        "risk_label":      str,
        "maturity_level":  int (1-5),
        "maturity_label":  str,
        "severity_counts": {SEV: count},
        "pillars": {
            pillar_name: {"score": int, "findings": int, "worst": str|None},
            ...
        },
      }
    """
    findings = list(findings or [])

    severity_counts = {s: 0 for s in SEVERITY_POINTS}
    pillar_points = {p: 0 for p in PILLARS}
    pillar_counts = {p: 0 for p in PILLARS}
    pillar_worst = {p: None for p in PILLARS}

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    for f in findings:
        sev = f.get("severity", "INFO")
        if sev not in severity_counts:
            sev = "INFO"
        severity_counts[sev] += 1

        pillar = pillar_for(f)
        pillar_points[pillar] += SEVERITY_POINTS.get(sev, 0)
        pillar_counts[pillar] += 1

        # Track the worst severity seen in this pillar
        cur = pillar_worst[pillar]
        if cur is None or severity_order.index(sev) < severity_order.index(cur):
            pillar_worst[pillar] = sev

    pillars = {
        p: {
            "score": min(pillar_points[p], 100),
            "findings": pillar_counts[p],
            "worst": pillar_worst[p],
        }
        for p in PILLARS
    }

    overall_score = max((pillars[p]["score"] for p in PILLARS), default=0)

    # Maturity level: worst severity present (INFO/none -> level 5)
    maturity_level = 5
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts.get(sev, 0) > 0:
            maturity_level = _MATURITY_BY_WORST[sev]
            break

    return {
        "overall_score": overall_score,
        "risk_label": risk_label(overall_score),
        "maturity_level": maturity_level,
        "maturity_label": MATURITY_LABELS[maturity_level],
        "severity_counts": severity_counts,
        "pillars": pillars,
    }


def overall_score(findings: Iterable[dict]) -> int:
    """Convenience helper returning just the 0-100 overall score."""
    return compute(findings)["overall_score"]
