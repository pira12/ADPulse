"""
Task 12: PDF policy status note + console suppression count.

Tests:
1. PDF: in_remediation finding generates bytes containing the reason text
2. PDF: finding without policy_status has no "In remediation" text
3. Notifier: notify() accepts suppressed_count kwarg without error
4. Notifier: console prints suppression message when suppressed_count > 0
5. Notifier: console is silent about suppression when suppressed_count == 0
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import io
import tempfile
from unittest.mock import patch

from modules.notifier import OutputNotifier

# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #

BASE_FINDING = {
    "finding_id": "KERB-001",
    "category": "Kerberos",
    "severity": "HIGH",
    "title": "Kerberoastable Account",
    "description": "SPN set on account.",
    "affected": ["svc-sql"],
    "remediation": "Rotate password.",
    "is_new": 1,
    "first_seen": "2026-04-01",
}

NOTIFIER_CFG = {
    "output_dir": tempfile.mkdtemp(),
    "company_name": "TestCo",
    "generate_csv": "false",
}

OUTPUT_CFG = {
    "write_windows_eventlog": "false",
    "min_summary_severity": "MEDIUM",
}


def _make_notifier():
    return OutputNotifier(NOTIFIER_CFG, OUTPUT_CFG)


# --------------------------------------------------------------------------- #
#  PDF tests                                                                   #
# --------------------------------------------------------------------------- #

def _pdf_available():
    """Return True if reportlab is installed."""
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def test_pdf_in_remediation_note_present():
    """PDF bytes contain the policy_reason for in_remediation findings."""
    if not _pdf_available():
        return  # skip — reportlab not installed in this environment

    from modules.report_generator import PDFReportGenerator

    finding = dict(BASE_FINDING)
    finding["policy_status"] = "in_remediation"
    finding["policy_reason"] = "Ticket-9999 in progress"
    finding["policy_expires"] = "2026-12-31"

    tmp = tempfile.mktemp(suffix=".pdf")
    result = PDFReportGenerator().generate([finding], "test-run", tmp)
    assert result, "generate() should return a path"

    raw = open(tmp, "rb").read()
    # PDF stores text as bytes; check the reason text is embedded
    assert b"Ticket-9999" in raw or b"In remediation" in raw, (
        "Expected policy reason or 'In remediation' label in PDF bytes"
    )


def test_pdf_no_policy_status_no_remediation_note():
    """PDF bytes do NOT contain 'In remediation' for plain findings."""
    if not _pdf_available():
        return  # skip

    from modules.report_generator import PDFReportGenerator

    finding = dict(BASE_FINDING)
    # no policy_status

    tmp = tempfile.mktemp(suffix=".pdf")
    result = PDFReportGenerator().generate([finding], "test-run", tmp)
    assert result, "generate() should return a path"

    raw = open(tmp, "rb").read()
    assert b"In remediation" not in raw, (
        "Plain finding should not have 'In remediation' text in PDF"
    )


# --------------------------------------------------------------------------- #
#  Notifier / console tests                                                    #
# --------------------------------------------------------------------------- #

def test_notify_accepts_suppressed_count_kwarg():
    """OutputNotifier.notify() accepts suppressed_count without raising TypeError."""
    notifier = _make_notifier()
    with patch("builtins.print"):  # silence output
        result = notifier.notify(
            findings=[BASE_FINDING],
            run_id="run-001",
            report_paths={},
            suppressed_count=3,
        )
    assert isinstance(result, str)  # returns txt path


def test_console_shows_suppression_line_when_nonzero():
    """Console prints suppression message when suppressed_count > 0."""
    notifier = _make_notifier()
    captured = []

    original_print = __builtins__["print"] if isinstance(__builtins__, dict) else print

    def capturing_print(*args, **kwargs):
        captured.append(" ".join(str(a) for a in args))

    with patch("builtins.print", side_effect=capturing_print):
        notifier.notify(
            findings=[BASE_FINDING],
            run_id="run-002",
            report_paths={},
            suppressed_count=5,
        )

    full_output = "\n".join(captured)
    assert "suppressed" in full_output.lower(), (
        "Expected 'suppressed' in console output when suppressed_count=5"
    )
    assert "5" in full_output, "Expected the count 5 in console output"


def test_console_silent_about_suppression_when_zero():
    """Console does NOT mention suppression when suppressed_count is 0."""
    notifier = _make_notifier()
    captured = []

    def capturing_print(*args, **kwargs):
        captured.append(" ".join(str(a) for a in args))

    with patch("builtins.print", side_effect=capturing_print):
        notifier.notify(
            findings=[BASE_FINDING],
            run_id="run-003",
            report_paths={},
            suppressed_count=0,
        )

    full_output = "\n".join(captured)
    # The word "suppressed" should not appear (no policy activity)
    assert "suppressed by policy" not in full_output.lower(), (
        "Should not print suppression message when suppressed_count=0"
    )
