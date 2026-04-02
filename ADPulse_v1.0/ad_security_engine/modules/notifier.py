"""
notifier.py
-----------
ADPulse - Output & Notification Module

No email server needed. Instead, ADPulse outputs findings in three ways:
  1. Console summary (always shown after every scan)
  2. Plain-text summary file  (easy to paste into Teams / email / ticket)
  3. Windows Event Log entry  (optional - only if running on Windows)

The summary .txt file in ./output/ is the primary sharing mechanism.
Copy it into an email, Teams message, or ticket manually.
"""

import logging
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_ICON_PLAIN = {
    "CRITICAL": "[!!!]",
    "HIGH":     "[ !! ]",
    "MEDIUM":   "[  ! ]",
    "LOW":      "[  - ]",
    "INFO":     "[  i ]",
}

# ANSI colours for console (stripped on Windows if not supported)
ANSI = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[93m",   # bright yellow
    "MEDIUM":   "\033[33m",   # yellow
    "LOW":      "\033[92m",   # green
    "INFO":     "\033[94m",   # blue
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "ORANGE":   "\033[38;5;208m",
    "BLUE":     "\033[38;5;27m",
}

_SUPPORTS_ANSI = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and platform.system() != "Windows"  # Windows cmd usually can't handle ANSI
    or os.environ.get("FORCE_COLOR") is not None
)


def _c(key: str, text: str) -> str:
    """Wrap text in ANSI colour if supported."""
    if not _SUPPORTS_ANSI:
        return text
    return f"{ANSI.get(key,'')}{text}{ANSI['RESET']}"


class OutputNotifier:
    """
    Handles all post-scan output:
      - Console summary table
      - Plain-text summary file (for manual sharing)
      - Windows Event Log (optional)
    """

    def __init__(self, config: dict):
        self.output_dir   = Path(config.get("output_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.company_name = config.get("company_name", "Your Organisation")
        self.min_severity = config.get("min_summary_severity", "MEDIUM").upper()
        self.write_eventlog = config.get("write_windows_eventlog", "false").lower() == "true"
        self.min_sev_order  = SEVERITY_ORDER.get(self.min_severity, 2)

    # ------------------------------------------------------------------ #
    #  Public Entry Point                                                  #
    # ------------------------------------------------------------------ #

    def notify(self, findings: list, run_id: str, report_paths: dict, domain_info: dict = None) -> str:
        """
        Run all notification outputs after a scan.
        Returns the path to the generated summary .txt file.
        """
        self._print_console_summary(findings, run_id, report_paths, domain_info)
        txt_path = self._write_summary_file(findings, run_id, report_paths, domain_info)

        if self.write_eventlog and platform.system() == "Windows":
            self._write_windows_event(findings, run_id)

        return txt_path

    # ------------------------------------------------------------------ #
    #  Console Output                                                      #
    # ------------------------------------------------------------------ #

    def _print_console_summary(self, findings, run_id, report_paths, domain_info):
        """Print a formatted summary to stdout."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = min(
            counts["CRITICAL"]*40 + counts["HIGH"]*15 + counts["MEDIUM"]*5 + counts["LOW"]*1, 100
        )
        risk_label = ("CRITICAL" if risk_score>=70 else "HIGH" if risk_score>=40 else "MEDIUM" if risk_score>=20 else "LOW")

        w = 70
        print()
        print(_c("BLUE", "=" * w))
        print(_c("BOLD", "  ADPulse".ljust(20)) + _c("DIM", "Active Directory Security Assessment"))
        print(_c("DIM", f"  {self.company_name}") + "  |  " + _c("DIM", now))
        print(_c("BLUE", "=" * w))

        if domain_info:
            print(_c("DIM", f"  Domain : {domain_info.get('name') or domain_info.get('base_dn','')}"))
            print(_c("DIM", f"  Server : {domain_info.get('server','')}"))
            print(_c("DIM", f"  Run ID : {run_id[:36]}"))
            print()

        # Severity counts
        print(_c("BOLD", "  FINDING SUMMARY"))
        print("  " + "-" * (w-4))
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            count  = counts[sev]
            icon   = SEVERITY_ICON_PLAIN[sev]
            bar    = "█" * count if count <= 20 else "█" * 20 + f"  (+{count-20})"
            prefix = _c(sev, f"  {icon} {sev:<10}")
            num    = _c(sev, f" {count:>3} ")
            print(f"{prefix}{num} {_c(sev, bar)}")

        print()
        risk_col = "CRITICAL" if risk_label == "CRITICAL" else "HIGH" if risk_label == "HIGH" else "MEDIUM" if risk_label == "MEDIUM" else "LOW"
        print(f"  Risk Score: {_c(risk_col, str(risk_score) + '/100')}  ({_c(risk_col, risk_label)})")
        print()

        # Top findings
        alert_findings = [
            f for f in findings
            if SEVERITY_ORDER.get(f.get("severity","INFO"), 99) <= self.min_sev_order
        ]
        if alert_findings:
            print(_c("BOLD", "  TOP FINDINGS (requires attention)"))
            print("  " + "-" * (w-4))
            for f in sorted(alert_findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"),99))[:15]:
                sev  = f.get("severity","INFO")
                icon = SEVERITY_ICON_PLAIN[sev]
                title = f.get("title","")[:50]
                affected_n = len(f.get("affected",[]))
                new_marker = " [NEW]" if f.get("is_new",1) else ""
                print(f"  {_c(sev, icon + ' ' + title)}")
                print(_c("DIM", f"           {affected_n} affected object(s){new_marker}"))
            print()

        # Report paths
        if report_paths:
            print(_c("BOLD", "  REPORTS SAVED"))
            print("  " + "-" * (w-4))
            for fmt, p in report_paths.items():
                print(f"  {_c('BLUE', fmt.upper())}: {p}")
        print()
        print(_c("BLUE", "=" * w))
        print()

    # ------------------------------------------------------------------ #
    #  Plain-Text Summary File                                             #
    # ------------------------------------------------------------------ #

    def _write_summary_file(self, findings, run_id, report_paths, domain_info) -> str:
        """
        Write a plain-text summary .txt file.
        This is the primary sharing artifact — paste into Teams / email / ticket.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(self.output_dir / f"ADPulse_Summary_{ts}.txt")

        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity","INFO")
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = min(
            counts["CRITICAL"]*40 + counts["HIGH"]*15 + counts["MEDIUM"]*5 + counts["LOW"]*1, 100
        )
        risk_label = (
            "CRITICAL" if risk_score>=70 else "HIGH" if risk_score>=40 else
            "MEDIUM" if risk_score>=20 else "LOW"
        )

        lines = []
        sep = "=" * 72

        lines += [
            sep,
            "  ADPulse - Active Directory Security Assessment",
            f"  {self.company_name}  |  {now}",
            sep,
            "",
        ]

        if domain_info:
            lines += [
                f"  Domain  : {domain_info.get('name') or domain_info.get('base_dn','')}",
                f"  Server  : {domain_info.get('server','')}",
                f"  Run ID  : {run_id}",
                "",
            ]

        lines += [
            "OVERALL RISK SCORE",
            "-" * 40,
            f"  Score : {risk_score} / 100",
            f"  Level : {risk_label}",
            "",
            "FINDING COUNTS",
            "-" * 40,
        ]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            lines.append(f"  {SEVERITY_ICON_PLAIN[sev]} {sev:<12} {counts[sev]}")

        lines += ["", "FINDINGS DETAIL", "-" * 40, ""]

        sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"),99))
        for f in sorted_findings:
            sev    = f.get("severity","INFO")
            icon   = SEVERITY_ICON_PLAIN[sev]
            is_new = "NEW" if f.get("is_new",1) else "RECURRING"
            lines += [
                f"{icon} [{sev}] {f.get('title','')}  ({is_new})",
                f"   Category   : {f.get('category','')}",
                f"   Finding ID : {f.get('finding_id','')}",
                f"   First seen : {(f.get('first_seen') or 'This scan')[:19]}",
            ]
            affected = f.get("affected", [])
            if affected:
                aff_str = ", ".join(str(a) for a in affected[:20])
                if len(affected)>20: aff_str += f" (+{len(affected)-20} more)"
                lines.append(f"   Affected   : {aff_str}")
            lines.append(f"   Description: {f.get('description','')}")
            lines.append("")
            rem = f.get("remediation","")
            if rem:
                lines.append("   Remediation:")
                for rline in rem.split("\n"):
                    lines.append(f"     {rline}")
            lines += ["", "-" * 72, ""]

        if report_paths:
            lines += ["FULL REPORTS", "-" * 40]
            for fmt, p in report_paths.items():
                lines.append(f"  {fmt.upper()}: {p}")
            lines.append("")

        lines += [
            sep,
            "  Generated by ADPulse - Open Source Active Directory Security Engine",
            "  This document is confidential. Do not distribute outside your organisation.",
            sep,
        ]

        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        logger.info(f"Summary file -> {out_path}")
        print(f"  Share-ready summary: {out_path}")
        print()
        return out_path

    # ------------------------------------------------------------------ #
    #  Windows Event Log (optional)                                        #
    # ------------------------------------------------------------------ #

    def _write_windows_event(self, findings, run_id):
        """
        Write a summary entry to the Windows Application Event Log.
        Useful for SIEM tools (Splunk, Sentinel, etc.) that monitor event logs.
        Requires pywin32: pip install pywin32
        """
        try:
            import win32evtlog
            import win32evtlogutil
            import win32con

            counts = {s: 0 for s in SEVERITY_ORDER}
            for f in findings:
                sev = f.get("severity","INFO")
                counts[sev] = counts.get(sev,0)+1

            critical = counts.get("CRITICAL",0)
            high     = counts.get("HIGH",0)

            event_type = (
                win32con.EVENTLOG_ERROR_TYPE   if critical > 0 else
                win32con.EVENTLOG_WARNING_TYPE if high     > 0 else
                win32con.EVENTLOG_INFORMATION_TYPE
            )

            msg = (
                f"ADPulse Security Scan Complete\n"
                f"Run ID: {run_id}\n"
                f"Total findings: {len(findings)}\n"
                f"CRITICAL: {critical}  HIGH: {high}  "
                f"MEDIUM: {counts.get('MEDIUM',0)}  LOW: {counts.get('LOW',0)}"
            )

            win32evtlogutil.ReportEvent(
                "ADPulse",
                1001,
                eventCategory=1,
                eventType=event_type,
                strings=[msg],
            )
            logger.info("Windows Event Log entry written (source: ADPulse, event ID: 1001).")

        except ImportError:
            logger.debug("pywin32 not installed — Windows Event Log skipped.")
        except Exception as e:
            logger.warning(f"Could not write Windows Event Log: {e}")
