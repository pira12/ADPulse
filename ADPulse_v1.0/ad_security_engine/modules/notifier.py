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

import csv
import io
import json
import logging
import os
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

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

    def __init__(self, config: dict, output_config: dict = None):
        self.output_dir   = Path(config.get("output_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.company_name = config.get("company_name", "Your Organisation")
        self.gen_csv      = config.get("generate_csv", "false").lower() == "true"

        out = output_config or {}
        self.min_severity = out.get("min_summary_severity", "MEDIUM").upper()
        self.write_eventlog = out.get("write_windows_eventlog", "false").lower() == "true"
        self.min_sev_order  = SEVERITY_ORDER.get(self.min_severity, 2)

        # Webhook config
        self.webhook_url = out.get("webhook_url", "").strip()
        self.webhook_min_sev = SEVERITY_ORDER.get(
            out.get("webhook_min_severity", "HIGH").upper(), 1
        )

        # Syslog config
        self.syslog_server = out.get("syslog_server", "").strip()
        self.syslog_port = int(out.get("syslog_port", 514))

        # Email config
        self.email_enabled = out.get("email_enabled", "false").lower() == "true"
        self.smtp_server = out.get("smtp_server", "")
        self.smtp_port = int(out.get("smtp_port", 587))
        self.smtp_use_tls = out.get("smtp_use_tls", "true").lower() == "true"
        self.smtp_username = out.get("smtp_username", "")
        self.smtp_password = out.get("smtp_password", "")
        self.email_from = out.get("email_from", "")
        self.email_to = out.get("email_to", "")
        self.email_min_sev = SEVERITY_ORDER.get(
            out.get("email_min_severity", "HIGH").upper(), 1
        )

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
        self._write_json_export(findings, run_id, domain_info)

        if self.gen_csv:
            self._write_csv_export(findings, run_id)

        if self.write_eventlog and platform.system() == "Windows":
            self._write_windows_event(findings, run_id)

        if self.webhook_url:
            self._send_webhook(findings, run_id, domain_info)

        if self.syslog_server:
            self._send_syslog(findings, run_id)

        if self.email_enabled:
            self._send_email(findings, run_id, report_paths, domain_info)

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
    #  JSON Export (for SIEM / automation integration)                      #
    # ------------------------------------------------------------------ #

    def _write_json_export(self, findings, run_id, domain_info) -> str:
        """
        Write a machine-readable JSON export of all findings.
        Useful for SIEM ingestion, ticketing system integration, or automation.
        """
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(self.output_dir / f"ADPulse_Export_{ts}.json")

        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = min(
            counts["CRITICAL"] * 40 + counts["HIGH"] * 15 + counts["MEDIUM"] * 5 + counts["LOW"] * 1, 100
        )

        export = {
            "tool": "ADPulse",
            "version": "1.0",
            "scan_time": now,
            "run_id": run_id,
            "domain": {
                "name": (domain_info or {}).get("name", ""),
                "base_dn": (domain_info or {}).get("base_dn", ""),
                "server": (domain_info or {}).get("server", ""),
            },
            "summary": {
                "total_findings": len(findings),
                "risk_score": risk_score,
                "by_severity": counts,
            },
            "findings": [
                {
                    "finding_id": f.get("finding_id"),
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "affected_count": len(f.get("affected", [])),
                    "affected": f.get("affected", []),
                    "remediation": f.get("remediation", ""),
                    "first_seen": f.get("first_seen"),
                    "is_new": bool(f.get("is_new", 1)),
                }
                for f in findings
            ],
        }

        Path(out_path).write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")
        logger.info(f"JSON export -> {out_path}")
        return out_path

    # ------------------------------------------------------------------ #
    #  CSV Export                                                           #
    # ------------------------------------------------------------------ #

    def _write_csv_export(self, findings, run_id) -> str:
        """Write findings as CSV for spreadsheet analysis."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(self.output_dir / f"ADPulse_Export_{ts}.csv")

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID", "Severity", "Category", "Title",
                "Affected Count", "Affected Objects", "First Seen",
                "Is New", "Description", "Remediation"
            ])
            for finding in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99)):
                affected = finding.get("affected", [])
                writer.writerow([
                    finding.get("finding_id", ""),
                    finding.get("severity", ""),
                    finding.get("category", ""),
                    finding.get("title", ""),
                    len(affected),
                    "; ".join(str(a) for a in affected[:50]),
                    (finding.get("first_seen") or "")[:19],
                    "NEW" if finding.get("is_new", 1) else "RECURRING",
                    finding.get("description", ""),
                    finding.get("remediation", ""),
                ])

        logger.info(f"CSV export -> {out_path}")
        return out_path

    # ------------------------------------------------------------------ #
    #  Webhook Notification                                                #
    # ------------------------------------------------------------------ #

    def _send_webhook(self, findings, run_id, domain_info):
        """Send scan summary to a webhook URL (Slack, Teams, custom endpoint)."""
        try:
            import urllib.request

            alert_findings = [
                f for f in findings
                if SEVERITY_ORDER.get(f.get("severity", "INFO"), 99) <= self.webhook_min_sev
            ]

            if not alert_findings:
                logger.debug("No findings meet webhook severity threshold.")
                return

            counts = {s: 0 for s in SEVERITY_ORDER}
            for f in findings:
                counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

            domain_name = (domain_info or {}).get("name", "Unknown")

            # Generic JSON payload (works with most webhook endpoints)
            payload = {
                "text": (
                    f"ADPulse Security Scan - {domain_name}\n"
                    f"CRITICAL: {counts.get('CRITICAL',0)} | HIGH: {counts.get('HIGH',0)} | "
                    f"MEDIUM: {counts.get('MEDIUM',0)} | LOW: {counts.get('LOW',0)}\n"
                    f"Run ID: {run_id[:16]}..."
                ),
                "findings": [
                    {"severity": f["severity"], "title": f["title"],
                     "affected_count": len(f.get("affected", []))}
                    for f in alert_findings[:20]
                ],
            }

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=15)
            logger.info(f"Webhook notification sent to {self.webhook_url}")

        except Exception as e:
            logger.warning(f"Webhook notification failed: {e}")

    # ------------------------------------------------------------------ #
    #  Syslog Output                                                       #
    # ------------------------------------------------------------------ #

    def _send_syslog(self, findings, run_id):
        """Send each finding as a syslog message (UDP, RFC 5424 compatible)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sev_to_priority = {
                "CRITICAL": 2,  # LOG_CRIT
                "HIGH": 3,      # LOG_ERR
                "MEDIUM": 4,    # LOG_WARNING
                "LOW": 6,       # LOG_INFO
                "INFO": 6,      # LOG_INFO
            }

            for f in findings:
                sev = f.get("severity", "INFO")
                priority = 8 + sev_to_priority.get(sev, 6)  # facility=user (1) * 8 + severity
                msg = (
                    f"<{priority}>ADPulse run={run_id[:16]} "
                    f"finding_id={f.get('finding_id','')} "
                    f"severity={sev} "
                    f"title=\"{f.get('title','')}\" "
                    f"affected_count={len(f.get('affected',[]))} "
                    f"category=\"{f.get('category','')}\""
                )
                sock.sendto(msg.encode("utf-8"), (self.syslog_server, self.syslog_port))

            sock.close()
            logger.info(f"Sent {len(findings)} syslog messages to {self.syslog_server}:{self.syslog_port}")

        except Exception as e:
            logger.warning(f"Syslog output failed: {e}")

    # ------------------------------------------------------------------ #
    #  Email Notification                                                  #
    # ------------------------------------------------------------------ #

    def _send_email(self, findings, run_id, report_paths, domain_info):
        """Send scan summary and PDF report via SMTP email."""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            from email.mime.base import MIMEBase
            from email import encoders

            alert_findings = [
                f for f in findings
                if SEVERITY_ORDER.get(f.get("severity", "INFO"), 99) <= self.email_min_sev
            ]

            if not alert_findings and findings:
                logger.debug("No findings meet email severity threshold.")
                return

            counts = {s: 0 for s in SEVERITY_ORDER}
            for f in findings:
                counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

            domain_name = (domain_info or {}).get("name", "Unknown Domain")
            risk_score = min(
                counts["CRITICAL"] * 40 + counts["HIGH"] * 15 +
                counts["MEDIUM"] * 5 + counts["LOW"] * 1, 100
            )

            subject = f"ADPulse: {domain_name} - Risk {risk_score}/100"
            if counts.get("CRITICAL", 0) > 0:
                subject += f" [{counts['CRITICAL']} CRITICAL]"

            body = (
                f"ADPulse Security Scan Report\n"
                f"{'='*50}\n"
                f"Domain: {domain_name}\n"
                f"Risk Score: {risk_score}/100\n"
                f"Run ID: {run_id}\n\n"
                f"Findings: CRITICAL={counts.get('CRITICAL',0)} | HIGH={counts.get('HIGH',0)} | "
                f"MEDIUM={counts.get('MEDIUM',0)} | LOW={counts.get('LOW',0)}\n\n"
            )

            for f in alert_findings[:15]:
                body += f"[{f['severity']}] {f['title']}\n"
                body += f"  Affected: {len(f.get('affected',[]))} object(s)\n\n"

            body += "\nFull report attached (PDF).\n"
            body += "This email was generated by ADPulse.\n"

            msg = MIMEMultipart()
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            # Attach PDF if available
            pdf_path = report_paths.get("pdf")
            if pdf_path and Path(pdf_path).exists():
                with open(pdf_path, "rb") as f:
                    part = MIMEBase("application", "pdf")
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f"attachment; filename={Path(pdf_path).name}")
                    msg.attach(part)

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                if self.smtp_username:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

            logger.info(f"Email notification sent to {self.email_to}")

        except ImportError:
            logger.warning("smtplib not available for email notification.")
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")

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
