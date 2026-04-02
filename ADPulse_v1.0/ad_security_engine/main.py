"""
main.py
-------
AD Security Continuous Assessment Engine
Entry point. Orchestrates collection, detection, baselining, and reporting.

Usage:
    python main.py                     # Run a scan (uses config.ini)
    python main.py --config /path.ini  # Use a specific config file
    python main.py --test-connection   # Test LDAP connectivity only
    python main.py --report-only       # Generate report from last scan (no new scan)
    python main.py --daemon            # Run continuously on a schedule

Requires only a standard domain user account. NO admin privileges needed.
"""

import argparse
import configparser
import logging
import logging.handlers
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: str, log_level: str, max_mb: int, backup_count: int):
    level = getattr(logging, log_level.upper(), logging.INFO)
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backup_count,
    )
    fh.setFormatter(formatter)
    root.addHandler(fh)


logger = logging.getLogger("main")


# ─────────────────────────────────────────────────────────────────────────────
#  Config Loading
# ─────────────────────────────────────────────────────────────────────────────

def load_config(config_path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not Path(config_path).exists():
        print(f"ERROR: Config file not found: {config_path}")
        print("Copy config.ini.example to config.ini and fill in your settings.")
        sys.exit(1)
    cfg.read(config_path)
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
#  Core Scan Function
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(cfg: configparser.ConfigParser) -> dict:
    """
    Execute a complete AD security scan.
    Returns a dict with run_id, findings, report_paths, and stats.
    """
    from modules.ldap_collector import LDAPCollector
    from modules.baseline_engine import BaselineEngine
    from modules.detections import DetectionEngine
    from modules.notifier import OutputNotifier
    from modules.report_generator import ReportManager

    run_id = str(uuid.uuid4())
    started_at = datetime.now(tz=timezone.utc)
    logger.info("=" * 70)
    logger.info(f"AD SECURITY SCAN STARTED | Run ID: {run_id}")
    logger.info(f"Time: {started_at.isoformat()}")
    logger.info("=" * 70)

    # Initialise subsystems
    ldap_cfg      = dict(cfg["ldap"])
    scanning_cfg  = dict(cfg["scanning"])
    reporting_cfg = dict(cfg["reporting"])
    
    db_path       = cfg["database"].get("db_path", "./ad_baseline.db")

    baseline  = BaselineEngine(db_path)
    detector  = DetectionEngine(scanning_cfg)
    reporter  = ReportManager(reporting_cfg)
    notifier  = OutputNotifier(reporting_cfg)

    # Record scan start
    baseline.start_scan(run_id)

    # ── Step 1: Connect to AD ────────────────────────────────────────────
    logger.info("Step 1/6: Connecting to Active Directory...")
    collector = LDAPCollector(ldap_cfg)
    if not collector.connect():
        error_msg = "Failed to connect to Active Directory. Check your credentials and server settings."
        logger.error(error_msg)
        baseline.fail_scan(run_id, error_msg)
        return {"success": False, "error": error_msg, "run_id": run_id}

    try:
        # ── Step 2: Collect AD Data ──────────────────────────────────────
        logger.info("Step 2/6: Collecting AD data (this may take a moment)...")

        privileged_groups = [
            g.strip() for g in scanning_cfg.get(
                "privileged_groups",
                "Domain Admins,Enterprise Admins,Schema Admins,Administrators"
            ).split(",")
        ]

        ad_data = {
            "users":                 collector.get_all_users(),
            "kerberoastable":        collector.get_kerberoastable_accounts(),
            "asreproastable":        collector.get_asreproastable_accounts(),
            "pwd_never_expires":     collector.get_accounts_password_never_expires(),
            "admincount_users":      collector.get_admincount_accounts(),
            "privileged_members":    collector.get_privileged_group_members(privileged_groups),
            "computers":             collector.get_all_computers(),
            "domain_controllers":    collector.get_domain_controllers(),
            "unconstrained_delegation": collector.get_unconstrained_delegation_accounts(),
            "constrained_delegation":   collector.get_constrained_delegation_accounts(),
            "password_policy":       collector.get_password_policy(),
            "gpo_links":             collector.get_gpo_links(),
            "fine_grained_policies": collector.get_fine_grained_password_policies(),
            "domain_info":           collector.get_domain_info(),
        }

        logger.info(
            f"  → Users: {len(ad_data['users'])} | "
            f"Computers: {len(ad_data['computers'])} | "
            f"DCs: {len(ad_data['domain_controllers'])} | "
            f"Kerberoastable: {len(ad_data['kerberoastable'])} | "
            f"AS-REP: {len(ad_data['asreproastable'])}"
        )

        # ── Step 3: Store Baseline ───────────────────────────────────────
        logger.info("Step 3/6: Updating baseline database...")
        previous_run_id = baseline.get_last_successful_run_id()

        baseline.save_users(run_id, ad_data["users"])
        baseline.save_group_members(run_id, ad_data["privileged_members"])

        if previous_run_id:
            logger.info(f"  → Previous scan found: {previous_run_id[:16]}... (delta detection enabled)")
        else:
            logger.info("  → No previous baseline. This is the first scan — delta detections will run next time.")

        # ── Step 4: Run Detections ───────────────────────────────────────
        logger.info("Step 4/6: Running security detections...")
        findings = detector.run_all_detections(
            ad_data=ad_data,
            baseline=baseline if previous_run_id else None,
            previous_run_id=previous_run_id,
        )

        # Attach first_seen/is_new fields for report (will be overwritten by DB save)
        for f in findings:
            f.setdefault("first_seen", datetime.now(tz=timezone.utc).isoformat())
            f.setdefault("is_new", 1)

        baseline.save_findings(run_id, findings)

        # Reload from DB to get first_seen / is_new correctly
        findings = baseline.get_findings_for_run(run_id)

        # Log severity breakdown
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        logger.info(
            f"  → Findings: CRITICAL={counts.get('CRITICAL',0)} | "
            f"HIGH={counts.get('HIGH',0)} | MEDIUM={counts.get('MEDIUM',0)} | "
            f"LOW={counts.get('LOW',0)} | INFO={counts.get('INFO',0)}"
        )

        # ── Step 5: Generate Reports ─────────────────────────────────────
        logger.info("Step 5/6: Generating reports...")
        report_paths = reporter.generate_all(
            findings=findings,
            run_id=run_id,
            domain_info=ad_data.get("domain_info"),
        )
        for fmt, path in report_paths.items():
            logger.info(f"  → {fmt.upper()} report: {path}")

        # ── Step 6: Send Alerts ──────────────────────────────────────────
        logger.info("Step 6/6: Generating output summary...")
        pdf_path = report_paths.get("pdf")
        alert_sent = alerter.send_alert(findings, run_id, pdf_path)
        if not alert_sent and cfg["alerting"].get("email_enabled", "false") == "true":
            logger.info("  → No alert sent (no findings met the severity threshold).")

        # Finalise
        elapsed = (datetime.now(tz=timezone.utc) - started_at).total_seconds()
        baseline.finish_scan(run_id, len(findings))

        logger.info("=" * 70)
        logger.info(f"SCAN COMPLETE | Duration: {elapsed:.1f}s | Findings: {len(findings)}")
        logger.info("=" * 70)

        return {
            "success":      True,
            "run_id":       run_id,
            "findings":     findings,
            "findings_count": len(findings),
            "report_paths": report_paths,
            "elapsed_sec":  elapsed,
            "stats":        counts,
        }

    except Exception as e:
        logger.exception(f"Unexpected error during scan: {e}")
        baseline.fail_scan(run_id, str(e))
        return {"success": False, "error": str(e), "run_id": run_id}

    finally:
        collector.disconnect()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_test_connection(cfg: configparser.ConfigParser):
    from modules.ldap_collector import LDAPCollector
    print("\n🔌 Testing LDAP connection...")
    collector = LDAPCollector(dict(cfg["ldap"]))
    result = collector.test_connection()
    if result["success"]:
        info = result.get("domain_info", {})
        print(f"✅ Connection successful!")
        print(f"   Domain : {info.get('name') or info.get('base_dn', 'N/A')}")
        print(f"   Server : {info.get('server', 'N/A')}")
    else:
        print(f"❌ Connection failed: {result.get('error')}")
    print()


def cmd_report_only(cfg: configparser.ConfigParser):
    from modules.baseline_engine import BaselineEngine
    from modules.report_generator import ReportManager

    db_path = cfg["database"].get("db_path", "./ad_baseline.db")
    baseline = BaselineEngine(db_path)
    run_id = baseline.get_last_successful_run_id()

    if not run_id:
        print("❌ No previous successful scan found. Run a scan first.")
        sys.exit(1)

    findings = baseline.get_findings_for_run(run_id)
    reporter = ReportManager(dict(cfg["reporting"]))
    paths = reporter.generate_all(findings=findings, run_id=run_id)

    print(f"\n✅ Reports generated from last scan ({run_id[:16]}...):")
    for fmt, path in paths.items():
        print(f"   {fmt.upper()}: {path}")
    print()


def cmd_show_history(cfg: configparser.ConfigParser):
    from modules.baseline_engine import BaselineEngine
    db_path = cfg["database"].get("db_path", "./ad_baseline.db")
    baseline = BaselineEngine(db_path)
    history = baseline.get_scan_history(limit=10)

    print(f"\n{'Run ID':<38} {'Status':<12} {'Started':<22} {'Findings'}")
    print("-" * 90)
    for h in history:
        rid = h["run_id"][:36]
        status = h.get("status", "?")[:12]
        started = h.get("started_at", "")[:19]
        findings = h.get("findings_count", 0)
        print(f"{rid:<38} {status:<12} {started:<22} {findings}")
    print()


def cmd_daemon(cfg: configparser.ConfigParser):
    """Run continuously, scanning on the configured interval."""
    interval_hours = float(cfg["scanning"].get("scan_interval_hours", 6))
    interval_sec = interval_hours * 3600

    logger.info(f"Daemon mode: scanning every {interval_hours} hours.")
    while True:
        try:
            run_scan(cfg)
        except Exception as e:
            logger.exception(f"Daemon scan error: {e}")

        next_run = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"Next scan in {interval_hours} hours. Sleeping...")
        time.sleep(interval_sec)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AD Security Continuous Assessment Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          Run a single scan
  python main.py --test-connection        Test LDAP connection only
  python main.py --report-only            Regenerate report from last scan
  python main.py --history                Show recent scan history
  python main.py --daemon                 Run continuously on schedule
  python main.py --config /etc/ad.ini     Use a custom config file
        """,
    )
    parser.add_argument(
        "--config", default="config.ini",
        help="Path to configuration file (default: config.ini)",
    )
    parser.add_argument(
        "--test-connection", action="store_true",
        help="Test LDAP connectivity and exit",
    )
    parser.add_argument(
        "--report-only", action="store_true",
        help="Generate report from last scan without running a new one",
    )
    parser.add_argument(
        "--history", action="store_true",
        help="Show recent scan history",
    )
    parser.add_argument(
        "--daemon", action="store_true",
        help="Run continuously on the configured schedule",
    )

    args = parser.parse_args()
    cfg = load_config(args.config)

    # Setup logging
    log_cfg = cfg["logging"] if "logging" in cfg else {}
    setup_logging(
        log_file=log_cfg.get("log_file", "./logs/ad_security_engine.log"),
        log_level=log_cfg.get("log_level", "INFO"),
        max_mb=int(log_cfg.get("max_log_size_mb", 10)),
        backup_count=int(log_cfg.get("log_backup_count", 5)),
    )

    print("""
╔══════════════════════════════════════════════════════════════════╗
║        AD Security Continuous Assessment Engine v1.0             ║
║        Low-Privilege | Read-Only | Automated                     ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if args.test_connection:
        cmd_test_connection(cfg)
    elif args.report_only:
        cmd_report_only(cfg)
    elif args.history:
        cmd_show_history(cfg)
    elif args.daemon:
        cmd_daemon(cfg)
    else:
        result = run_scan(cfg)
        if not result["success"]:
            print(f"\n❌ Scan failed: {result.get('error')}")
            sys.exit(1)

        print(f"\n✅ Scan complete in {result['elapsed_sec']:.1f}s")
        print(f"   Findings: {result['findings_count']}")
        for fmt, path in result.get("report_paths", {}).items():
            print(f"   {fmt.upper()} Report: {path}")
        print()


if __name__ == "__main__":
    main()
