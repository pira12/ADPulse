"""
main.py
-------
ADPulse - AD Security Continuous Assessment Engine
Entry point. Orchestrates collection, detection, baselining, and reporting.

Usage:
    python main.py                     # Run a scan (uses config.ini)
    python main.py --config /path.ini  # Use a specific config file
    python main.py --test-connection   # Test LDAP connectivity only
    python main.py --report-only       # Generate report from last scan (no new scan)
    python main.py --diff              # Show what changed between last two scans
    python main.py --daemon            # Run continuously on a schedule

Run on a domain-joined Windows VM with read access to AD. No service account needed.
"""

import argparse
import configparser
import json
import logging
import logging.handlers
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    config_file = Path(config_path)
    if not config_file.exists():
        print(f"ERROR: Config file not found: {config_path}")
        print("Copy config.ini.example to config.ini and fill in your settings.")
        sys.exit(1)

    # Warn if config file is world-readable (contains credentials)
    try:
        import stat
        mode = config_file.stat().st_mode
        if mode & stat.S_IROTH:
            print(f"WARNING: {config_path} is world-readable. This file contains credentials.")
            print("         Fix with: chmod 600 " + config_path)
            print()
    except (OSError, AttributeError):
        pass  # Skip on Windows or if stat fails

    cfg.read(config_path)
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
#  Core Scan Function
# ─────────────────────────────────────────────────────────────────────────────

def _load_exclusions(cfg: configparser.ConfigParser) -> dict:
    """Load finding exclusions and severity overrides from config."""
    exclusions = {
        "finding_ids": set(),
        "accounts": set(),
        "reason": "",
    }
    if cfg.has_section("exclusions"):
        exc = cfg["exclusions"]
        exclusions["finding_ids"] = {
            fid.strip() for fid in exc.get("finding_ids", "").split(",") if fid.strip()
        }
        exclusions["accounts"] = {
            a.strip().lower() for a in exc.get("accounts", "").split(",") if a.strip()
        }
        exclusions["reason"] = exc.get("reason", "")

    overrides = {}
    if cfg.has_section("severity_overrides"):
        for fid, sev in cfg["severity_overrides"].items():
            overrides[fid.strip().upper()] = sev.strip().upper()

    return {"exclusions": exclusions, "overrides": overrides}


def _apply_exclusions(findings: list, exclusion_cfg: dict) -> list:
    """Filter findings based on exclusion rules and apply severity overrides."""
    exc = exclusion_cfg["exclusions"]
    overrides = exclusion_cfg["overrides"]
    excluded_ids = exc["finding_ids"]
    excluded_accounts = exc["accounts"]

    filtered = []
    for f in findings:
        fid = f.get("finding_id", "")
        # Skip excluded finding IDs
        if fid in excluded_ids:
            logger.debug(f"Excluding finding {fid} (exclusion list)")
            continue

        # Remove excluded accounts from affected lists
        if excluded_accounts and f.get("affected"):
            f["affected"] = [
                a for a in f["affected"]
                if not any(exc_acct in str(a).lower() for exc_acct in excluded_accounts)
            ]
            # If all affected objects were excluded, skip the finding
            if not f["affected"]:
                logger.debug(f"Excluding finding {fid} (all affected objects excluded)")
                continue

        # Apply severity overrides
        if fid in overrides:
            old_sev = f["severity"]
            f["severity"] = overrides[fid]
            logger.debug(f"Severity override: {fid} {old_sev} -> {f['severity']}")

        filtered.append(f)

    if len(filtered) < len(findings):
        logger.info(f"Exclusions applied: {len(findings) - len(filtered)} finding(s) excluded.")

    return filtered


def _get_ldap_configs(cfg: configparser.ConfigParser) -> list:
    """Get all LDAP configurations (primary + additional domains)."""
    configs = [dict(cfg["ldap"])]
    # Check for additional domains: [ldap.2], [ldap.3], etc.
    for section in cfg.sections():
        if section.startswith("ldap.") and section != "ldap":
            configs.append(dict(cfg[section]))
    return configs


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


def run_scan(cfg: configparser.ConfigParser) -> dict:
    """
    Execute a complete AD security scan (supports multi-domain).
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
    scanning_cfg  = dict(cfg["scanning"])
    reporting_cfg = dict(cfg["reporting"])
    output_cfg    = dict(cfg["output"]) if cfg.has_section("output") else {}
    db_path       = cfg["database"].get("db_path", "./ad_baseline.db")

    baseline  = BaselineEngine(db_path)
    detector  = DetectionEngine(scanning_cfg)
    reporter  = ReportManager(reporting_cfg)
    notifier  = OutputNotifier(reporting_cfg, output_cfg)

    # Load exclusions and severity overrides
    exclusion_cfg = _load_exclusions(cfg)

    # DB retention cleanup
    retention_days = int(cfg["database"].get("retention_days", 0))
    if retention_days > 0:
        baseline.cleanup_old_scans(retention_days)

    # Record scan start
    baseline.start_scan(run_id)

    # Get all LDAP configs (multi-domain support)
    ldap_configs = _get_ldap_configs(cfg)
    all_ad_data = []

    for i, ldap_cfg in enumerate(ldap_configs):
        domain_label = ldap_cfg.get("domain", f"domain-{i+1}")

        # ── Step 1: Connect to AD ────────────────────────────────────────
        logger.info(f"Step 1/6: Connecting to Active Directory ({domain_label})...")
        collector = LDAPCollector(ldap_cfg)
        if not collector.connect():
            error_msg = f"Failed to connect to {domain_label}. Check server settings and AD access."
            logger.error(error_msg)
            if i == 0:  # Fail on primary domain
                baseline.fail_scan(run_id, error_msg)
                return {"success": False, "error": error_msg, "run_id": run_id}
            else:
                logger.warning(f"Skipping additional domain {domain_label}")
                continue

        try:
            # ── Step 2: Collect AD Data ──────────────────────────────────
            logger.info(f"Step 2/6: Collecting AD data from {domain_label}...")

            ad_data = _collect_ad_data(collector, scanning_cfg)
            ad_data["_domain_label"] = domain_label

            logger.info(
                f"  → Users: {len(ad_data.get('users', []))} | "
                f"Computers: {len(ad_data.get('computers', []))} | "
                f"DCs: {len(ad_data.get('domain_controllers', []))} | "
                f"Kerberoastable: {len(ad_data.get('kerberoastable', []))} | "
                f"AS-REP: {len(ad_data.get('asreproastable', []))}"
            )
            all_ad_data.append(ad_data)

        except Exception as e:
            logger.exception(f"Error collecting data from {domain_label}: {e}")
        finally:
            collector.disconnect()

    if not all_ad_data:
        baseline.fail_scan(run_id, "No AD data collected from any domain.")
        return {"success": False, "error": "No data collected", "run_id": run_id}

    try:
        # Use primary domain data for baseline/reports; merge findings from all
        primary = all_ad_data[0]

        # ── Step 3: Store Baseline ───────────────────────────────────────
        logger.info("Step 3/6: Updating baseline database...")
        previous_run_id = baseline.get_last_successful_run_id()

        baseline.save_users(run_id, primary["users"])
        baseline.save_group_members(run_id, primary["privileged_members"])

        if previous_run_id:
            logger.info(f"  → Previous scan found: {previous_run_id[:16]}... (delta detection enabled)")
        else:
            logger.info("  → No previous baseline. First scan — delta detections next time.")

        # ── Step 4: Run Detections ───────────────────────────────────────
        logger.info("Step 4/6: Running security detections...")
        all_findings = []
        for ad_data in all_ad_data:
            domain_findings = detector.run_all_detections(
                ad_data=ad_data,
                baseline=baseline if previous_run_id else None,
                previous_run_id=previous_run_id,
            )
            # Tag findings with domain for multi-domain
            if len(all_ad_data) > 1:
                domain_label = ad_data.get("_domain_label", "")
                for f in domain_findings:
                    f["finding_id"] = f"{f['finding_id']}@{domain_label}"
                    f["title"] = f"[{domain_label}] {f['title']}"
            all_findings.extend(domain_findings)

        # Apply exclusions and severity overrides
        all_findings = _apply_exclusions(all_findings, exclusion_cfg)

        # Attach first_seen/is_new fields
        for f in all_findings:
            f.setdefault("first_seen", datetime.now(tz=timezone.utc).isoformat())
            f.setdefault("is_new", 1)

        baseline.save_findings(run_id, all_findings)
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
            domain_info=primary.get("domain_info"),
            baseline=baseline,
        )
        for fmt, path in report_paths.items():
            logger.info(f"  → {fmt.upper()} report: {path}")

        # ── Step 6: Output Summary & Notifications ────────────────────────
        logger.info("Step 6/6: Generating output summary...")
        notifier.notify(
            findings=findings,
            run_id=run_id,
            report_paths=report_paths,
            domain_info=primary.get("domain_info"),
        )

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


def cmd_diff(cfg: configparser.ConfigParser):
    """Show what changed between the last two scans."""
    from modules.baseline_engine import BaselineEngine
    db_path = cfg["database"].get("db_path", "./ad_baseline.db")
    baseline = BaselineEngine(db_path)
    diff = baseline.get_finding_diff()

    if not diff:
        print("\n  Need at least 2 completed scans to show a diff.")
        return

    print(f"\n  Finding Diff: {diff['current_run'][:16]}... vs {diff['previous_run'][:16]}...")
    print(f"  {'='*60}")

    if diff["new"]:
        print(f"\n  NEW FINDINGS ({len(diff['new'])})")
        print(f"  {'-'*40}")
        for f in diff["new"]:
            print(f"  [+] [{f['severity']}] {f['title']}")

    if diff["resolved"]:
        print(f"\n  RESOLVED FINDINGS ({len(diff['resolved'])})")
        print(f"  {'-'*40}")
        for f in diff["resolved"]:
            print(f"  [-] [{f['severity']}] {f['title']}")

    if diff["persistent"]:
        print(f"\n  PERSISTENT FINDINGS ({len(diff['persistent'])})")
        print(f"  {'-'*40}")
        for f in diff["persistent"]:
            print(f"  [=] [{f['severity']}] {f['title']}")

    if not diff["new"] and not diff["resolved"]:
        print("\n  No changes between scans.")
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
    parser.add_argument(
        "--diff", action="store_true",
        help="Show what changed between the last two scans",
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
║        Integrated Auth | Read-Only | Automated                   ║
╚══════════════════════════════════════════════════════════════════╝
""")

    if args.test_connection:
        cmd_test_connection(cfg)
    elif args.report_only:
        cmd_report_only(cfg)
    elif args.history:
        cmd_show_history(cfg)
    elif args.diff:
        cmd_diff(cfg)
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
