"""
baseline_engine.py
------------------
Manages the SQLite baseline database.
Stores snapshots of AD objects and detects drift between scans.

No admin rights needed - this only reads from AD and writes to a local DB file.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class BaselineEngine:
    """
    Manages the AD security baseline stored in SQLite.

    Tables:
      - snapshots       : Records of each scan run
      - group_members   : Current membership of monitored groups
      - user_objects    : Key attributes of all user accounts
      - computer_objects: Key attributes of all computer accounts
      - findings_history: Every finding ever raised (for trend tracking)
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------ #
    #  DB Initialisation                                                   #
    # ------------------------------------------------------------------ #

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id      TEXT NOT NULL UNIQUE,
                    started_at  TEXT NOT NULL,
                    finished_at TEXT,
                    status      TEXT DEFAULT 'running',
                    findings_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS group_members (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id      TEXT NOT NULL,
                    group_name  TEXT NOT NULL,
                    member_dn   TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_objects (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id              TEXT NOT NULL,
                    sam_account_name    TEXT NOT NULL,
                    display_name        TEXT,
                    enabled             INTEGER,
                    admin_count         INTEGER,
                    pwd_last_set        TEXT,
                    last_logon          TEXT,
                    has_spn             INTEGER DEFAULT 0,
                    no_preauth          INTEGER DEFAULT 0,
                    pwd_never_expires   INTEGER DEFAULT 0,
                    unconstrained_deleg INTEGER DEFAULT 0,
                    distinguished_name  TEXT,
                    recorded_at         TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS computer_objects (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id              TEXT NOT NULL,
                    sam_account_name    TEXT NOT NULL,
                    dns_hostname        TEXT,
                    os                  TEXT,
                    os_version          TEXT,
                    last_logon          TEXT,
                    enabled             INTEGER,
                    distinguished_name  TEXT,
                    recorded_at         TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id      TEXT NOT NULL,
                    finding_id  TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    description TEXT,
                    affected    TEXT,
                    details     TEXT,
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    is_new      INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_group_members_run ON group_members(run_id);
                CREATE INDEX IF NOT EXISTS idx_users_run ON user_objects(run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_run ON findings_history(run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_id ON findings_history(finding_id);
            """)
        logger.debug(f"Database initialised at {self.db_path}")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------ #
    #  Snapshot Lifecycle                                                  #
    # ------------------------------------------------------------------ #

    def start_scan(self, run_id: str):
        """Record the start of a new scan."""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO snapshots (run_id, started_at, status) VALUES (?, ?, 'running')",
                (run_id, _now_iso()),
            )
        logger.info(f"Scan started: {run_id}")

    def finish_scan(self, run_id: str, findings_count: int):
        """Mark a scan as complete."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE snapshots SET finished_at=?, status='completed', findings_count=? WHERE run_id=?",
                (_now_iso(), findings_count, run_id),
            )
        logger.info(f"Scan finished: {run_id} | Findings: {findings_count}")

    def fail_scan(self, run_id: str, error: str):
        """Mark a scan as failed."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE snapshots SET finished_at=?, status=? WHERE run_id=?",
                (_now_iso(), f"failed: {error}", run_id),
            )

    def get_last_successful_run_id(self) -> Optional[str]:
        """Return the run_id of the most recent successful scan."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT run_id FROM snapshots WHERE status='completed' ORDER BY finished_at DESC LIMIT 1"
            ).fetchone()
        return row["run_id"] if row else None

    def get_scan_history(self, limit: int = 30) -> list:
        """Return recent scan history."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM snapshots ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  Group Membership Storage & Delta                                    #
    # ------------------------------------------------------------------ #

    def save_group_members(self, run_id: str, group_members: dict):
        """
        Store current group membership snapshot.
        group_members: {group_name: [member_dn, ...]}
        """
        now = _now_iso()
        rows = []
        for group_name, members in group_members.items():
            for member_dn in members:
                rows.append((run_id, group_name, member_dn, now))

        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO group_members (run_id, group_name, member_dn, recorded_at) VALUES (?,?,?,?)",
                rows,
            )
        logger.debug(f"Saved group membership for {len(group_members)} groups.")

    def get_group_member_delta(self, current_members: dict, previous_run_id: str) -> dict:
        """
        Compare current group membership against the previous snapshot.
        Returns: {group_name: {added: [...], removed: [...]}}
        """
        delta = {}
        with self._conn() as conn:
            for group_name, current_dns in current_members.items():
                rows = conn.execute(
                    "SELECT member_dn FROM group_members WHERE run_id=? AND group_name=?",
                    (previous_run_id, group_name),
                ).fetchall()
                previous_dns = {r["member_dn"] for r in rows}
                current_set = set(current_dns)

                added = list(current_set - previous_dns)
                removed = list(previous_dns - current_set)

                if added or removed:
                    delta[group_name] = {"added": added, "removed": removed}

        return delta

    # ------------------------------------------------------------------ #
    #  User Objects Storage & Delta                                        #
    # ------------------------------------------------------------------ #

    def save_users(self, run_id: str, users: list):
        """Store user account data for baseline."""
        now = _now_iso()
        rows = []
        for u in users:
            uac = u.get("userAccountControl") or 0
            if isinstance(uac, list):
                uac = uac[0] if uac else 0
            try:
                uac = int(uac)
            except (TypeError, ValueError):
                uac = 0

            enabled = 1 if not (uac & 0x2) else 0
            no_preauth = 1 if (uac & 0x400000) else 0
            pwd_never_exp = 1 if (uac & 0x10000) else 0
            unconstrained = 1 if (uac & 0x80000) else 0
            has_spn = 1 if u.get("servicePrincipalName") else 0
            admin_count = u.get("adminCount") or 0

            rows.append((
                run_id,
                str(u.get("sAMAccountName") or ""),
                str(u.get("displayName") or ""),
                enabled,
                int(admin_count),
                str(u.get("pwdLastSet") or ""),
                str(u.get("lastLogonTimestamp") or ""),
                has_spn,
                no_preauth,
                pwd_never_exp,
                unconstrained,
                str(u.get("dn") or u.get("distinguishedName") or ""),
                now,
            ))

        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO user_objects
                   (run_id, sam_account_name, display_name, enabled, admin_count,
                    pwd_last_set, last_logon, has_spn, no_preauth, pwd_never_expires,
                    unconstrained_deleg, distinguished_name, recorded_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
        logger.debug(f"Saved {len(rows)} user objects.")

    def get_new_users(self, run_id: str, previous_run_id: str) -> list:
        """Return accounts that exist in current run but not in previous."""
        with self._conn() as conn:
            current = {
                r["sam_account_name"]
                for r in conn.execute(
                    "SELECT sam_account_name FROM user_objects WHERE run_id=?", (run_id,)
                ).fetchall()
            }
            previous = {
                r["sam_account_name"]
                for r in conn.execute(
                    "SELECT sam_account_name FROM user_objects WHERE run_id=?", (previous_run_id,)
                ).fetchall()
            }
        return list(current - previous)

    def get_removed_users(self, run_id: str, previous_run_id: str) -> list:
        """Return accounts that existed previously but no longer exist."""
        with self._conn() as conn:
            current = {
                r["sam_account_name"]
                for r in conn.execute(
                    "SELECT sam_account_name FROM user_objects WHERE run_id=?", (run_id,)
                ).fetchall()
            }
            previous = {
                r["sam_account_name"]
                for r in conn.execute(
                    "SELECT sam_account_name FROM user_objects WHERE run_id=?", (previous_run_id,)
                ).fetchall()
            }
        return list(previous - current)

    # ------------------------------------------------------------------ #
    #  Findings Storage                                                    #
    # ------------------------------------------------------------------ #

    def save_findings(self, run_id: str, findings: list):
        """Persist findings and mark them as new vs recurring."""
        now = _now_iso()
        with self._conn() as conn:
            for f in findings:
                # Check if this exact finding existed in a previous scan
                existing = conn.execute(
                    "SELECT first_seen FROM findings_history WHERE finding_id=? ORDER BY last_seen DESC LIMIT 1",
                    (f["finding_id"],),
                ).fetchone()

                first_seen = existing["first_seen"] if existing else now
                is_new = 0 if existing else 1

                conn.execute(
                    """INSERT INTO findings_history
                       (run_id, finding_id, category, severity, title, description,
                        affected, details, first_seen, last_seen, is_new)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        run_id,
                        f["finding_id"],
                        f["category"],
                        f["severity"],
                        f["title"],
                        f.get("description", ""),
                        json.dumps(f.get("affected", [])),
                        json.dumps(f.get("details", {})),
                        first_seen,
                        now,
                        is_new,
                    ),
                )
        logger.info(f"Saved {len(findings)} findings to database.")

    def get_findings_for_run(self, run_id: str) -> list:
        """Retrieve all findings for a specific run."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings_history WHERE run_id=? ORDER BY severity DESC",
                (run_id,),
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["affected"] = json.loads(d.get("affected") or "[]")
            d["details"] = json.loads(d.get("details") or "{}")
            results.append(d)
        return results

    def get_finding_trend(self, finding_id: str, limit: int = 10) -> list:
        """Get historical occurrences of a specific finding."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT run_id, last_seen, is_new FROM findings_history WHERE finding_id=? ORDER BY last_seen DESC LIMIT ?",
                (finding_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_findings_summary(self, limit: int = 5) -> list:
        """Get aggregated findings across recent scans."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT finding_id, title, category, severity, COUNT(*) as occurrences,
                          MIN(first_seen) as first_seen, MAX(last_seen) as last_seen
                   FROM findings_history
                   GROUP BY finding_id
                   ORDER BY severity DESC, occurrences DESC
                   LIMIT ?""",
                (limit * 10,),
            ).fetchall()
        return [dict(r) for r in rows]
