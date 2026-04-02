"""
policy_manager.py
-----------------
Manages the finding lifecycle policy stored in policy.json.

Analysts record decisions about specific findings (accepted_risk,
in_remediation, resolved). Policy is applied after findings are assembled
and before reports are generated.
"""

import json
import logging
from datetime import date
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

VALID_STATUSES = {"accepted_risk", "in_remediation", "resolved"}


class PolicyManager:
    """
    Load, save, and apply finding policy from a JSON file.

    File format:
    {
      "KERB-001-STANDARD": {
        "status":   "accepted_risk",
        "reason":   "Legacy service, migration planned Q3",
        "set_by":   "jsmith",
        "set_on":   "2026-03-01",
        "expires":  "2026-09-01"   # or null
      }
    }
    """

    def __init__(self, policy_path: str):
        self.path = Path(policy_path)
        self._policy: dict = self._load()

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not load policy.json: {e}. Starting with empty policy.")
            return {}

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._policy, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save policy.json: {e}")

    # ------------------------------------------------------------------ #
    #  CRUD                                                                #
    # ------------------------------------------------------------------ #

    def get(self, finding_id: str) -> Optional[dict]:
        """Return the policy entry for a finding ID, or None."""
        return self._policy.get(finding_id)

    def set_status(self, finding_id: str, status: str, reason: str,
                   set_by: str = "", expires: Optional[str] = None):
        """Create or replace a policy entry. Raises ValueError for invalid status."""
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}"
            )
        self._policy[finding_id] = {
            "status":  status,
            "reason":  reason,
            "set_by":  set_by,
            "set_on":  date.today().isoformat(),
            "expires": expires,
        }
        self._save()

    def clear(self, finding_id: str):
        """Remove a policy entry. Safe to call even if the ID is not present."""
        if finding_id in self._policy:
            del self._policy[finding_id]
            self._save()

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def check_expiry(self) -> list:
        """
        Remove policy entries whose expiry date has passed.
        Returns list of finding IDs that were removed.
        Logs a warning for each.
        """
        today = date.today().isoformat()
        expired = [
            fid for fid, entry in self._policy.items()
            if entry.get("expires") and entry["expires"] < today
        ]
        for fid in expired:
            logger.warning(
                f"Policy entry for {fid} has expired ({self._policy[fid]['expires']}) "
                "and has been removed. Finding reactivated."
            )
            del self._policy[fid]
        if expired:
            self._save()
        return expired

    def handle_resolved_reappearance(self, current_finding_ids: set) -> list:
        """
        If a finding marked 'resolved' reappears in the current scan, clear
        its policy entry and return its ID. Logs a warning for each.
        """
        cleared = [
            fid for fid, entry in self._policy.items()
            if entry.get("status") == "resolved" and fid in current_finding_ids
        ]
        for fid in cleared:
            logger.warning(
                f"Finding {fid} was marked resolved but has reappeared. "
                "Policy entry cleared — please re-triage."
            )
            del self._policy[fid]
        if cleared:
            self._save()
        return cleared

    def apply_to_findings(self, findings: list) -> tuple:
        """
        Apply policy to a findings list.

        Returns (active_findings, suppressed_findings):
          - active_findings: findings visible in reports.
            'in_remediation' findings have policy_status/policy_reason fields added.
          - suppressed_findings: 'accepted_risk' and 'resolved' findings,
            excluded from the main report body but listed in the audit trail.
        """
        active = []
        suppressed = []
        for f in findings:
            fid = f["finding_id"]
            entry = self._policy.get(fid)
            if entry:
                f = dict(f)  # copy — do not mutate the original
                f["policy_status"] = entry["status"]
                f["policy_reason"] = entry.get("reason", "")
                f["policy_expires"] = entry.get("expires")
                f["policy_set_by"] = entry.get("set_by", "")
                if entry["status"] in ("accepted_risk", "resolved"):
                    suppressed.append(f)
                else:
                    active.append(f)  # in_remediation stays visible
            else:
                active.append(f)
        return active, suppressed

    # ------------------------------------------------------------------ #
    #  Listing                                                             #
    # ------------------------------------------------------------------ #

    def list_all(self) -> list:
        """Return all policy entries as a list of dicts, sorted by finding_id."""
        today = date.today().isoformat()
        result = []
        for fid, entry in self._policy.items():
            item = dict(entry)
            item["finding_id"] = fid
            item["expired"] = bool(entry.get("expires") and entry["expires"] < today)
            result.append(item)
        return sorted(result, key=lambda x: x["finding_id"])
