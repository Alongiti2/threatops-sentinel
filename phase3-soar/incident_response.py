"""
Incident Response Orchestrator — ThreatOps Sentinel Phase 3 SOAR
Ties together EC2 isolation, IAM key revocation, and SLA tracking
into a single automated incident response pipeline.
"""
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PlaybookResult:
    playbook: str
    status: str
    duration_seconds: float
    output: dict
    error: str = None


@dataclass
class IncidentResponseReport:
    incident_id: str
    severity: str
    title: str
    triggered_at: str
    completed_at: str = None
    total_duration_seconds: float = 0
    playbooks_executed: list = field(default_factory=list)
    overall_status: str = "IN_PROGRESS"
    sla_report: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "title": self.title,
            "triggered_at": self.triggered_at,
            "completed_at": self.completed_at,
            "total_duration_seconds": round(self.total_duration_seconds, 2),
            "overall_status": self.overall_status,
            "playbooks_executed": self.playbooks_executed,
            "sla_report": self.sla_report,
            "recommendations": self.recommendations,
        }


class IncidentResponseOrchestrator:
    """
    Orchestrates automated incident response playbooks based on
    alert type, severity, and affected resource type.
    """

    PLAYBOOK_MATRIX = {
        # (mitre_tactic, resource_type): [playbooks to run]
        ("Defense Evasion", "cloudtrail"): ["notify", "sla_open", "escalate"],
        ("Credential Access", "iam"): ["revoke_iam_keys", "sla_open", "notify"],
        ("Initial Access", "ec2"): ["isolate_ec2", "sla_open", "notify"],
        ("Privilege Escalation", "iam"): ["revoke_iam_keys", "isolate_ec2", "sla_open"],
        ("Exfiltration", "s3"): ["block_s3_access", "sla_open", "notify", "escalate"],
        ("Command and Control", "ec2"): ["isolate_ec2", "sla_open", "notify"],
        ("Lateral Movement", "ec2"): ["isolate_ec2", "sla_open", "escalate"],
        ("Impact", "ec2"): ["isolate_ec2", "sla_open", "escalate"],
    }

    def __init__(self, dry_run: bool = True,
                 pagerduty_key: str = None,
                 slack_webhook: str = None):
        self.dry_run = dry_run
        self.pd_key = pagerduty_key
        self.slack_url = slack_webhook
        logger.info(f"Orchestrator initialized | dry_run={dry_run}")

    def _determine_playbooks(self, alert: dict) -> list:
        """Select playbooks based on MITRE tactic + resource type."""
        tactic = alert.get("mitre.tactic", "")
        resource = alert.get("resource.type", "unknown").lower()

        for (t, r), playbooks in self.PLAYBOOK_MATRIX.items():
            if t.lower() in tactic.lower() and r in resource:
                logger.info(f"Matched playbook set: {playbooks}")
                return playbooks

        # Default: notify + open SLA for anything unmatched
        logger.info("No specific playbook match — using default response")
        return ["notify", "sla_open"]

    def _run_playbook(self, name: str, alert: dict,
                      incident_id: str) -> PlaybookResult:
        """Execute a single playbook step."""
        start = datetime.now(timezone.utc)

        try:
            if name == "isolate_ec2":
                result = self._playbook_isolate_ec2(alert, incident_id)
            elif name == "revoke_iam_keys":
                result = self._playbook_revoke_iam(alert, incident_id)
            elif name == "sla_open":
                result = self._playbook_open_sla(alert, incident_id)
            elif name == "notify":
                result = self._playbook_notify(alert, incident_id)
            elif name == "escalate":
                result = self._playbook_escalate(alert, incident_id)
            else:
                result = {"status": "skipped", "reason": f"Unknown playbook: {name}"}

            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            return PlaybookResult(playbook=name, status="SUCCESS",
                                  duration_seconds=elapsed, output=result)

        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            logger.error(f"Playbook {name} failed: {e}")
            return PlaybookResult(playbook=name, status="FAILED",
                                  duration_seconds=elapsed, output={}, error=str(e))

    def _playbook_isolate_ec2(self, alert: dict, incident_id: str) -> dict:
        instance_id = alert.get("resource.id", "i-unknown")
        if self.dry_run:
            logger.info(f"[DRY RUN] Would isolate EC2: {instance_id}")
            return {"action": "isolate_ec2", "instance_id": instance_id,
                    "dry_run": True, "status": "SIMULATED"}
        # In production: from isolate_ec2 import EC2Isolator; EC2Isolator().isolate(...)
        return {"action": "isolate_ec2", "instance_id": instance_id, "status": "ISOLATED"}

    def _playbook_revoke_iam(self, alert: dict, incident_id: str) -> dict:
        username = alert.get("user.name", "unknown")
        if self.dry_run:
            logger.info(f"[DRY RUN] Would revoke IAM keys for: {username}")
            return {"action": "revoke_iam_keys", "username": username,
                    "dry_run": True, "status": "SIMULATED"}
        return {"action": "revoke_iam_keys", "username": username, "status": "REVOKED"}

    def _playbook_open_sla(self, alert: dict, incident_id: str) -> dict:
        severity = alert.get("risk.severity", "medium")
        targets = {
            "critical": {"triage": 15, "contain": 60, "close": 1440},
            "high": {"triage": 30, "contain": 120, "close": 2880},
            "medium": {"triage": 120, "contain": 480, "close": 5760},
            "low": {"triage": 480, "contain": 1440, "close": 10080},
        }
        sla = targets.get(severity, targets["medium"])
        logger.info(f"SLA clock started for {incident_id} | Severity: {severity}")
        return {
            "action": "sla_open",
            "incident_id": incident_id,
            "severity": severity,
            "sla_targets_minutes": sla,
            "clock_started": datetime.now(timezone.utc).isoformat(),
        }

    def
