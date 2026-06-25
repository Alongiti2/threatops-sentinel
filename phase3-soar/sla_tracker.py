"""
SLA Tracker — ThreatOps Sentinel Phase 3 SOAR
Tracks detection-to-closure SLA for every incident with
PagerDuty webhook integration and breach alerting.
"""
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


# SLA targets in minutes by severity
SLA_TARGETS = {
    "critical": {
        "triage": 15,
        "contain": 60,
        "eradicate": 240,
        "recover": 480,
        "close": 1440,
    },
    "high": {
        "triage": 30,
        "contain": 120,
        "eradicate": 480,
        "recover": 1440,
        "close": 2880,
    },
    "medium": {
        "triage": 120,
        "contain": 480,
        "eradicate": 1440,
        "recover": 2880,
        "close": 5760,
    },
    "low": {
        "triage": 480,
        "contain": 1440,
        "eradicate": 2880,
        "recover": 5760,
        "close": 10080,
    },
}


@dataclass
class IncidentRecord:
    incident_id: str
    severity: str
    title: str
    mitre_tactic: str
    mitre_technique: str
    source: str
    detected_at: str
    status: str = IncidentStatus.DETECTED
    triaged_at: Optional[str] = None
    contained_at: Optional[str] = None
    eradicated_at: Optional[str] = None
    recovered_at: Optional[str] = None
    closed_at: Optional[str] = None
    assignee: Optional[str] = None
    sla_breaches: list = field(default_factory=list)
    timeline: list = field(default_factory=list)

    def elapsed_minutes(self, from_time: str = None) -> float:
        start = datetime.fromisoformat(self.detected_at)
        end = datetime.fromisoformat(from_time) if from_time else datetime.now(timezone.utc)
        return (end - start).total_seconds() / 60

    def to_dict(self) -> dict:
        return asdict(self)


class SLATracker:
    def __init__(self, pagerduty_routing_key: str = None,
                 slack_webhook_url: str = None):
        self.incidents: dict[str, IncidentRecord] = {}
        self.pd_key = pagerduty_routing_key
        self.slack_url = slack_webhook_url

    def open_incident(self, incident_id: str, severity: str, title: str,
                      mitre_tactic: str, mitre_technique: str,
                      source: str, assignee: str = None) -> IncidentRecord:
        """Open a new tracked incident and start SLA clock."""
        now = datetime.now(timezone.utc).isoformat()
        record = IncidentRecord(
            incident_id=incident_id,
            severity=severity.lower(),
            title=title,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            source=source,
            detected_at=now,
            assignee=assignee,
            timeline=[{"event": "detected", "timestamp": now, "actor": "ThreatOps-Sentinel"}]
        )
        self.incidents[incident_id] = record
        logger.info(f"[{incident_id}] Incident opened | Severity: {severity} | SLA clock started")

        if self.pd_key:
            self._page_pagerduty(record)
        if self.slack_url:
            self._notify_slack(record, "🚨 New Incident Opened")

        return record

    def advance_status(self, incident_id: str,
                       new_status: IncidentStatus,
                       actor: str = "analyst") -> IncidentRecord:
        """Advance incident status and record SLA checkpoint."""
        record = self.incidents.get(incident_id)
        if not record:
            raise ValueError(f"Incident {incident_id} not found")

        now = datetime.now(timezone.utc).isoformat()
        elapsed = record.elapsed_minutes(now)
        targets = SLA_TARGETS.get(record.severity, SLA_TARGETS["medium"])

        status_to_field = {
            IncidentStatus.TRIAGED: "triaged_at",
            IncidentStatus.CONTAINED: "contained_at",
            IncidentStatus.ERADICATED: "eradicated_at",
            IncidentStatus.RECOVERED: "recovered_at",
            IncidentStatus.CLOSED: "closed_at",
        }
        status_to_target = {
            IncidentStatus.TRIAGED: "triage",
            IncidentStatus.CONTAINED: "contain",
            IncidentStatus.ERADICATED: "eradicate",
            IncidentStatus.RECOVERED: "recover",
            IncidentStatus.CLOSED: "close",
        }

        field_name = status_to_field.get(new_status)
        target_key = status_to_target.get(new_status)

        if field_name:
            setattr(record, field_name, now)

        record.status = new_status
        target_minutes = targets.get(target_key, 9999)
        sla_met = elapsed <= target_minutes

        timeline_entry = {
            "event": new_status,
            "timestamp": now,
            "actor": actor,
            "elapsed_minutes": round(elapsed, 1),
            "sla_target_minutes": target_minutes,
            "sla_met": sla_met,
        }
        record.timeline.append(timeline_entry)

        if not sla_met:
            breach = {
                "checkpoint": new_status,
                "elapsed_minutes": round(elapsed, 1),
                "target_minutes": target_minutes,
                "breach_minutes": round(elapsed - target_minutes, 1),
            }
            record.sla_breaches.append(breach)
            logger.warning(f"[{incident_id}] SLA BREACH at {new_status}: "
                          f"{elapsed:.0f}min elapsed vs {target_minutes}min target")
            if self.slack_url:
                self._notify_slack(record, f"⚠️ SLA Breach: {new_status}")
        else:
            logger.info(f"[{incident_id}] {new_status} — SLA met ({elapsed:.0f}/{target_minutes} min)")

        return record

    def get_status_report(self, incident_id: str) -> dict:
        """Generate full SLA status report for an incident."""
        record = self.incidents.get(incident_id)
        if not record:
            raise ValueError(f"Incident {incident_id} not found")

        elapsed = record.elapsed_minutes()
        targets = SLA_TARGETS.get(record.severity, SLA_TARGETS["medium"])
        close_target = targets["close"]
        time_remaining = close_target - elapsed

        return {
            "incident_id": incident_id,
            "title": record.title,
            "severity": record.severity,
            "status": record.status,
            "mitre": {"tactic": record.mitre_tactic, "technique": record.mitre_technique},
            "assignee": record.assignee,
            "sla": {
                "elapsed_minutes": round(elapsed, 1),
                "close_target_minutes": close_target,
                "time_remaining_minutes": round(time_remaining, 1),
                "on_track": time_remaining > 0,
                "breach_count": len(record.sla_breaches),
                "breaches": record.sla_breaches,
            },
            "timeline": record.timeline,
        }

    def _page_pagerduty(self, record: IncidentRecord) -> None:
        """Fire
