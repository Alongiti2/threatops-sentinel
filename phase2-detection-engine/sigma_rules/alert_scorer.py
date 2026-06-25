"""
Alert Scorer — ThreatOps Sentinel Phase 2
Risk-scores enriched events using MITRE ATT&CK severity, confidence,
asset criticality, and threat intel context.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Asset criticality multipliers
ASSET_CRITICALITY = {
    "domain_controller": 3.0,
    "database_server": 2.5,
    "web_server": 2.0,
    "bastion_host": 2.0,
    "workstation": 1.0,
    "unknown": 1.2,
}

# Source reliability scores
SOURCE_RELIABILITY = {
    "guardduty": 0.95,
    "cloudtrail": 0.90,
    "auditd": 0.85,
    "vpc_flow": 0.80,
    "unknown": 0.60,
}

TACTIC_WEIGHTS = {
    "Impact": 1.5,
    "Exfiltration": 1.5,
    "Command and Control": 1.3,
    "Credential Access": 1.3,
    "Privilege Escalation": 1.2,
    "Defense Evasion": 1.2,
    "Lateral Movement": 1.1,
    "Persistence": 1.1,
    "Execution": 1.0,
    "Discovery": 0.8,
    "Collection": 0.9,
    "Initial Access": 1.0,
}


@dataclass
class ScoredAlert:
    event_id: str
    timestamp: str
    source: str
    raw_score: float
    final_score: float
    severity: str
    mitre_tactic: str
    mitre_technique: str
    asset_type: str
    asset_criticality: float
    confidence: float
    tactic_weight: float
    triggered_rules: list = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "score": {
                "raw": round(self.raw_score, 2),
                "final": round(self.final_score, 2),
                "severity": self.severity,
            },
            "mitre": {
                "tactic": self.mitre_tactic,
                "technique": self.mitre_technique,
            },
            "asset": {
                "type": self.asset_type,
                "criticality_multiplier": self.asset_criticality,
            },
            "confidence": self.confidence,
            "triggered_rules": self.triggered_rules,
            "recommended_action": self.recommended_action,
        }


class AlertScorer:
    def __init__(self, asset_inventory: dict = None):
        self.asset_inventory = asset_inventory or {}

    def _get_asset_type(self, event: dict) -> str:
        resource_id = event.get("resource.id", event.get("source.ip", ""))
        return self.asset_inventory.get(resource_id, "unknown")

    def _classify_final_score(self, score: float) -> str:
        if score >= 85:
            return "critical"
        elif score >= 65:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 15:
            return "low"
        return "informational"

    def _recommend_action(self, severity: str, tactic: str) -> str:
        if severity == "critical":
            return "IMMEDIATE: Isolate asset, revoke credentials, page on-call SOC"
        elif severity == "high" and tactic in ("Credential Access", "Privilege Escalation"):
            return "URGENT: Force password reset, audit IAM permissions, open P1 incident"
        elif severity == "high":
            return "HIGH: Open P2 incident, assign to on-call analyst within 15 minutes"
        elif severity == "medium":
            return "MEDIUM: Queue for analyst review within 4 hours"
        return "LOW: Log and monitor, review in daily triage"

    def score(self, event: dict) -> Optional[ScoredAlert]:
        if not event.get("alert"):
            return None

        base_score = event.get("risk.score", 0) * 10  # 0–100 scale
        source = event.get("source", "unknown")
        tactic = event.get("mitre.tactic", "Unknown")
        technique = event.get("mitre.technique", "Unknown")
        confidence = event.get("mitre.confidence", 0.7)

        source_reliability = SOURCE_RELIABILITY.get(source, 0.6)
        asset_type = self._get_asset_type(event)
        asset_mult = ASSET_CRITICALITY.get(asset_type, 1.2)
        tactic_weight = TACTIC_WEIGHTS.get(tactic, 1.0)

        final_score = base_score * confidence * source_reliability * asset_mult * tactic_weight
        final_score = min(final_score, 100.0)

        severity = self._classify_final_score(final_score)

        return ScoredAlert(
            event_id=event.get("event.id", f"evt-{hash(str(event)) % 100000:05d}"),
            timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            source=source,
            raw_score=base_score,
            final_score=final_score,
            severity=severity,
            mitre_tactic=tactic,
            mitre_technique=technique,
            asset_type=asset_type,
            asset_criticality=asset_mult,
            confidence=confidence,
            tactic_weight=tactic_weight,
            triggered_rules=[event.get("rule.name", technique)],
            recommended_action=self._recommend_action(severity, tactic),
        )

    def score_batch(self, events: list) -> list:
        scored = [self.score(e) for e in events if e.get("alert")]
        scored = [s for s in scored if s is not None]
        scored.sort(key=lambda x: x.final_score, reverse=True)
        logger.info(f"Scored {len(scored)} alerts | Top score: {scored[0].final_score:.1f}" if scored else "No alerts to score")
        return scored

    def print_summary(self, scored: list) -> None:
        print(f"\n{'='*60}")
        print(f"  THREATOPS SENTINEL — Alert Score Summary")
        print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*60}")
        for alert in scored:
            print(f"\n  [{alert.severity.upper():12}] Score: {alert.final_score:5.1f} | {alert.mitre_tactic}")
            print(f"  Technique : {alert.mitre_technique}")
            print(f"  Source    : {alert.source}")
            print(f"  Action    : {alert.recommended_action}")
        print(f"\n{'='*60}\n")


if __name__ == "__main__":
    sample_events = [
        {"alert": True, "source": "cloudtrail", "risk.score": 10, "mitre.tactic": "Defense Evasion",
         "mitre.technique": "T1562.008", "mitre.confidence": 0.95, "rule.name": "StopLogging"},
        {"alert": True, "source": "guardduty", "risk.score": 7, "mitre.tactic": "Credential Access",
         "mitre.technique": "T1110", "mitre.confidence": 0.9, "rule.name": "SSHBruteForce"},
        {"alert": True, "source": "auditd", "risk.score": 7, "mitre.tactic": "Privilege Escalation",
         "mitre.technique": "T1548", "mitre.confidence": 0.85, "rule.name": "setuid"},
        {"alert": False, "source": "cloudtrail", "risk.score": 0},
    ]

    scorer = AlertScorer(asset_inventory={"i-1234567": "web_server"})
    results = scorer.score_batch(sample_events)
    scorer.print_summary(results)
    print(json.dumps([r.to_dict() for r in results], indent=2))
