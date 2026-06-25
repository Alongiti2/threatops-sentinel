"""
MITRE ATT&CK Mapper — ThreatOps Sentinel Phase 2
Enriches normalized events with ATT&CK tactic, technique, and severity score.
"""
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AttackTag:
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    subtechnique: Optional[str] = None
    subtechnique_id: Optional[str] = None
    severity: str = "medium"
    confidence: float = 0.8


# Master ATT&CK mapping table
ATTACK_MAPPINGS: dict[str, AttackTag] = {
    # Initial Access
    "ConsoleLogin":                 AttackTag("Initial Access", "TA0001", "Valid Accounts", "T1078", severity="high", confidence=0.7),
    "UnauthorizedAccess:IAMUser":   AttackTag("Initial Access", "TA0001", "Valid Accounts", "T1078", severity="high"),
    "Recon:EC2/Portscan":           AttackTag("Discovery", "TA0007", "Network Service Discovery", "T1046", severity="medium"),

    # Execution
    "execve":                       AttackTag("Execution", "TA0002", "Command and Scripting Interpreter", "T1059", "Unix Shell", "T1059.004", severity="high"),
    "fork":                         AttackTag("Execution", "TA0002", "Command and Scripting Interpreter", "T1059", severity="low", confidence=0.5),

    # Persistence
    "PutUserPolicy":                AttackTag("Persistence", "TA0003", "Account Manipulation", "T1098", severity="high"),
    "CreateAccessKey":              AttackTag("Persistence", "TA0003", "Account Manipulation", "T1098", "Additional Cloud Credentials", "T1098.001", severity="high"),
    "cron":                         AttackTag("Persistence", "TA0003", "Scheduled Task/Job", "T1053", "Cron", "T1053.003", severity="medium"),

    # Privilege Escalation
    "setuid":                       AttackTag("Privilege Escalation", "TA0004", "Abuse Elevation Control", "T1548", "Setuid/Setgid", "T1548.001", severity="high"),
    "PrivilegeEscalation:IAMUser":  AttackTag("Privilege Escalation", "TA0004", "Abuse Elevation Control", "T1548", severity="critical"),

    # Defense Evasion
    "StopLogging":                  AttackTag("Defense Evasion", "TA0005", "Impair Defenses", "T1562", "Disable Cloud Logs", "T1562.008", severity="critical"),
    "DeleteTrail":                  AttackTag("Defense Evasion", "TA0005", "Impair Defenses", "T1562", "Disable Cloud Logs", "T1562.008", severity="critical"),
    "unlink":                       AttackTag("Defense Evasion", "TA0005", "Indicator Removal", "T1070", severity="medium"),

    # Credential Access
    "ptrace":                       AttackTag("Credential Access", "TA0006", "OS Credential Dumping", "T1003", severity="high"),
    "UnauthorizedAccess:EC2/SSHBruteForce": AttackTag("Credential Access", "TA0006", "Brute Force", "T1110", "Password Spraying", "T1110.003", severity="high"),

    # Discovery
    "DescribeInstances":            AttackTag("Discovery", "TA0007", "Cloud Infrastructure Discovery", "T1580", severity="low", confidence=0.5),
    "ListBuckets":                  AttackTag("Discovery", "TA0007", "Cloud Storage Object Discovery", "T1619", severity="low"),

    # Lateral Movement
    "Backdoor:EC2/C&CActivity.B":  AttackTag("Command and Control", "TA0011", "Application Layer Protocol", "T1071", severity="critical"),

    # Collection
    "GetObject":                    AttackTag("Collection", "TA0009", "Data from Cloud Storage", "T1530", severity="medium", confidence=0.4),

    # Exfiltration
    "Exfiltration:S3/ObjectRead":   AttackTag("Exfiltration", "TA0010", "Transfer Data to Cloud Account", "T1537", severity="critical"),

    # Impact
    "DeleteBucket":                 AttackTag("Impact", "TA0040", "Data Destruction", "T1485", severity="critical"),
    "TerminateInstances":           AttackTag("Impact", "TA0040", "Service Stop", "T1489", severity="high"),
}

SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 1}


class MitreMapper:
    def __init__(self, custom_mappings: dict = None):
        self.mappings = {**ATTACK_MAPPINGS, **(custom_mappings or {})}

    def _find_tag(self, event: dict) -> Optional[AttackTag]:
        """Match event against mappings using action, rule name, or syscall."""
        candidates = [
            event.get("event.action", ""),
            event.get("rule.name", ""),
            event.get("syscall", ""),
        ]
        for key in candidates:
            if key in self.mappings:
                return self.mappings[key]
            # Partial match for prefixed finding types
            for mapping_key, tag in self.mappings.items():
                if key.startswith(mapping_key) or mapping_key.startswith(key):
                    return tag
        return None

    def enrich(self, event: dict) -> dict:
        """Add MITRE ATT&CK fields and risk score to an event."""
        tag = self._find_tag(event)
        if tag:
            event["mitre.tactic"] = tag.tactic
            event["mitre.tactic_id"] = tag.tactic_id
            event["mitre.technique"] = tag.technique
            event["mitre.technique_id"] = tag.technique_id
            event["mitre.confidence"] = tag.confidence
            event["risk.severity"] = tag.severity
            event["risk.score"] = SEVERITY_SCORE.get(tag.severity, 0)
            event["alert"] = True
            if tag.subtechnique:
                event["mitre.subtechnique"] = tag.subtechnique
                event["mitre.subtechnique_id"] = tag.subtechnique_id
        else:
            event["alert"] = False
            event["risk.score"] = 0
            event["risk.severity"] = "informational"
        return event

    def enrich_batch(self, events: list) -> list:
        enriched = [self.enrich(e) for e in events]
        alerts = [e for e in enriched if e.get("alert")]
        logger.info(f"Enriched {len(enriched)} events | {len(alerts)} ATT&CK matches")
        return enriched

    def summary(self, events: list) -> dict:
        """Return tactic frequency summary for dashboard/reporting."""
        tactics: dict[str, int] = {}
        for e in events:
            t = e.get("mitre.tactic")
            if t:
                tactics[t] = tactics.get(t, 0) + 1
        return dict(sorted(tactics.items(), key=lambda x: x[1], reverse=True))


if __name__ == "__main__":
    sample_events = [
        {"event.action": "ConsoleLogin", "source": "cloudtrail", "user.name": "admin"},
        {"event.action": "StopLogging", "source": "cloudtrail", "user.name": "svc-account"},
        {"syscall": "ptrace", "source": "auditd", "comm": "gdb"},
        {"rule.name": "Recon:EC2/Portscan", "source": "guardduty"},
        {"event.action": "ListBuckets", "source": "cloudtrail"},
    ]
    mapper = MitreMapper()
    results = mapper.enrich_batch(sample_events)
    print(json.dumps(results, indent=2))
    print("\nTactic Summary:", mapper.summary(results))
