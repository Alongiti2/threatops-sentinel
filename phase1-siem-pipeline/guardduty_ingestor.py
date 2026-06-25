"""
GuardDuty Finding Ingestor — ThreatOps Sentinel Phase 1
Polls GuardDuty findings, normalizes severity, maps to MITRE ATT&CK.
"""
import boto3
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MITRE ATT&CK mapping for common GuardDuty finding types
GUARDDUTY_ATTACK_MAP = {
    "Recon:EC2/Portscan": {"tactic": "Discovery", "technique": "T1046"},
    "UnauthorizedAccess:EC2/SSHBruteForce": {"tactic": "Credential Access", "technique": "T1110"},
    "Trojan:EC2/BlackholeTraffic": {"tactic": "Command and Control", "technique": "T1071"},
    "Backdoor:EC2/C&CActivity.B": {"tactic": "Command and Control", "technique": "T1071"},
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller": {"tactic": "Initial Access", "technique": "T1078"},
    "Persistence:IAMUser/UserPermissions": {"tactic": "Persistence", "technique": "T1098"},
    "PrivilegeEscalation:IAMUser/AdministrativePermissions": {"tactic": "Privilege Escalation", "technique": "T1548"},
    "Exfiltration:S3/ObjectRead.Unusual": {"tactic": "Exfiltration", "technique": "T1537"},
    "DefenseEvasion:CloudTrailLoggingDisabled": {"tactic": "Defense Evasion", "technique": "T1070"},
}

SEVERITY_MAP = {
    "critical": (8.0, 10.0),
    "high": (7.0, 7.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
}

class GuardDutyIngestor:
    def __init__(self, region: str = "us-east-1", detector_id: str = None):
        self.gd = boto3.client("guardduty", region_name=region)
        self.detector_id = detector_id or self._get_detector_id()

    def _get_detector_id(self) -> str:
        """Auto-discover the GuardDuty detector ID."""
        detectors = self.gd.list_detectors()["DetectorIds"]
        if not detectors:
            raise RuntimeError("No GuardDuty detector found in this region")
        return detectors[0]

    def _classify_severity(self, score: float) -> str:
        for label, (low, high) in SEVERITY_MAP.items():
            if low <= score <= high:
                return label
        return "informational"

    def get_findings(self, max_results: int = 50) -> list:
        """Fetch active GuardDuty findings."""
        finding_ids = self.gd.list_findings(
            DetectorId=self.detector_id,
            FindingCriteria={
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                    "severity": {"Gte": 4},
                }
            },
            MaxResults=max_results,
        )["FindingIds"]

        if not finding_ids:
            logger.info("No active findings")
            return []

        raw = self.gd.get_findings(
            DetectorId=self.detector_id,
            FindingIds=finding_ids,
        )["Findings"]

        return [self._normalize(f) for f in raw]

    def _normalize(self, finding: dict) -> dict:
        """Normalize GuardDuty finding to ECS + ATT&CK enrichment."""
        finding_type = finding.get("Type", "")
        attack_info = GUARDDUTY_ATTACK_MAP.get(finding_type, {
            "tactic": "Unknown", "technique": "Unknown"
        })
        severity_score = finding.get("Severity", 0)

        return {
            "timestamp": finding.get("UpdatedAt"),
            "source": "guardduty",
            "event.id": finding.get("Id"),
            "event.kind": "alert",
            "rule.name": finding_type,
            "rule.description": finding.get("Description", ""),
            "severity.score": severity_score,
            "severity.label": self._classify_severity(severity_score),
            "mitre.tactic": attack_info["tactic"],
            "mitre.technique": attack_info["technique"],
            "aws.region": finding.get("Region"),
            "aws.account_id": finding.get("AccountId"),
            "resource.type": finding.get("Resource", {}).get("ResourceType"),
            "resource.id": finding.get("Resource", {}).get(
                "InstanceDetails", {}
            ).get("InstanceId", "N/A"),
            "raw": finding,
        }

    def ingest(self) -> list:
        findings = self.get_findings()
        logger.info(f"Ingested {len(findings)} GuardDuty findings")
        return findings


if __name__ == "__main__":
    ingestor = GuardDutyIngestor()
    findings = ingestor.ingest()
    print(json.dumps(findings[:2], indent=2, default=str))
