"""
IAM Key Revoker — ThreatOps Sentinel Phase 3 SOAR
Immediately deactivates leaked or compromised IAM access keys
and documents the full audit trail for compliance.
"""
import boto3
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IAMKeyRevoker:
    def __init__(self, region: str = "us-east-1"):
        self.iam = boto3.client("iam", region_name=region)
        self.sts = boto3.client("sts", region_name=region)

    def get_caller_identity(self) -> dict:
        return self.sts.get_caller_identity()

    def list_user_keys(self, username: str) -> list:
        """List all access keys for a user with their status."""
        response = self.iam.list_access_keys(UserName=username)
        return response["AccessKeyMetadata"]

    def get_key_last_used(self, access_key_id: str) -> dict:
        """Get last used info for an access key."""
        response = self.iam.get_access_key_last_used(AccessKeyId=access_key_id)
        last_used = response.get("AccessKeyLastUsed", {})
        return {
            "last_used_date": str(last_used.get("LastUsedDate", "Never")),
            "service": last_used.get("ServiceName", "N/A"),
            "region": last_used.get("Region", "N/A"),
        }

    def deactivate_key(self, username: str, access_key_id: str) -> dict:
        """Deactivate a single IAM access key."""
        self.iam.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
        logger.info(f"Deactivated key {access_key_id} for user {username}")
        return {"key_id": access_key_id, "status": "Inactive"}

    def attach_deny_policy(self, username: str, incident_id: str) -> str:
        """Attach an explicit deny-all policy to block the user entirely."""
        policy_name = f"threatops-incident-deny-{incident_id}"
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "ThreatOpsDenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": "*"
                    }
                }
            }]
        }
        self.iam.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(deny_policy),
        )
        logger.info(f"Attached deny-all policy '{policy_name}' to {username}")
        return policy_name

    def revoke_all(self, username: str, incident_id: str = None,
                   attach_deny: bool = True) -> dict:
        """
        Full IAM credential revocation playbook:
        1. List all active keys
        2. Capture last-used metadata
        3. Deactivate all keys
        4. Optionally attach deny-all policy
        5. Return audit record
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        incident_id = incident_id or f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        logger.info(f"[{incident_id}] Starting IAM key revocation for {username}")

        # Step 1 — List all keys
        all_keys = self.list_user_keys(username)
        active_keys = [k for k in all_keys if k["Status"] == "Active"]

        if not active_keys:
            logger.info(f"No active keys found for {username}")

        # Step 2 & 3 — Capture metadata and deactivate
        revoked = []
        for key in active_keys:
            key_id = key["AccessKeyId"]
            last_used = self.get_key_last_used(key_id)
            result = self.deactivate_key(username, key_id)
            revoked.append({
                "key_id": key_id,
                "created": str(key["CreateDate"]),
                "last_used": last_used,
                "action": "deactivated",
            })

        # Step 4 — Deny-all policy
        deny_policy = None
        if attach_deny and active_keys:
            deny_policy = self.attach_deny_policy(username, incident_id)

        audit_record = {
            "playbook": "revoke_iam_keys",
            "incident_id": incident_id,
            "timestamp": timestamp,
            "target_user": username,
            "status": "COMPLETED",
            "keys_found": len(all_keys),
            "keys_revoked": len(revoked),
            "revoked_keys": revoked,
            "deny_policy_attached": deny_policy,
            "sla": {
                "detection_to_revocation_target": "5 minutes",
                "completed_at": timestamp,
            },
            "next_steps": [
                "Audit CloudTrail for all API calls made with compromised key",
                "Check for new IAM users or roles created by the compromised identity",
                "Scan S3 buckets accessed during the compromise window",
                "File incident report within 24 hours",
                "Rotate any secrets that may have been exposed",
            ]
        }

        logger.info(f"[{incident_id}] Revocation complete: {len(revoked)} keys deactivated")
        return audit_record


if __name__ == "__main__":
    revoker = IAMKeyRevoker()
    print("IAM Key Revoker ready.")
    print(json.dumps({
        "playbook": "revoke_iam_keys",
        "sla_target": "5 minutes detection-to-revocation",
        "actions": [
            "list_active_keys",
            "capture_last_used_metadata",
            "deactivate_all_keys",
            "attach_deny_all_policy",
            "generate_audit_record"
        ],
        "mitre_coverage": [
            "T1078 - Valid Accounts",
            "T1098 - Account Manipulation",
            "T1110 - Brute Force"
        ],
    }, indent=2))
