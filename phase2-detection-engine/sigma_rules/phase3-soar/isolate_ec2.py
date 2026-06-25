"""
EC2 Isolator — ThreatOps Sentinel Phase 3 SOAR
Automatically isolates a compromised EC2 instance by swapping its
security group to a quarantine group that blocks all traffic.
"""
import boto3
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EC2Isolator:
    def __init__(self, region: str = "us-east-1"):
        self.ec2 = boto3.client("ec2", region_name=region)
        self.region = region

    def _get_or_create_quarantine_sg(self, vpc_id: str) -> str:
        """Get existing quarantine SG or create one that blocks all traffic."""
        name = "threatops-quarantine-sg"
        try:
            response = self.ec2.describe_security_groups(
                Filters=[
                    {"Name": "group-name", "Values": [name]},
                    {"Name": "vpc-id", "Values": [vpc_id]},
                ]
            )
            if response["SecurityGroups"]:
                sg_id = response["SecurityGroups"][0]["GroupId"]
                logger.info(f"Found existing quarantine SG: {sg_id}")
                return sg_id
        except Exception:
            pass

        # Create quarantine SG with no inbound/outbound rules
        response = self.ec2.create_security_group(
            GroupName=name,
            Description="ThreatOps Sentinel — Quarantine: NO inbound/outbound traffic",
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "ManagedBy", "Value": "ThreatOps-Sentinel"},
                    {"Key": "Purpose", "Value": "incident-response-quarantine"},
                ]
            }]
        )
        sg_id = response["GroupId"]

        # Remove default outbound rule (allow all)
        self.ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }]
        )
        logger.info(f"Created quarantine SG with no rules: {sg_id}")
        return sg_id

    def get_instance_info(self, instance_id: str) -> dict:
        """Get instance metadata before isolation."""
        response = self.ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        return {
            "instance_id": instance_id,
            "state": instance["State"]["Name"],
            "vpc_id": instance["VpcId"],
            "subnet_id": instance["SubnetId"],
            "private_ip": instance.get("PrivateIpAddress"),
            "public_ip": instance.get("PublicIpAddress"),
            "original_sgs": [sg["GroupId"] for sg in instance["SecurityGroups"]],
            "tags": {t["Key"]: t["Value"] for t in instance.get("Tags", [])},
        }

    def isolate(self, instance_id: str, incident_id: str = None) -> dict:
        """
        Full isolation playbook:
        1. Snapshot original security groups
        2. Create/get quarantine SG
        3. Replace all SGs with quarantine SG
        4. Tag instance with incident metadata
        5. Return audit record
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        incident_id = incident_id or f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        logger.info(f"[{incident_id}] Starting isolation of {instance_id}")

        # Step 1 — Get current state
        info = self.get_instance_info(instance_id)
        if info["state"] != "running":
            logger.warning(f"Instance {instance_id} is not running (state: {info['state']})")

        # Step 2 — Get quarantine SG
        quarantine_sg = self._get_or_create_quarantine_sg(info["vpc_id"])

        # Step 3 — Swap security groups
        self.ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_sg],
        )
        logger.info(f"[{incident_id}] Security groups swapped → {quarantine_sg}")

        # Step 4 — Tag instance with incident info
        self.ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "threatops:isolated", "Value": "true"},
                {"Key": "threatops:incident_id", "Value": incident_id},
                {"Key": "threatops:isolated_at", "Value": timestamp},
                {"Key": "threatops:original_sgs", "Value": ",".join(info["original_sgs"])},
            ]
        )

        audit_record = {
            "playbook": "isolate_ec2",
            "incident_id": incident_id,
            "timestamp": timestamp,
            "instance_id": instance_id,
            "region": self.region,
            "status": "ISOLATED",
            "original_security_groups": info["original_sgs"],
            "quarantine_security_group": quarantine_sg,
            "private_ip": info["private_ip"],
            "public_ip": info["public_ip"],
            "vpc_id": info["vpc_id"],
            "sla": {
                "detection_to_isolation_target": "15 minutes",
                "completed_at": timestamp,
            },
            "next_steps": [
                "Capture memory dump for forensic analysis",
                "Take EBS snapshot before any remediation",
                "Open P1 incident ticket",
                "Notify CISO and Legal if PII data involved",
            ]
        }

        logger.info(f"[{incident_id}] Isolation complete. Audit: {json.dumps(audit_record, indent=2)}")
        return audit_record

    def restore(self, instance_id: str, incident_id: str) -> dict:
        """Restore original security groups after investigation."""
        response = self.ec2.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": ["threatops:original_sgs"]},
            ]
        )
        tags = {t["Key"]: t["Value"] for t in response["Tags"]}
        original_sgs = tags.get("threatops:original_sgs", "").split(",")

        if not original_sgs or original_sgs == [""]:
            raise ValueError(f"No original SGs found in tags for {instance_id}")

        self.ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=original_sgs,
        )
        logger.info(f"[{incident_id}] Restored SGs for {instance_id}: {original_sgs}")
        return {"status": "RESTORED", "instance_id": instance_id, "restored_sgs": original_sgs}


if __name__ == "__main__":
    # Demo — replace with real instance ID
    isolator = EC2Isolator(region="us-east-1")
    print("EC2 Isolator ready. Call isolator.isolate('i-xxxxxxxxx') to quarantine an instance.")
    print(json.dumps({
        "playbook": "isolate_ec2",
        "sla_target": "15 minutes detection-to-isolation",
        "actions":
