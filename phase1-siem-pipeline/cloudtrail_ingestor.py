"""
CloudTrail Log Ingestor — ThreatOps Sentinel Phase 1
Polls CloudTrail S3 bucket, parses events, normalizes to ECS schema.
"""
import boto3
import json
import gzip
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CloudTrailIngestor:
    def __init__(self, bucket_name: str, prefix: str = "cloudtrail/"):
        self.s3 = boto3.client("s3")
        self.bucket = bucket_name
        self.prefix = prefix

    def list_new_logs(self, since_hours: int = 1) -> list:
        """List CloudTrail log files modified in the last N hours."""
        paginator = self.s3.get_paginator("list_objects_v2")
        cutoff = datetime.now(timezone.utc).timestamp() - (since_hours * 3600)
        keys = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                if obj["LastModified"].timestamp() > cutoff:
                    keys.append(obj["Key"])
        logger.info(f"Found {len(keys)} new CloudTrail log files")
        return keys

    def parse_log_file(self, key: str) -> list:
        """Download, decompress, and parse a CloudTrail .json.gz file."""
        response = self.s3.get_object(Bucket=self.bucket, Key=key)
        body = response["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        records = json.loads(body).get("Records", [])
        return [self._normalize(r) for r in records]

    def _normalize(self, record: dict) -> dict:
        """Normalize CloudTrail event to Elastic Common Schema (ECS)."""
        return {
            "timestamp": record.get("eventTime"),
            "source": "cloudtrail",
            "event.action": record.get("eventName"),
            "event.outcome": "success" if not record.get("errorCode") else "failure",
            "aws.region": record.get("awsRegion"),
            "aws.service": record.get("eventSource"),
            "user.name": record.get("userIdentity", {}).get("userName", "unknown"),
            "user.arn": record.get("userIdentity", {}).get("arn"),
            "source.ip": record.get("sourceIPAddress"),
            "user_agent": record.get("userAgent"),
            "raw": record,
        }

    def ingest(self) -> list:
        """Full ingest cycle: list → parse → return normalized events."""
        all_events = []
        for key in self.list_new_logs():
            events = self.parse_log_file(key)
            all_events.extend(events)
            logger.info(f"Parsed {len(events)} events from {key}")
        return all_events


if __name__ == "__main__":
    ingestor = CloudTrailIngestor(bucket_name="your-cloudtrail-bucket")
    events = ingestor.ingest()
    print(json.dumps(events[:2], indent=2, default=str))
