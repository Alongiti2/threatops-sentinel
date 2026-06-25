"""
S3 Uploader — ThreatOps Sentinel Phase 1
Uploads normalized events to S3 in partitioned JSON format for Athena queries.
"""
import boto3
import json
import gzip
import logging
from datetime import datetime, timezone
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class S3Uploader:
    def __init__(self, bucket_name: str, prefix: str = "normalized-events"):
        self.s3 = boto3.client("s3")
        self.bucket = bucket_name
        self.prefix = prefix

    def _build_s3_key(self, source: str) -> str:
        """Build a Hive-partitioned S3 key for Athena compatibility."""
        now = datetime.now(timezone.utc)
        return (
            f"{self.prefix}/"
            f"source={source}/"
            f"year={now.year}/"
            f"month={now.month:02d}/"
            f"day={now.day:02d}/"
            f"hour={now.hour:02d}/"
            f"{now.strftime('%H%M%S%f')}.json.gz"
        )

    def upload_events(self, events: List[dict], source: str) -> str:
        """
        Compress and upload a batch of normalized events to S3.
        Returns the S3 key of the uploaded object.
        """
        if not events:
            logger.info("No events to upload")
            return ""

        # Serialize to newline-delimited JSON (NDJSON) for Athena
        ndjson = "\n".join(json.dumps(e, default=str) for e in events)
        compressed = gzip.compress(ndjson.encode("utf-8"))

        key = self._build_s3_key(source)

        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=compressed,
            ContentEncoding="gzip",
            ContentType="application/json",
            Metadata={
                "source": source,
                "event_count": str(len(events)),
                "upload_time": datetime.now(timezone.utc).isoformat(),
            },
        )

        logger.info(
            f"Uploaded {len(events)} events from '{source}' → s3://{self.bucket}/{key}"
        )
        return key

    def upload_all(self, event_batches: dict) -> dict:
        """
        Upload multiple event batches by source.
        event_batches = {"cloudtrail": [...], "guardduty": [...], "auditd": [...]}
        Returns a summary of uploaded keys.
        """
        results = {}
        for source, events in event_batches.items():
            key = self.upload_events(events, source)
            results[source] = {
                "key": key,
                "count": len(events),
            }
        return results

    def get_upload_summary(self, results: dict) -> str:
        """Return a human-readable upload summary."""
        lines = ["=== S3 Upload Summary ==="]
        total = 0
        for source, info in results.items():
            lines.append(f"  {source}: {info['count']} events → {info['key']}")
            total += info["count"]
        lines.append(f"  TOTAL: {total} events uploaded")
        return "\n".join(lines)


if __name__ == "__main__":
    # Demo with mock events
    mock_batches = {
        "cloudtrail": [
            {"timestamp": "2026-06-24T10:00:00Z", "event.action": "ConsoleLogin", "source": "cloudtrail"},
            {"timestamp": "2026-06-24T10:01:00Z", "event.action": "PutBucketPolicy", "source": "cloudtrail"},
        ],
        "guardduty": [
            {"timestamp": "2026-06-24T10:02:00Z", "rule.name": "Recon:EC2/Portscan", "severity.label": "medium"},
        ],
        "auditd": [
            {"timestamp": "2026-06-24T10:03:00Z", "syscall": "execve", "mitre.tactic": "Execution"},
        ],
    }

    uploader = S3Uploader(bucket_name="threatops-sentinel-events")
    results = uploader.upload_all(mock_batches)
    print(uploader.get_upload_summary(results))
