"""
Auditd Log Parser — ThreatOps Sentinel Phase 1
Parses Linux auditd logs, extracts syscall events, normalizes to ECS.
"""
import re
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suspicious syscalls mapped to MITRE ATT&CK
SUSPICIOUS_SYSCALLS = {
    "execve": {"tactic": "Execution", "technique": "T1059", "risk": "high"},
    "ptrace": {"tactic": "Credential Access", "technique": "T1003", "risk": "high"},
    "setuid": {"tactic": "Privilege Escalation", "technique": "T1548", "risk": "high"},
    "setgid": {"tactic": "Privilege Escalation", "technique": "T1548", "risk": "high"},
    "chmod": {"tactic": "Defense Evasion", "technique": "T1222", "risk": "medium"},
    "chown": {"tactic": "Defense Evasion", "technique": "T1222", "risk": "medium"},
    "open": {"tactic": "Collection", "technique": "T1005", "risk": "low"},
    "connect": {"tactic": "Command and Control", "technique": "T1071", "risk": "medium"},
    "bind": {"tactic": "Command and Control", "technique": "T1071", "risk": "medium"},
    "fork": {"tactic": "Execution", "technique": "T1059", "risk": "low"},
    "kill": {"tactic": "Impact", "technique": "T1489", "risk": "high"},
    "unlink": {"tactic": "Defense Evasion", "technique": "T1070", "risk": "medium"},
}

# Regex patterns for auditd log fields
AUDITD_PATTERNS = {
    "timestamp": re.compile(r"audit\((\d+\.\d+):(\d+)\)"),
    "syscall": re.compile(r"\bsyscall=(\w+)"),
    "pid": re.compile(r"\bpid=(\d+)"),
    "uid": re.compile(r"\buid=(\d+)"),
    "auid": re.compile(r"\bauid=(\d+)"),
    "exe": re.compile(r'\bexe="([^"]+)"'),
    "comm": re.compile(r'\bcomm="([^"]+)"'),
    "key": re.compile(r'\bkey="([^"]+)"'),
    "result": re.compile(r"\bresult=(\w+)"),
    "hostname": re.compile(r'\bhostname="([^"]+)"'),
}


class AuditdParser:
    def __init__(self, log_path: str = "/var/log/audit/audit.log"):
        self.log_path = log_path

    def parse_line(self, line: str) -> dict | None:
        """Parse a single auditd log line into a structured event."""
        if "type=SYSCALL" not in line:
            return None

        event = {"source": "auditd", "raw": line.strip()}

        for field, pattern in AUDITD_PATTERNS.items():
            match = pattern.search(line)
            if match:
                event[field] = match.group(1)

        # Convert epoch timestamp
        if "timestamp" in event:
            try:
                event["timestamp"] = datetime.fromtimestamp(
                    float(event["timestamp"])
                ).isoformat()
            except ValueError:
                pass

        # MITRE ATT&CK enrichment
        syscall = event.get("syscall", "")
        if syscall in SUSPICIOUS_SYSCALLS:
            attack = SUSPICIOUS_SYSCALLS[syscall]
            event["mitre.tactic"] = attack["tactic"]
            event["mitre.technique"] = attack["technique"]
            event["risk.level"] = attack["risk"]
            event["alert"] = True
        else:
            event["alert"] = False

        return event

    def parse_file(self, max_lines: int = 10000) -> list:
        """Parse the auditd log file and return normalized events."""
        events = []
        alerts = []
        try:
            with open(self.log_path, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    event = self.parse_line(line)
                    if event:
                        events.append(event)
                        if event.get("alert"):
                            alerts.append(event)
        except FileNotFoundError:
            logger.warning(f"Log file not found: {self.log_path}")

        logger.info(
            f"Parsed {len(events)} SYSCALL events | {len(alerts)} alerts flagged"
        )
        return events

    def parse_sample(self, raw_lines: list) -> list:
        """Parse a list of raw log lines (useful for testing)."""
        return [e for line in raw_lines if (e := self.parse_line(line))]


# Sample test data for demo/testing without a live auditd system
SAMPLE_AUDITD_LINES = [
    'type=SYSCALL msg=audit(1718000000.123:456): arch=c000003e syscall=execve success=yes exit=0 a0=7f a1=7f a2=0 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="exec_monitor"',
    'type=SYSCALL msg=audit(1718000001.456:457): arch=c000003e syscall=setuid success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=5678 pid=5679 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"',
    'type=SYSCALL msg=audit(1718000002.789:458): arch=c000003e syscall=ptrace success=yes exit=0 a0=10 a1=5680 a2=0 a3=0 items=0 ppid=5678 pid=5681 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="gdb" exe="/usr/bin/gdb"
