---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Detection Method | Status |
|--------|-----------|-----|-----------------|--------|
| Initial Access | Phishing | T1566 | Email header Sigma rule | ✅ Covered |
| Execution | Command & Scripting Interpreter | T1059 | auditd + process Sigma rule | ✅ Covered |
| Persistence | Cron Job / Scheduled Task | T1053 | auditd Sigma rule | ✅ Covered |
| Privilege Escalation | Sudo / SUID Abuse | T1548 | auditd Sigma rule | ✅ Covered |
| Defense Evasion | Log Clearing | T1070 | CloudTrail Sigma rule | ✅ Covered |
| Credential Access | OS Credential Dumping | T1003 | YARA + process rule | ✅ Covered |
| Discovery | Network Scanning | T1046 | VPC Flow Log rule | ✅ Covered |
| Lateral Movement | Remote Services (SSH) | T1021 | auditd + CloudTrail | ✅ Covered |
| Collection | Data from Local System | T1005 | YARA file rule | ✅ Covered |
| Command & Control | C2 Beaconing | T1071 | DNS + flow analysis | ✅ Covered |
| Exfiltration | Transfer to Cloud | T1537 | S3 data event rule | ✅ Covered |
| Impact | Data Destruction | T1485 | CloudTrail + GuardDuty | ✅ Covered |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12 |
| Cloud | AWS (Lambda, GuardDuty, CloudTrail, S3, Athena, WAF, EC2) |
| SIEM | OpenSearch + Kibana |
| Detection | Sigma rules, YARA, Atomic Red Team |
| Threat Intel | MISP, VirusTotal API, AbuseIPDB, AlienVault OTX |
| SOAR | Custom Python playbooks + AWS SDK (boto3) |
| ATT&CK | MITRE ATT&CK STIX dataset, ATT&CK Navigator |
| IaC | Terraform |
| Alerting | PagerDuty + Slack webhooks |
| CI/CD | GitHub Actions (pytest + Bandit security scan) |

---

## Setup

```bash
git clone https://github.com/Alongiti2/threatops-sentinel.git
cd threatops-sentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
aws configure
```

---

## Author

**Delphin Alongiti** · Senior Cybersecurity Engineer  
CISSP · CEH · CCSP · PCNSE · AWS Solutions Architect Professional  
[github.com/Alongiti2](https://github.com/Alongiti2)

---

## License

MIT
