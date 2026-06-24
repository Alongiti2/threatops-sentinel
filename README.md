# ThreatOps Sentinel

> End-to-end Security Operations & Threat Management platform — built to mirror real-world Staff SecOps engineering: SIEM ingestion, MITRE ATT&CK detection, SOAR automation, adversary emulation, and forensic response on AWS.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![AWS](https://img.shields.io/badge/AWS-CloudTrail%20%7C%20GuardDuty%20%7C%20Lambda-orange?style=flat-square&logo=amazonaws)
![Terraform](https://img.shields.io/badge/IaC-Terraform-purple?style=flat-square&logo=terraform)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)

---

## What this project does

ThreatOps Sentinel is a production-grade SecOps platform that demonstrates the full lifecycle of threat detection and response — from raw log ingestion to executive incident reporting. It was designed to reflect the exact responsibilities of a Staff Security Engineer operating in a cloud-native environment.

| Phase | Domain | Key Capability |
|-------|--------|----------------|
| 1 | SIEM Pipeline | AWS log ingestion, normalization, OpenSearch dashboards |
| 2 | Detection Engine | Sigma/YARA rules, MITRE ATT&CK auto-tagging, vulnerability correlation |
| 3 | SOAR Automation | Incident response playbooks, SLA tracking, PagerDuty/Slack routing |
| 4 | Threat Intelligence | MISP/VirusTotal enrichment, APT emulation planning, Atomic Red Team |
| 5 | Forensics & Compliance | Attack timeline reconstruction, chain-of-custody vault, compliance matrix |

---

## Architecture
┌─────────────────────────────────────────────────────────────────┐

│                        AWS Cloud Environment                     │

│                                                                  │

│  CloudTrail ──┐                                                  │

│  GuardDuty ───┼──► Kinesis ──► Lambda ──► S3 ──► Athena         │

│  VPC Flow ────┘    (ingest)   (normalize)        (forensic replay)│

│  auditd ─────────────────────────────────────────────────────── │

│                                        │                         │

│                                        ▼                         │

│                                   OpenSearch ──► Kibana Dashboard│

│                                        │                         │

│                              ┌─────────┴──────────┐             │

│                              ▼                     ▼             │

│                       Detection Engine        SOAR Engine        │

│                    (Sigma + YARA rules)   (Response Playbooks)   │

│                    (MITRE ATT&CK mapper)  (SLA Tracker)          │

│                              │                     │             │

│                              ▼                     ▼             │

│                       Threat Intel           PagerDuty / Slack   │

│                    (MISP / VT / CISA KEV)                        │

│                              │                                   │

│                              ▼                                   │

│                    Forensics & Compliance                        │

│                 (Timeline Reconstructor)                         │

│                 (Chain-of-Custody Vault)                         │

│                 (NIST / SOC 2 / ISO 27001 Matrix)               │

└─────────────────────────────────────────────────────────────────┘
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
