# SOAR Playbooks — SOC Automation Library

**Vendor-Neutral Incident Response Playbooks with Python Enrichment**
Oluwaseyi Michael Falode | Cybersecurity & Cloud Security Engineer | Toronto, ON

![SOAR](https://img.shields.io/badge/SOAR-4_Playbooks-0078D4?style=flat)
![Python](https://img.shields.io/badge/Python-Enrichment_Scripts-3776AB?style=flat&logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-E63F2B?style=flat)
![Human in the loop](https://img.shields.io/badge/Human--in--the--Loop-Approval_Gates-107C41?style=flat)

> **Security Orchestration, Automation and Response (SOAR) playbooks for a modern SOC — platform-aware, vendor-neutral, human-in-the-loop by design.**

---

## What Is SOAR?

A **SOAR platform** is a layer on top of your SIEM and security tools that lets a SOC team codify its response procedures as automated workflows. Instead of an analyst manually checking VirusTotal, querying the identity provider, opening a ticket, and sending notifications — all while under pressure — a SOAR playbook does those mechanical steps automatically and presents the analyst with a pre-enriched summary and a clear decision to make.

Think of it as the difference between a surgeon who has to prep the operating room, sterilise the tools, and locate the patient's file before cutting — versus one who walks in, finds everything ready, and focuses entirely on the judgment that only a human can make.

SOAR platforms referenced in this repo:
- **Cortex XSOAR** (Palo Alto Networks) — enterprise-grade, Python-based automation
- **Splunk SOAR** (formerly Phantom) — event-driven playbooks with a visual canvas

The playbooks in this repo are documented in a vendor-neutral format — the logic, decision points, and enrichment steps apply to either platform (and others such as Microsoft Sentinel Automation, Google Chronicle SOAR, or custom orchestration frameworks).

---

## Why Human-in-the-Loop Matters

Automation makes SOC teams faster. But **speed without judgment creates risk**.

Every playbook in this repo includes a mandatory **human-in-the-loop (HITL) decision point** before any action that is:
- **Destructive** — deleting data, blocking access, isolating a host
- **Irreversible** — revoking sessions, quarantining mailboxes across thousands of users
- **Business-impacting** — taking a server offline, changing cloud resource permissions

> In a regulated environment — PCI-DSS, SOC 2, ISO 27001, HIPAA — automated security actions must be **defensible**. That means a human approved them, the approval is timestamped and auditable, and the action can be traced to a business decision. An automated containment that turns out to be a false positive is not just an operational incident; it can be a compliance finding.

The HITL gate does **not** mean slow. Every gate in these playbooks is designed so that:
1. The analyst receives a fully enriched, pre-summarised case — not raw log data
2. The decision is binary (approve / reject / modify scope)
3. Timeouts escalate automatically rather than stalling the workflow

---

## Playbook Index

| # | Playbook | Trigger | MITRE ATT&CK | Severity |
|---|----------|---------|--------------|----------|
| 01 | [Phishing Email Response](playbooks/01_phishing_email_response.md) | High-confidence phishing alert from email security platform | [T1566](https://attack.mitre.org/techniques/T1566/) · [T1566.001](https://attack.mitre.org/techniques/T1566/001/) · [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | HIGH |
| 02 | [Suspicious Login Response](playbooks/02_suspicious_login_response.md) | Impossible travel or anomalous sign-in alert from IdP | [T1078](https://attack.mitre.org/techniques/T1078/) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | HIGH |
| 03 | [Malware / Endpoint Response](playbooks/03_malware_endpoint_response.md) | EDR HIGH/CRITICAL detection — malware, ransomware, C2, credential dumping | [T1059](https://attack.mitre.org/techniques/T1059/) · [T1486](https://attack.mitre.org/techniques/T1486/) · [T1490](https://attack.mitre.org/techniques/T1490/) | CRITICAL |
| 04 | [Cloud Misconfiguration Response](playbooks/04_cloud_misconfiguration_response.md) | CSPM finding — public storage bucket, permissive IAM, open security group | [T1530](https://attack.mitre.org/techniques/T1530/) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | HIGH–CRITICAL |

---

## Enrichment Scripts

Three Python scripts in `enrichment/` are called by the playbooks during the automated enrichment phase. Each script is well-commented, handles errors gracefully, and reads credentials from environment variables — **no secrets are hard-coded**.

| Script | Purpose | Used In |
|--------|---------|---------|
| [`virustotal_lookup.py`](enrichment/virustotal_lookup.py) | Query VirusTotal v3 API for hash, IP, or URL reputation | PB 01, 02, 03 |
| [`ip_geo_enrich.py`](enrichment/ip_geo_enrich.py) | Geolocate an IP, detect VPN/Tor/datacenter, calculate impossible travel | PB 02, 03, 04 |
| [`misp_lookup.py`](enrichment/misp_lookup.py) | Query a MISP threat intel instance for any IOC type | PB 01, 02, 03 |

### Environment variables required

```bash
# VirusTotal
export VT_API_KEY="your_virustotal_api_key"

# MISP
export MISP_URL="https://misp.yourdomain.com"
export MISP_API_KEY="your_misp_automation_key"

# Optional — ip_geo_enrich.py
export HIGH_RISK_COUNTRIES="KP,IR,BY,CU,SY"     # ISO country codes
export IMPOSSIBLE_TRAVEL_SPEED_KPH="900"          # Default: 900 km/h
```

### Running the scripts standalone

```bash
# Install the only dependency
pip install requests

# Run any script directly for testing
python enrichment/virustotal_lookup.py
python enrichment/ip_geo_enrich.py
python enrichment/misp_lookup.py
```

---

## Flowcharts / Diagrams

Each playbook has a corresponding Mermaid flowchart in `diagrams/`. These render natively in GitHub and can be imported into Confluence, Notion, or any documentation platform that supports Mermaid.

| Diagram | Playbook |
|---------|---------|
| [01_phishing_email_response.md](diagrams/01_phishing_email_response.md) | Phishing Email Response |
| [02_suspicious_login_response.md](diagrams/02_suspicious_login_response.md) | Suspicious Login Response |
| [03_malware_endpoint_response.md](diagrams/03_malware_endpoint_response.md) | Malware / Endpoint Response |
| [04_cloud_misconfiguration_response.md](diagrams/04_cloud_misconfiguration_response.md) | Cloud Misconfiguration Response |

---

## Repository Structure

```
soar-playbooks/
├── playbooks/                   # Markdown playbooks — one per use case
│   ├── 01_phishing_email_response.md
│   ├── 02_suspicious_login_response.md
│   ├── 03_malware_endpoint_response.md
│   └── 04_cloud_misconfiguration_response.md
├── diagrams/                    # Mermaid flowcharts for each playbook
│   ├── 01_phishing_email_response.md
│   ├── 02_suspicious_login_response.md
│   ├── 03_malware_endpoint_response.md
│   └── 04_cloud_misconfiguration_response.md
├── enrichment/                  # Python enrichment scripts
│   ├── virustotal_lookup.py
│   ├── ip_geo_enrich.py
│   └── misp_lookup.py
├── docs/                        # Supporting documentation
└── README.md
```

---

## How This Maps to SOAR Platforms

### Cortex XSOAR
- Each playbook maps to a **XSOAR Playbook** built in the visual canvas
- Enrichment scripts map to **Integration commands** or **Automation scripts**
- The HITL gate maps to a **Manual Task** or **Ask** step that pings the analyst via PagerDuty/Slack
- Tickets map to the **Incident** object with a full War Room log

### Splunk SOAR
- Each playbook maps to a **Playbook** in the visual editor
- Enrichment scripts map to **App Actions** on integrated assets
- The HITL gate maps to a **Prompt** block that suspends execution and sends a Teams/email notification
- Evidence is collected in the **Vault** attached to the case

---

## Author

**Oluwaseyi Michael Falode**
Detection Engineer | Cloud & Cybersecurity

- Email: [seyi.falode@yahoo.com](mailto:seyi.falode@yahoo.com)
- LinkedIn: [https://www.linkedin.com/in/oluwaseyi-falode-bb3b1651](https://www.linkedin.com/in/oluwaseyi-falode-bb3b1651)
- GitHub: [github.com/seyifalode-cmd](https://github.com/seyifalode-cmd)

---

*Playbooks are documented for educational and portfolio purposes. Adapt enrichment thresholds, timeout values, and escalation paths to your organisation's specific risk tolerance and SLA requirements before deploying to production.*
