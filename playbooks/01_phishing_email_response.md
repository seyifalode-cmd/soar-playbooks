# Playbook 01 — Phishing Email Response

## Purpose
Automate the triage, enrichment, and initial containment of high-confidence phishing emails detected in the corporate mail environment. Reduce analyst time-to-respond and ensure consistent handling across every phishing alert while keeping a human decision point before any mailbox-wide action.

## Trigger
- A phishing alert fires with **confidence ≥ HIGH** from the email security platform (e.g. Microsoft Defender for Office 365, Proofpoint, Mimecast)
- OR an analyst manually promotes a suspicious email to this playbook

## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|-----------|-----|--------|
| Phishing | T1566 | Initial Access |
| Spearphishing Attachment | T1566.001 | Initial Access |
| Spearphishing Link | T1566.002 | Initial Access |

---

## Step-by-Step Logic

### Step 1 — Ingest & Parse Alert
- Extract from the alert:
  - Sender email address and display name
  - Recipient list
  - Subject line
  - All URLs contained in the body
  - All attachment filenames and hashes (MD5, SHA256)
  - Email headers (Reply-To, X-Originating-IP, Return-Path)
- Deduplicate URLs (strip tracking parameters)
- Log all extracted IOCs to the SOAR case

### Step 2 — Enrich Indicators
Run the following in parallel:

**Sender domain / IP enrichment**
- Resolve the sending IP from email headers
- Run `ip_geo_enrich.py` → return country, ASN, ISP
- Check sender domain age (WHOIS) — flag domains < 30 days old
- Check sender IP against known spam/phishing reputation feeds

**URL enrichment**
- Submit each extracted URL to VirusTotal (`virustotal_lookup.py`)
- Check URL against MISP threat intel (`misp_lookup.py`)
- Expand shortened URLs and re-evaluate

**Attachment hash enrichment**
- Submit each SHA256 to VirusTotal (`virustotal_lookup.py`)
- Check hash against MISP (`misp_lookup.py`)
- Flag files with > 3 AV engine detections as **MALICIOUS**

### Step 3 — Risk Scoring
Compute a composite risk score:

| Indicator | Condition | Score |
|-----------|-----------|-------|
| URL | VirusTotal malicious ≥ 5 engines | +40 |
| Attachment | VT detections ≥ 3 engines | +40 |
| Sender domain | Age < 30 days | +20 |
| Sender IP | Known phishing source in MISP | +30 |
| Reply-To | Differs from From address | +10 |

- **Score ≥ 60** → classify as **CONFIRMED MALICIOUS**
- **Score 30–59** → classify as **SUSPICIOUS** → route to analyst for manual review
- **Score < 30** → classify as **LOW RISK** → log and close

### Step 4 — Decision Point: Automated vs. Human Action

> ⚠️ **HUMAN-IN-THE-LOOP — REQUIRED BEFORE PROCEEDING**
>
> If the email is classified **CONFIRMED MALICIOUS**, the playbook pauses and alerts the on-call analyst via PagerDuty / Teams notification before executing any mailbox-wide quarantine or sender block.
>
> **Why this gate exists:** Quarantining emails across all mailboxes and blocking a sender domain are irreversible actions that can disrupt legitimate business communications (e.g. a spoofed vendor domain). In a regulated environment (SOC 2, ISO 27001, PCI-DSS), automated containment actions must be reviewed and approved to maintain an auditable chain of custody. A false positive at this stage could constitute a service disruption.
>
> **Analyst decision options:**
> - ✅ **Approve** → proceed to Step 5 (containment)
> - ✏️ **Modify** → adjust scope (e.g. quarantine only affected recipient, not all mailboxes)
> - ❌ **Reject** → demote to SUSPICIOUS, route to manual investigation
>
> **Timeout:** If no analyst response within **30 minutes**, escalate to senior analyst and hold containment.

### Step 5 — Containment (Post-Approval)
- **Quarantine** all copies of the email from every mailbox where it was delivered
- **Block sender** email address and domain at the mail gateway
- **Block malicious URLs** at the web proxy / DNS sinkhole
- **Block malicious file hashes** in endpoint security (EDR block list)
- Submit malicious URLs and hashes to threat intel platform as confirmed IOCs

### Step 6 — Ticketing & Notification
- Open or update a SIEM/ITSM incident ticket (ServiceNow / Jira) with:
  - All extracted IOCs
  - Enrichment results
  - Analyst approval record
  - Containment actions taken with timestamps
- Notify affected recipients via email: *"A phishing email you received has been removed from your mailbox. No action required."*
- Tag ticket with MITRE ATT&CK: `T1566`

### Step 7 — Post-Incident
- Add confirmed IOCs (sender domain, IPs, hashes, URLs) to the organisation's internal block list
- Update MISP with the new indicators
- Close ticket with resolution summary

---

## Decision Tree Summary

```
Alert fired (HIGH confidence)
│
├─► Extract IOCs → Enrich (VT + MISP + GeoIP)
│
├─► Risk Score < 30?  → Log & Close
├─► Risk Score 30-59? → Route to Analyst (manual review)
└─► Risk Score ≥ 60?  → PAUSE → Notify Analyst → Await Approval
                              │
                        ┌─────┴─────┐
                     Approve       Reject
                        │             │
                   Quarantine     Demote to
                   + Block        Suspicious
                        │
                   Open Ticket + Notify Recipients
```

---

## Human-in-the-Loop Note
This playbook enforces analyst approval before any quarantine or block action. This is non-negotiable in environments subject to data protection regulations or SLA commitments to end users. The automation handles speed and consistency; the analyst handles judgment and accountability.

---

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1566/
- Cortex XSOAR Phishing Use Case: https://docs.paloaltonetworks.com/cortex/cortex-xsoar
- Splunk SOAR Phishing Playbook: https://docs.splunk.com/Documentation/SOAR
