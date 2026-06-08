# Playbook 04 — Cloud Misconfiguration Response

## Purpose
Automate the detection, enrichment, notification, and remediation of cloud misconfigurations identified by a Cloud Security Posture Management (CSPM) tool — with a particular focus on publicly exposed storage buckets and sensitive data exposure. Ensure the resource owner is notified and given the opportunity to confirm business intent before automated remediation changes cloud resource permissions.

## Trigger
- CSPM platform (Wiz, Prisma Cloud, AWS Security Hub, Microsoft Defender for Cloud) raises a **HIGH or CRITICAL** finding
- Finding categories include:
  - Publicly accessible S3 bucket / Azure Blob / GCS bucket
  - Overly permissive IAM role or policy (e.g. `*:*` on all resources)
  - Storage bucket with public ACL containing sensitive data patterns
  - Security group with `0.0.0.0/0` inbound on sensitive ports (22, 3389, 1433)
- OR a manual escalation from a cloud security review

## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|-----------|-----|--------|
| Data from Cloud Storage | T1530 | Collection |
| Valid Accounts — Cloud Accounts | T1078.004 | Initial Access |
| Unsecured Credentials — Cloud Instance Metadata | T1552.005 | Credential Access |

---

## Step-by-Step Logic

### Step 1 — Ingest & Parse Finding
- Extract from the CSPM finding:
  - Cloud provider (AWS / Azure / GCP)
  - Resource type (S3 bucket, IAM role, Security Group, Storage Account)
  - Resource name and ARN / resource ID
  - Region and account ID
  - Finding severity and policy rule violated
  - Timestamp of detection
  - Whether the resource is tagged (owner, environment, data classification)
- Log all fields to the SOAR case

### Step 2 — Resource Owner Enrichment
- Query the cloud resource tags for:
  - `Owner` tag → map to identity directory entry
  - `Environment` tag (production / staging / dev)
  - `DataClassification` tag (public / internal / confidential / restricted)
- If no `Owner` tag exists:
  - Query CloudTrail / Azure Activity Log for the identity that created the resource
  - Map the creator's IAM identity to an employee in the HR/identity directory
- If no owner can be identified: escalate to Cloud Security team immediately

### Step 3 — Sensitive Data Detection
For publicly exposed storage buckets:
- Trigger a lightweight data scan (AWS Macie / Azure Purview / manual pattern check via API) to detect:
  - PII patterns (email addresses, phone numbers, national ID numbers)
  - Credentials (AWS key patterns, private keys, API tokens)
  - PCI data patterns (credit card number formats)
  - PHI patterns (if healthcare environment)
- Record findings: data classification level and sample count (not the actual data)

### Step 4 — Exposure Risk Classification
| Condition | Classification |
|-----------|----------------|
| Public bucket + sensitive data (PII/PCI/PHI/credentials) confirmed | CRITICAL |
| Public bucket + no sensitive data confirmed | HIGH |
| Overly permissive IAM (`*:*`) on production account | CRITICAL |
| SSH/RDP open to 0.0.0.0/0 on production server | HIGH |
| Dev/test environment misconfiguration | MEDIUM |
| Misconfiguration on untagged/orphaned resource | HIGH |

### Step 5 — Auto-Tag Missing Metadata
If the resource is missing required tags:
- Apply tags automatically (no approval required — tagging is non-destructive):
  - `AutoTagged: true`
  - `MisconfigurationDetected: <date>`
  - `ReviewRequired: true`
- This ensures the resource appears in the next cloud compliance report regardless of remediation outcome

### Step 6 — Owner Notification
- Send a notification to the identified resource owner via:
  - Email (primary)
  - Slack / Teams channel for the owning team (secondary)
- Notification includes:
  - Resource name and region
  - What the misconfiguration is (plain language)
  - Whether sensitive data was detected
  - A link to the SOAR case
  - A **24-hour response window** to confirm: "Is this misconfiguration intentional?"
- Log the notification timestamp

### Step 7 — Decision Point: Automated Remediation

> ⚠️ **HUMAN-IN-THE-LOOP — REQUIRED BEFORE PROCEEDING**
>
> Before changing any cloud resource permissions, ACLs, or security group rules, the playbook requires explicit approval from either the resource owner or the Cloud Security team.
>
> **Why this gate exists:** Cloud resources configured as "public" are sometimes intentionally public — for example, a marketing website's asset bucket, a public software distribution endpoint, or a dev sandbox deliberately exposed for a third-party integration test. Automatically making a bucket private could break a production application or a customer-facing service. In regulated environments, changes to cloud resource access controls may require a Change Advisory Board (CAB) approval. Automated remediation without review creates a risk of undocumented configuration changes that cannot be traced back to a business decision.
>
> **Approval flow:**
>
> **Path A — Owner responds "Yes, this is intentional":**
> - Mark the finding as an accepted risk exception
> - Document the business justification in the SOAR case
> - Set a 30-day review reminder
> - Close ticket as "Risk Accepted"
>
> **Path B — Owner responds "No, please fix it" OR no response within 24 hours:**
> - Escalate to Cloud Security team for approval to remediate
> - Cloud Security approves → proceed to Step 8
> - Cloud Security requires CAB → open change ticket
>
> **Path C — CRITICAL finding (sensitive data exposed):**
> - Timeout is reduced to **2 hours**, not 24
> - If no owner response in 2 hours, Cloud Security team can approve remediation directly
> - Reason: data exposure with confirmed PII/credentials cannot wait a full business day

### Step 8 — Remediation (Post-Approval)
Perform the approved remediation action via cloud provider API:

**For public S3 bucket:**
- Apply `Block Public Access` settings at bucket level
- Remove any public bucket ACL entries
- Verify bucket policy does not contain `"Principal": "*"`

**For overly permissive IAM role:**
- Flag for IAM least-privilege review
- If `*:*` policy: remove the wildcard allow and replace with scoped permissions (requires human-written policy — SOAR opens a task for the cloud team)

**For open security groups (SSH/RDP to 0.0.0.0/0):**
- Remove the inbound rule
- If the host requires remote access: restrict to known corporate IP ranges

### Step 9 — Ticketing & Closure
- Update the SOAR case with:
  - All enrichment data
  - Owner communication record
  - Remediation actions taken with timestamps and approver identity
  - Post-remediation verification (re-scan the resource to confirm misconfiguration is resolved)
- Close the CSPM finding
- Tag ticket: MITRE ATT&CK `T1530`

### Step 10 — Post-Incident
- If sensitive data was exposed: determine if data was accessed while misconfigured (check cloud access logs / S3 server access logging)
- If data access is confirmed: escalate to Data Breach Assessment workflow
- Publish a "lessons learned" note for the owning team: what caused the misconfiguration and how to prevent recurrence

---

## Decision Tree Summary

```
CSPM HIGH/CRITICAL finding
│
├─► Extract: Resource, Account, Region, Tags
│
├─► Enrich: Owner lookup + Data classification scan
│
├─► Auto-tag missing metadata (non-destructive, no approval needed)
│
├─► Notify resource owner (24h window / 2h if CRITICAL)
│
├─► Owner: "Intentional" → Accept risk, document, close
│
└─► Owner: "Fix it" or No Response
           │
     Escalate to Cloud Security
           │
     Cloud Security approves?
    ┌──────┴──────┐
  Yes            CAB needed
    │                │
 Remediate       Open change
 via API         ticket
    │
 Verify + Close ticket
```

---

## Human-in-the-Loop Note
The 24-hour window for owner response (reduced to 2 hours for confirmed sensitive data exposure) reflects the operational reality that cloud teams own their infrastructure and need to be consulted before security changes break their applications. The SOAR workflow does not skip this gate even under pressure — it escalates instead. For CRITICAL findings, the escalation path is direct to Cloud Security, not a dead-end wait.

---

## References
- MITRE ATT&CK T1530: https://attack.mitre.org/techniques/T1530/
- AWS Security Hub: https://docs.aws.amazon.com/securityhub/
- Wiz CSPM: https://www.wiz.io/
- Amazon Macie: https://docs.aws.amazon.com/macie/
- Microsoft Defender for Cloud: https://learn.microsoft.com/en-us/azure/defender-for-cloud/
