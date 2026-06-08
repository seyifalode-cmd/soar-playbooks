# SOAR Concepts & Terminology

## Core Concepts

**Playbook** — A codified, automated workflow that defines the step-by-step response to a specific type of security alert. Playbooks replace ad-hoc analyst procedures with consistent, auditable automation.

**Enrichment** — The process of automatically gathering additional context about an IOC (indicator of compromise) from external and internal sources before a human makes a decision. Enrichment turns a raw alert into an actionable case.

**IOC (Indicator of Compromise)** — A piece of forensic evidence suggesting a host or network has been breached. Common IOC types: file hashes, IP addresses, domains, URLs, email addresses, registry keys, process names.

**Human-in-the-Loop (HITL)** — A deliberate pause in automated execution that requires a human analyst to review enriched data and approve, modify, or reject a proposed action before the automation proceeds.

**Case / Incident** — The SOAR platform's representation of a security event. Contains all alerts, enrichment data, analyst notes, evidence, and action logs in one place.

**War Room** — Cortex XSOAR's term for the collaborative workspace attached to an incident, where all automated and manual actions are logged in real time.

## Enrichment Sources Used in This Repo

| Source | What It Provides |
|--------|-----------------|
| VirusTotal | Multi-engine AV/reputation analysis for hashes, IPs, URLs, domains |
| MISP | Threat intel correlation — known malware families, APT infrastructure, shared IOCs |
| ip-api.com | IP geolocation, ASN, ISP, VPN/proxy/Tor detection |
| Azure AD / Okta | User identity context, MFA status, sign-in history |
| EDR Platform | Host telemetry, process history, file activity |
| CSPM (Wiz / AWS Security Hub) | Cloud resource configuration state, exposure risk |

## Playbook Design Principles

1. **Enrich before deciding** — Never ask a human to make a decision without first providing all available context automatically.
2. **Gate destructive actions** — Any action that disconnects a user, takes a host offline, or modifies production infrastructure requires explicit human approval.
3. **Short timeouts on critical alerts** — Ransomware does not wait 24 hours. Timeout values are calibrated to the severity of the threat.
4. **Every action is logged** — SOAR must maintain a complete audit trail: who approved what, when, and why.
5. **False positives are a first-class outcome** — Every HITL gate includes a "false positive" path that closes the case cleanly without requiring workarounds.
