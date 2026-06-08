# Playbook 02 — Suspicious Login / Anomalous Sign-In Response

## Purpose
Automatically triage and respond to anomalous authentication events — specifically impossible travel, sign-ins from unknown locations, and MFA anomalies — to contain potential account compromise before an attacker can pivot or exfiltrate data.

## Trigger
- An impossible travel alert fires from the Identity Provider (Azure AD / Okta / Duo)
- OR a sign-in risk score ≥ HIGH from Azure AD Identity Protection / Okta ThreatInsight
- OR a SIEM alert for Sigma rule: Impossible Travel (T1078) fires
- OR an analyst manually escalates a suspicious authentication event

## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|-----------|-----|--------|
| Valid Accounts | T1078 | Initial Access / Persistence / Defense Evasion |
| Cloud Accounts | T1078.004 | Initial Access |

---

## Step-by-Step Logic

### Step 1 — Ingest & Parse Alert
- Extract from the alert:
  - User Principal Name (UPN) / username
  - Source IP address(es)
  - Timestamp(s) of sign-in event(s)
  - Geolocation data (city, country, ASN)
  - Device ID and compliance status (if available)
  - Application accessed
  - MFA method used (or absent)
- Log all fields to the SOAR case

### Step 2 — User Context Enrichment
- Query HR / Identity directory for:
  - User role and department
  - Manager name
  - Whether the user is flagged as a privileged account (admin, finance, C-suite)
  - Expected working location (home country)
  - Recent travel bookings (if integration available)
- Pull the user's last 10 sign-in events to establish baseline geolocation

### Step 3 — IP & Geo Enrichment
- Run `ip_geo_enrich.py` on each source IP:
  - Return country, city, ASN, ISP
  - Flag if IP is a known VPN exit node, Tor exit, or datacenter IP
  - Calculate distance and travel time between the two sign-in locations
- Run `misp_lookup.py` on each IP:
  - Check for prior association with threat actor infrastructure
- Run `virustotal_lookup.py` on each IP:
  - Check malicious/suspicious vote count

### Step 4 — MFA Status Check
- Query IdP API to determine:
  - Was MFA completed for this session? (method and timestamp)
  - Does the user have MFA enrolled at all?
  - Any recent MFA push denials in the last 60 minutes (MFA fatigue indicator)?
- If MFA was **not** completed and session is active → escalate risk immediately

### Step 5 — Risk Scoring
| Condition | Score |
|-----------|-------|
| Two countries in < 2 hours (impossible travel) | +50 |
| Sign-in from Tor/VPN/datacenter IP | +30 |
| IP flagged in MISP as threat actor infra | +40 |
| MFA not completed | +30 |
| > 5 MFA push denials in last 60 min | +25 |
| Privileged account (admin/finance/exec) | +20 |
| Off-hours access (00:00–05:00 local) | +15 |

- **Score ≥ 70** → **HIGH RISK** — go to human gate (Step 6)
- **Score 40–69** → **MEDIUM RISK** — step-up MFA challenge, notify analyst
- **Score < 40** → **LOW RISK** — log and monitor

### Step 6 — Decision Point: Session Termination

> ⚠️ **HUMAN-IN-THE-LOOP — REQUIRED BEFORE PROCEEDING**
>
> If risk score is **HIGH (≥ 70)**, the playbook pauses and pages the on-call analyst before disabling the user's active sessions or forcing password reset.
>
> **Why this gate exists:** Disabling a user's session is an operational disruption. If the user is a legitimate executive travelling internationally, automated lockout could interrupt a business-critical activity. In regulated industries (finance, healthcare), disabling access to systems without approval may need to be documented as part of an access control audit. Password resets require confirmation that the user is genuinely compromised — not just triggering a false positive from a VPN.
>
> **Analyst decision options:**
> - ✅ **Approve — Disable session + force re-auth** → proceed to Step 7 (containment)
> - 🔒 **Step-up only** → issue MFA challenge without full session revocation
> - 📞 **Verify with user** → SOAR sends SMS/Teams message to user asking "Was this you?" — await confirmation
> - ❌ **False positive** → close case, whitelist location for 24 hours
>
> **Timeout:** If no analyst response within **15 minutes** on a HIGH-risk privileged account, auto-escalate to senior analyst.

### Step 7 — Containment (Post-Approval)
- Revoke all active sessions for the user via IdP API
- Force re-authentication with MFA on next login
- If confirmed compromise: initiate credential reset workflow
- If privileged account: temporarily disable account pending full investigation
- Block source IP at perimeter firewall (if not a shared IP/VPN)

### Step 8 — Ticketing & Notification
- Open incident ticket with all enrichment data and analyst decision record
- Notify user's manager via email
- If privileged account: notify CISO
- Tag ticket: MITRE ATT&CK `T1078`

### Step 9 — Post-Incident
- If confirmed compromise: trigger full credential audit for the user
- Add malicious IPs to block list and MISP
- Review for lateral movement: did the session access sensitive systems before containment?
- Document findings in incident report

---

## Decision Tree Summary

```
Anomalous sign-in alert
│
├─► Extract: User, IP, Geo, MFA status
│
├─► Enrich: GeoIP + MISP + VT + IdP baseline
│
├─► Risk Score < 40?  → Log & Monitor
├─► Risk Score 40-69? → Step-up MFA challenge + Notify analyst
└─► Risk Score ≥ 70?  → PAUSE → Page Analyst → Await Decision
                              │
               ┌──────────────┼──────────────┐
           Approve         Step-up        Verify w/ User
               │           MFA only           │
         Revoke session                  Await user reply
         + Force re-auth                      │
               │                    Confirmed? → Revoke
         Open Ticket                Not me?   → Close
         + Notify Manager
```

---

## Human-in-the-Loop Note
Session revocation and forced password resets are disruptive and can affect business continuity. A single false positive on a C-suite account during a board meeting is a significant operational incident. The 15-minute timeout on privileged accounts balances speed with the need for human judgment — it is short enough to prevent dwell time but long enough for a thoughtful decision.

---

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1078/
- Azure AD Identity Protection: https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/
- Okta ThreatInsight: https://help.okta.com/en-us/content/topics/security/threat-insight/ti-main.htm
