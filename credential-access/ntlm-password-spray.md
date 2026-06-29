# Hunt Playbook: NTLM Password Spray

| Field | Detail |
|---|---|
| **Tactic** | Credential Access (TA0006) |
| **Technique** | T1110.003 — Password Spraying |
| **Platforms** | Microsoft Sentinel, IBM QRadar, Microsoft Defender XDR |
| **Data Sources** | Windows Security Events (4625, 4624), NTLM logs, IdentityLogonEvents |
| **Hunt Frequency** | Weekly or on threat intel tip |
| **Author** | Faizaan Sajjad |

---

## Overview

Password spraying is a credential attack technique where an adversary tries a small number of commonly used passwords against a large number of accounts. Unlike brute force (many passwords, one account), spraying avoids account lockouts by staying below lockout thresholds.

This hunt looks for the behavioral signature: **low attempt count per account, high breadth across accounts, from a single or small number of source IPs, in a compressed timeframe.**

---

## Hypothesis

> An adversary has obtained a list of valid usernames (via OSINT, LinkedIn, or prior recon) and is attempting NTLM password spray against domain accounts to gain initial foothold or expand access.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows Security Event logging | Event ID 4625 (failed logon) must be enabled |
| NTLM audit logging | Enable via GPO: Computer Config → Windows Settings → Security Settings → Local Policies → Security Options → "Network security: Restrict NTLM" |
| Log ingestion into SIEM | Events forwarded from DCs and member servers |
| Domain Controller list | Needed to filter out legitimate replication traffic |

---

## Hunt Steps

### Step 1 — Establish Baseline of Failed Logins

Before hunting anomalies, understand your environment's normal failed login volume.

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4625
| summarize DailyFailures = count() by bin(TimeGenerated, 1d)
| render timechart
```

Look for spikes above baseline. A spray event will appear as a sharp, short-duration spike.

---

### Step 2 — Identify High-Breadth Failure Sources

**[KQL-Sentinel]**
```kql
let TimeWindow = 30m;
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| where AuthenticationPackageName == "NTLM"
| where LogonType == 3
| summarize
    FailedAttempts = count(),
    UniqueAccounts = dcount(TargetUserName),
    TargetAccounts = make_set(TargetUserName, 30),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IpAddress, bin(TimeGenerated, TimeWindow)
| where UniqueAccounts >= 5
| where FailedAttempts >= 10
| extend AttemptsPerAccount = round(toreal(FailedAttempts) / UniqueAccounts, 2)
| sort by UniqueAccounts desc
```

> **Spray signature:** High `UniqueAccounts`, low `AttemptsPerAccount` (typically 1–3 per account).

---

### Step 3 — Check for Successful Logon Following Failures

A spray that succeeds will show a 4624 (successful logon) shortly after a cluster of 4625s from the same source.

**[KQL-Sentinel]**
```kql
let SuspiciousSources =
    SecurityEvent
    | where TimeGenerated >= ago(24h)
    | where EventID == 4625 and AuthenticationPackageName == "NTLM"
    | summarize Failures = count(), UniqueAccounts = dcount(TargetUserName) by IpAddress
    | where UniqueAccounts >= 5
    | project IpAddress;
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4624
| where IpAddress in (SuspiciousSources)
| project TimeGenerated, IpAddress, TargetUserName, LogonType, WorkstationName
| sort by TimeGenerated asc
```

Any result here is a **critical pivot** — a spray may have succeeded.

---

### Step 4 — Correlate with Defender XDR Identity Events

**[KQL-XDR]**
```kql
IdentityLogonEvents
| where Timestamp >= ago(24h)
| where ActionType == "LogonFailed"
| where Protocol == "Ntlm"
| summarize
    Failures = count(),
    UniqueAccounts = dcount(AccountName),
    Accounts = make_set(AccountName, 20)
    by IPAddress, bin(Timestamp, 30m)
| where UniqueAccounts >= 5
| sort by UniqueAccounts desc
```

---

### Step 5 — Geolocate and Enrich Source IPs

For each suspicious IP:
- Check if IP is internal (expected NTLM source) or external (immediate red flag)
- Query VirusTotal / AbuseIPDB for reputation
- Check if IP belongs to a known VPN, proxy, or TOR exit node
- Look up ASN — cloud provider IPs (AWS, Azure, DigitalOcean) used for internal auth = suspicious

---

### Step 6 — Review Targeted Accounts

**[KQL-Sentinel]**
```kql
// Check if targeted accounts are privileged
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| where IpAddress == "<suspicious_ip>"  // Replace with finding from Step 2
| summarize Attempts = count() by TargetUserName
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4728 or EventID == 4732  // Members of privileged groups
    | project TargetUserName, GroupName = TargetDomainName
) on TargetUserName
| sort by Attempts desc
```

Privileged accounts (Domain Admins, service accounts) being targeted elevates severity.

---

## Investigation Pivots

| Finding | Next Step |
|---|---|
| External IP source | Immediately block at perimeter firewall, check for VPN/proxy |
| Successful logon after failures | Treat as compromised credential — force password reset, review session activity |
| Privileged accounts targeted | Escalate to P1, notify identity team |
| Multiple source IPs, same pattern | Distributed spray — check if IPs share ASN or geo |
| Spray occurred outside business hours | Higher likelihood of malicious activity |

---

## True Positive Indicators

- Single IP → 10+ unique accounts → 1–3 attempts per account → compressed timeframe
- NTLM logon type 3 (network logon) from external or unexpected source
- Successful logon (4624) immediately following spray from same IP
- Targeted accounts include service accounts or privileged users

---

## False Positive Guidance

| Source | Why it triggers | How to exclude |
|---|---|---|
| Misconfigured application | Retrying with wrong credentials against multiple accounts | Identify app, fix config, allowlist source IP |
| Shared NAT / proxy egress | Multiple users behind one IP cause apparent spray | Cross-reference with user count behind that IP |
| Password policy enforcement tool | Tests accounts for weak passwords | Allowlist known tool IPs and service accounts |
| Load balancer health checks | Repeated auth attempts from single IP | Verify target accounts and allowlist |

---

## Response Actions

**If True Positive:**
1. Block source IP at firewall and in SIEM watchlist
2. Force password reset on all targeted accounts
3. If successful logon confirmed — isolate affected endpoint, revoke active sessions
4. Alert identity team to enable MFA enforcement if not already in place
5. Open P1/P2 incident, initiate IR process
6. Preserve logs (30-day minimum) for forensic review

**If False Positive:**
1. Document source and reason
2. Add exclusion rule to detection logic
3. Update playbook FP section

---

## MITRE ATT&CK Reference

| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.003 — Password Spraying |
| Reference | https://attack.mitre.org/techniques/T1110/003/ |

---

*Last updated: 2025 | Author: Faizaan Sajjad*
