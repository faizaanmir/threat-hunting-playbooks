# Hunt Playbook: DCSync Credential Dump

| Field | Detail |
|---|---|
| **Tactic** | Credential Access (TA0006) |
| **Technique** | T1003.006 — OS Credential Dumping: DCSync |
| **Platforms** | Microsoft Sentinel, Microsoft Defender XDR |
| **Data Sources** | Security Event 4662, IdentityDirectoryEvents |
| **Hunt Frequency** | Daily (high-value target, low noise) |
| **Severity if TP** | Critical |
| **Author** | Faizaan Sajjad |

---

## Overview

DCSync is an attack technique where an adversary abuses the Active Directory replication protocol (MS-DRSR) to impersonate a Domain Controller and request password hashes for any account — including KRBTGT. This does not require running code on a DC and leaves minimal footprint compared to tools like Mimikatz run locally.

**Why it's critical:** Obtaining KRBTGT hash enables Golden Ticket attacks — persistent, near-undetectable domain-level access that survives password resets until KRBTGT is rotated twice.

---

## Hypothesis

> An adversary with Domain Admin, SYSTEM, or delegated replication rights is abusing Directory Replication Services to extract credential hashes from Active Directory without touching a Domain Controller.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Advanced Audit Policy | Directory Service Access must be enabled — Event 4662 |
| Object Access auditing | Enable on domain NC head in AD |
| DC hostname list | Required to filter legitimate replication |
| Defender XDR identity coverage | IdentityDirectoryEvents requires Defender for Identity sensor on DCs |

---

## Hunt Steps

### Step 1 — Hunt for Replication Requests from Non-DC Hosts

**[KQL-Sentinel]**
```kql
let dc_hostnames = dynamic(["DC01", "DC02", "DC03"]);  // Update with your DC names

SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4662
| where ObjectType has "domainDNS"
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   // DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   // DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c"    // DS-Replication-Get-Changes-In-Filtered-Set
    )
| where not(Computer in~ (dc_hostnames))
| project
    TimeGenerated,
    SourceHost = Computer,
    RequestingAccount = SubjectUserName,
    Domain = SubjectDomainName,
    ObjectName,
    IpAddress
| sort by TimeGenerated desc
```

**Any result from a non-DC host is high-fidelity.** DCSync from a workstation or member server has no legitimate use case.

---

### Step 2 — Defender XDR / Defender for Identity

**[KQL-XDR]**
```kql
IdentityDirectoryEvents
| where Timestamp >= ago(7d)
| where ActionType == "Directory Service replication"
| extend AdditionalInfo = parse_json(AdditionalFields)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    IPAddress,
    AdditionalInfo
| sort by Timestamp desc
```

Defender for Identity has built-in DCSync detection — cross-reference any alerts in the Defender portal.

---

### Step 3 — Identify the Requesting Account's Privilege Level

**[KQL-Sentinel]**
```kql
// Check if the requesting account is a member of high-privilege groups
SecurityEvent
| where TimeGenerated >= ago(30d)
| where EventID in (4728, 4732, 4756)  // Added to security/admin groups
| where TargetUserName == "<account_from_step1>"  // Replace
| project TimeGenerated, EventID, TargetUserName, MemberName, GroupName = TargetDomainName
```

---

### Step 4 — Check for KRBTGT or Admin Account Hash Requests

If you have object-level logging, check whether KRBTGT specifically was targeted:

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4662
| where ObjectName has "krbtgt" or ObjectName has "Administrator"
| project TimeGenerated, Computer, SubjectUserName, ObjectName, Properties
```

KRBTGT targeted = assume Golden Ticket capability — treat as Critical P0.

---

### Step 5 — Review Lateral Movement Post-DCSync

If DCSync was successful, the attacker now has hashes. Look for Pass-the-Hash or new privileged logons:

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4624
| where LogonType == 3
| where SubjectUserName =~ "<account_from_step1>"
| where not(Computer in~ (dc_hostnames))
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType
| sort by TimeGenerated asc
```

---

## True Positive Indicators

- Replication GUIDs (`1131f6aa`, `1131f6ad`) observed from a workstation or member server
- Requesting account is not a DC computer account (`$` suffix)
- KRBTGT or privileged account specifically targeted
- Source host has Mimikatz, Impacket, or secretsdump artifacts
- New privileged logons from same host shortly after

---

## False Positive Guidance

| Source | Why it triggers | Action |
|---|---|---|
| Azure AD Connect | Syncs password hashes legitimately | Identify AAD Connect server, add to allowlist |
| Microsoft Identity Manager | Directory synchronization | Allowlist MIM service account and host |
| Veeam / backup agents | Some backup solutions replicate AD | Verify, then allowlist if confirmed legitimate |
| Quest / Semperis tools | AD management tools may replicate | Validate with AD team |

---

## Response Actions

**If True Positive:**
1. Immediately isolate source host from network
2. Force password reset on requesting account
3. **Rotate KRBTGT password TWICE** (required to invalidate existing Kerberos tickets — do with 10-hour gap)
4. Revoke all Kerberos tickets domain-wide if KRBTGT targeted
5. Review all privileged account activity for the past 30 days
6. Open P0/Critical incident, notify CISO
7. Preserve memory image of source host for forensic analysis

---

## MITRE ATT&CK Reference

| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | T1003 — OS Credential Dumping |
| Sub-technique | T1003.006 — DCSync |
| Reference | https://attack.mitre.org/techniques/T1003/006/ |

---

*Last updated: 2025 | Author: Faizaan Sajjad*
