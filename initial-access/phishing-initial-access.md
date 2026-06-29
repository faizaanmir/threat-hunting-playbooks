# Hunt Playbook: Phishing Initial Access

| Field | Detail |
|---|---|
| **Tactic** | Initial Access (TA0001) |
| **Technique** | T1566 — Phishing |
| **Sub-techniques** | T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link) |
| **Platforms** | Microsoft Sentinel, Microsoft Defender XDR, Defender for Office 365 |
| **Data Sources** | EmailEvents, EmailUrlInfo, EmailAttachmentInfo, DeviceProcessEvents |
| **Hunt Frequency** | Daily |
| **Author** | Faizaan Sajjad |

---

## Overview

Phishing remains the most common initial access vector. This playbook covers both attachment-based and link-based phishing delivery, tracking the full chain from email receipt through URL click to potential payload execution.

---

## Hypothesis

> An adversary has delivered a phishing email to one or more users that bypassed email security controls. A user may have clicked a malicious link or opened a weaponized attachment, resulting in code execution or credential harvesting.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Defender for Office 365 Plan 1/2 | Required for EmailEvents, EmailUrlInfo tables |
| Safe Links / Safe Attachments enabled | Provides detonation data |
| Defender XDR Advanced Hunting | For cross-domain correlation |
| URL reputation feeds | VirusTotal, URLhaus, or integrated TI |

---

## Hunt Steps

### Step 1 — Identify Emails That Bypassed Filtering

**[KQL-XDR]**
```kql
EmailEvents
| where Timestamp >= ago(24h)
| where DeliveryAction == "Delivered"
| where EmailDirection == "Inbound"
| where ThreatTypes has_any ("Phish", "Malware", "Spam")
    or ConfidenceLevel in ("High", "Medium")
| project
    Timestamp,
    SenderFromAddress,
    SenderIPv4,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DeliveryLocation,
    NetworkMessageId
| sort by Timestamp desc
```

---

### Step 2 — Find Users Who Clicked Phishing URLs

**[KQL-XDR]**
```kql
EmailUrlInfo
| where Timestamp >= ago(24h)
| where Url !startswith "https://aka.ms"
    and Url !contains "microsoft.com"
| join kind=inner (
    EmailEvents
    | where DeliveryAction == "Delivered"
    | where EmailDirection == "Inbound"
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress
) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Subject, Url, SenderFromAddress
| sort by Timestamp desc
```

---

### Step 3 — Check for Payload Execution Post-Click

**[KQL-XDR]**
```kql
DeviceProcessEvents
| where Timestamp >= ago(24h)
| where InitiatingProcessFileName in~ ("outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe", "winword.exe", "excel.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine
| sort by Timestamp desc
```

Office or browser spawning script interpreters = strong phishing execution signal.

---

### Step 4 — Hunt for Credential Harvesting Page Visits

**[KQL-XDR]**
```kql
DeviceNetworkEvents
| where Timestamp >= ago(24h)
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe")
| where RemoteUrl matches regex @"(login|signin|verify|account|secure|update|microsoft|office365)[^.]*\.[a-z]{2,}\/(login|signin|auth|verify)"
| where not(RemoteUrl has_any ("microsoft.com", "live.com", "office.com", "microsoftonline.com"))
| project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName
| sort by Timestamp desc
```

---

### Step 5 — Check for Suspicious Attachment Execution

**[KQL-XDR]**
```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where InitiatingProcessFileName in~ ("outlook.exe", "winword.exe", "excel.exe")
| where FileName endswith_cs ".exe"
    or FileName endswith_cs ".js"
    or FileName endswith_cs ".vbs"
    or FileName endswith_cs ".hta"
    or FileName endswith_cs ".iso"
    or FileName endswith_cs ".lnk"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, SHA256, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## True Positive Indicators

- Office application spawning cmd.exe, powershell.exe, or wscript.exe
- User visited look-alike login page shortly after receiving phishing email
- Dropped file with unusual extension in Temp, Downloads, or AppData
- Outbound connection to newly registered or low-reputation domain post-click
- Safe Links detonation flagged URL as malicious post-delivery

---

## False Positive Guidance

| Source | Why it triggers | Action |
|---|---|---|
| Phishing simulation tools (KnowBe4, Proofpoint) | Intentional phishing test emails | Correlate with simulation schedule, allowlist simulation domains |
| Marketing emails with tracking links | URL redirectors look suspicious | Check sender reputation and redirect chain |
| Macro-enabled legitimate docs | Finance/ops teams may use macro workbooks | Validate with business unit |

---

## Response Actions

**If True Positive:**
1. Quarantine the email from all mailboxes: Defender portal → Threat Explorer → Purge
2. Block sender domain and IP at email gateway
3. Block malicious URL in Safe Links / firewall
4. If payload executed — isolate endpoint immediately
5. Force password reset if credential harvesting suspected
6. Search for same email/URL/attachment across all mailboxes (lateral phishing)
7. Open incident, notify affected user's manager

---

## MITRE ATT&CK Reference

| Field | Value |
|---|---|
| Tactic | Initial Access |
| Technique | T1566 — Phishing |
| Sub-techniques | T1566.001 (Attachment), T1566.002 (Link) |
| Reference | https://attack.mitre.org/techniques/T1566/ |

---

*Last updated: 2025 | Author: Faizaan Sajjad*
