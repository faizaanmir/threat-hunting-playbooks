# Hunt Playbook: Lateral Movement via SMB

| Field | Detail |
|---|---|
| **Tactic** | Lateral Movement (TA0008) |
| **Technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| **Platforms** | Microsoft Sentinel, Microsoft Defender XDR |
| **Data Sources** | SecurityEvent (4624, 4648, 5140, 5145), DeviceLogonEvents, DeviceNetworkEvents |
| **Hunt Frequency** | Weekly |
| **Author** | Faizaan Sajjad |

---

## Overview

SMB-based lateral movement involves an adversary using valid (stolen or forged) credentials to authenticate to Windows Admin Shares (C$, ADMIN$, IPC$) on remote hosts. Common techniques include PsExec, WMI, sc.exe remote service creation, and Pass-the-Hash. This is one of the most common post-exploitation lateral movement paths in enterprise environments.

---

## Hypothesis

> An adversary with compromised credentials is moving laterally through the environment by authenticating to Windows administrative shares on multiple internal hosts, potentially deploying tools or executing commands remotely.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Security Event logging | Events 4624, 4648, 5140, 5145 must be enabled |
| Object Access auditing | Required for share access events (5140, 5145) |
| Network topology baseline | Needed to identify abnormal host-to-host connections |
| Defender for Identity | Enhances detection with Pass-the-Hash alerts |

---

## Hunt Steps

### Step 1 — Identify Unusual Admin Share Access

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 5140  // Network share accessed
| where ShareName in~ ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$")
| summarize
    AccessCount = count(),
    UniqueTargetHosts = dcount(Computer),
    TargetHosts = make_set(Computer, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SubjectUserName, IpAddress
| where UniqueTargetHosts >= 3   // One account accessing many hosts = lateral movement signal
| sort by UniqueTargetHosts desc
```

---

### Step 2 — Hunt for Pass-the-Hash Pattern

PtH uses NTLM type 3 network logons with a blank or null source workstation name — a known artifact.

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where WorkstationName == "" or WorkstationName == "-"  // PtH artifact
| where TargetUserName !endswith "$"  // Exclude machine accounts
| summarize
    Count = count(),
    TargetHosts = make_set(Computer, 20),
    UniqueHosts = dcount(Computer)
    by IpAddress, TargetUserName, bin(TimeGenerated, 1h)
| where UniqueHosts >= 2
| sort by UniqueHosts desc
```

---

### Step 3 — Detect PsExec / Remote Service Execution

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 7045  // New service installed
| where ServiceFileName has_any ("\\ADMIN$\\", "\\C$\\", "PSEXESVC", "%TEMP%", "cmd.exe /c")
| project TimeGenerated, Computer, ServiceName, ServiceFileName, SubjectUserName
| sort by TimeGenerated desc
```

**[KQL-XDR]**
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where InitiatingProcessFileName =~ "services.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "psexesvc.exe")
| where FolderPath has_any ("\\Windows\\", "\\ADMIN$\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

### Step 4 — Correlate Network Logons Across Multiple Hosts

**[KQL-XDR]**
```kql
DeviceLogonEvents
| where Timestamp >= ago(24h)
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName !endswith "$"
| summarize
    SuccessfulLogons = count(),
    UniqueDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountName, RemoteIP, bin(Timestamp, 1h)
| where UniqueDevices >= 3
| sort by UniqueDevices desc
```

---

### Step 5 — Check for Files Dropped on Remote Shares

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 5145  // Network share object access
| where ShareName in~ ("\\\\*\\C$", "\\\\*\\ADMIN$")
| where RelativeTargetName endswith_cs ".exe"
    or RelativeTargetName endswith_cs ".ps1"
    or RelativeTargetName endswith_cs ".bat"
    or RelativeTargetName endswith_cs ".dll"
| project TimeGenerated, Computer, SubjectUserName, ShareName, RelativeTargetName, IpAddress
| sort by TimeGenerated desc
```

Executables or scripts written to admin shares = strong lateral movement + staging indicator.

---

## True Positive Indicators

- Single account accessing C$ or ADMIN$ on 3+ hosts in a short window
- NTLM type 3 logon with blank workstation name (Pass-the-Hash artifact)
- PSEXESVC service created on remote host
- Executable written to ADMIN$ share from a non-admin workstation
- Logon success on multiple hosts with no matching user activity (e.g., after hours)

---

## False Positive Guidance

| Source | Why it triggers | Action |
|---|---|---|
| SCCM / Intune deployments | Pushes software via admin shares | Allowlist SCCM server IPs and service accounts |
| IT admin remote management | Legitimate PsExec or admin share use by IT | Baseline IT admin accounts, create allowlist |
| Vulnerability scanners | Scan across multiple hosts using admin credentials | Allowlist scanner IP and service account |
| Backup agents | Traverse file system via admin shares | Verify backup schedule correlation |

---

## Response Actions

**If True Positive:**
1. Disable compromised account immediately
2. Isolate source host and all destination hosts accessed
3. Identify all hosts the account successfully authenticated to
4. Check for persistence mechanisms on each accessed host (scheduled tasks, new services, new local accounts)
5. Collect memory and disk images from source host
6. Review what files were accessed or dropped on remote hosts
7. Open P1 incident, initiate full IR process

---

## MITRE ATT&CK Reference

| Field | Value |
|---|---|
| Tactic | Lateral Movement |
| Technique | T1021 — Remote Services |
| Sub-technique | T1021.002 — SMB/Windows Admin Shares |
| Reference | https://attack.mitre.org/techniques/T1021/002/ |

---

*Last updated: 2025 | Author: Faizaan Sajjad*
