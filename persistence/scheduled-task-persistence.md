# Hunt Playbook: Scheduled Task Persistence

| Field | Detail |
|---|---|
| **Tactic** | Persistence (TA0003), Privilege Escalation (TA0004) |
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Platforms** | Microsoft Sentinel, Microsoft Defender XDR |
| **Data Sources** | SecurityEvent (4698, 4702), DeviceProcessEvents, DeviceScheduledTaskEvents |
| **Hunt Frequency** | Weekly |
| **Author** | Faizaan Sajjad |

---

## Overview

Scheduled tasks are a common persistence mechanism. Adversaries create tasks to execute malicious payloads on a recurring basis, survive reboots, or run at specific triggers (logon, system startup). They are also used for privilege escalation when a task runs as SYSTEM or a higher-privileged account.

---

## Hypothesis

> An adversary with local or domain access has created a scheduled task to maintain persistence on a compromised host, executing a malicious payload at regular intervals or system events.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Security Event logging | Event 4698 (task created), 4702 (task updated) |
| Task Scheduler audit policy | Enable under Advanced Audit → Object Access |
| Defender XDR coverage | DeviceScheduledTaskEvents available with MDE onboarding |

---

## Hunt Steps

### Step 1 — Hunt for Newly Created Scheduled Tasks

**[KQL-Sentinel]**
```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4698  // Scheduled task created
| extend TaskXML = EventData
| project
    TimeGenerated,
    Computer,
    SubjectUserName,
    SubjectDomainName,
    TaskName = tostring(EventData),
    TaskContent = EventData
| sort by TimeGenerated desc
```

---

### Step 2 — Identify Tasks with Suspicious Actions

**[KQL-XDR]**
```kql
DeviceScheduledTaskEvents
| where Timestamp >= ago(7d)
| where ActionType == "ScheduledTaskCreated" or ActionType == "ScheduledTaskUpdated"
| where ScheduledTaskName !startswith "\\Microsoft\\"  // Exclude built-in Windows tasks
| extend TaskActions = tostring(parse_json(AdditionalFields).TaskContent)
| where TaskActions has_any (
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "rundll32", "regsvr32", "certutil",
    "bitsadmin", "http://", "https://", "%TEMP%", "%APPDATA%"
    )
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ScheduledTaskName,
    TaskActions
| sort by Timestamp desc
```

---

### Step 3 — Hunt for Tasks Running from Suspicious Paths

**[KQL-XDR]**
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where InitiatingProcessFileName =~ "taskeng.exe"
    or InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has "Schedule"
| where FolderPath has_any (
    "\\Temp\\", "\\AppData\\", "\\Downloads\\",
    "\\Public\\", "\\ProgramData\\"
    )
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    SHA256
| sort by Timestamp desc
```

Legitimate scheduled tasks rarely execute binaries from user-writable directories.

---

### Step 4 — Detect Tasks Created via Command Line

**[KQL-XDR]**
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (
    "powershell", "cmd /c", "wscript", "mshta",
    "http://", "https://", "%TEMP%", "%APPDATA%", "rundll32"
    )
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by Timestamp desc
```

---

### Step 5 — Check Task Run Frequency and Trigger

Tasks set to run every minute or at logon with no legitimate owner are red flags.

**[KQL-XDR]**
```kql
DeviceScheduledTaskEvents
| where Timestamp >= ago(7d)
| where ActionType == "ScheduledTaskCreated"
| where ScheduledTaskName !startswith "\\Microsoft\\"
| extend Fields = parse_json(AdditionalFields)
| extend Trigger = tostring(Fields.TaskTrigger)
| where Trigger has_any ("PT1M", "PT5M", "logon", "boot", "startup")  // High-frequency or system triggers
| project Timestamp, DeviceName, InitiatingProcessAccountName, ScheduledTaskName, Trigger
| sort by Timestamp desc
```

---

## True Positive Indicators

- Task created by non-admin user account
- Task executing from Temp, AppData, or Downloads
- Task action contains encoded PowerShell or HTTP download
- Task runs as SYSTEM but was created by a standard user
- Task name mimics legitimate Windows task names (e.g., `\Microsoft\Windows\WindowsUpdate\UpdateCheck`)

---

## False Positive Guidance

| Source | Why it triggers | Action |
|---|---|---|
| Software installers | Create tasks for update checks | Correlate with installation activity, allowlist known software |
| Security tools | EDR/AV agents use scheduled tasks | Verify vendor tasks, allowlist |
| Admin scripts | IT automation via schtasks.exe | Baseline known admin scripts and accounts |
| RMM tools | Remote management creates tasks | Identify RMM service account, allowlist |

---

## Response Actions

**If True Positive:**
1. Disable and delete the malicious scheduled task
2. Identify and terminate the malicious process if running
3. Hash and submit task payload to VirusTotal / sandbox
4. Check for additional persistence (registry run keys, services, startup folder)
5. Determine how task was created — trace back to initial access vector
6. Isolate host if active compromise suspected
7. Review other hosts for same task name or payload hash

---

## MITRE ATT&CK Reference

| Field | Value |
|---|---|
| Tactic | Persistence, Privilege Escalation |
| Technique | T1053 — Scheduled Task/Job |
| Sub-technique | T1053.005 — Scheduled Task |
| Reference | https://attack.mitre.org/techniques/T1053/005/ |

---

*Last updated: 2025 | Author: Faizaan Sajjad*
