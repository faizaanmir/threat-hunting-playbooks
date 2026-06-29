# Threat Hunting Playbooks

Structured threat hunting playbooks built from real SOC operations experience. Each playbook targets a specific adversary behavior, maps to MITRE ATT&CK, and provides hypothesis-driven hunting steps across SIEM and EDR platforms.

**Platforms covered:** Microsoft Sentinel · Microsoft Defender XDR · IBM QRadar · Splunk · Darktrace

---

## Playbook Index

| Playbook | Tactic | Technique | Platform |
|---|---|---|---|
| [Phishing Initial Access Hunt](initial-access/phishing-initial-access.md) | Initial Access | T1566 | Sentinel, Defender XDR |
| [NTLM Password Spray Hunt](credential-access/ntlm-password-spray.md) | Credential Access | T1110.003 | Sentinel, QRadar |
| [DCSync Credential Dump Hunt](credential-access/dcsync-hunt.md) | Credential Access | T1003.006 | Sentinel, Defender XDR |
| [Lateral Movement via SMB Hunt](lateral-movement/smb-lateral-movement.md) | Lateral Movement | T1021.002 | Sentinel, Defender XDR |
| [Scheduled Task Persistence Hunt](persistence/scheduled-task-persistence.md) | Persistence | T1053.005 | Sentinel, Defender XDR |
| [DNS Exfiltration Hunt](exfiltration/dns-exfiltration.md) | Exfiltration | T1048.003 | Sentinel, Darktrace |

---

## Playbook Structure

Every playbook follows this format:

```
## Overview
## Hypothesis
## Prerequisites (log sources, onboarded assets)
## Hunt Steps (numbered, platform-specific queries included)
## Investigation Pivots
## True Positive Indicators
## False Positive Guidance
## Response Actions
## MITRE ATT&CK Reference
```

---

## How to Use

1. Pick a playbook based on a threat intel tip, alert, or periodic hunt schedule.
2. Validate prerequisites — confirm required log sources are ingesting.
3. Execute hunt steps in order. Document findings at each step.
4. Pivot on any anomalies found using the Investigation Pivots section.
5. If TP confirmed — escalate per your IR process. If FP — document tuning notes.

---

## Platform Query Legend

| Tag | Platform |
|---|---|
| `[KQL-Sentinel]` | Microsoft Sentinel |
| `[KQL-XDR]` | Microsoft Defender XDR Advanced Hunting |
| `[SPL]` | Splunk |
| `[AQL]` | IBM QRadar |

---

*Author: Faizaan Sajjad — Security Specialist, Orange Cyber Defense*
*All examples use sanitized, synthetic data. No client or production data is present.*
