# Hunt Playbook: DNS-Based Data Exfiltration

| Field | Detail |
|---|---|
| **Tactic** | Exfiltration (TA0010) |
| **Technique** | T1048.003 — Exfiltration Over Alternative Protocol: DNS |
| **Platforms** | Microsoft Sentinel, Darktrace |
| **Data Sources** | DnsEvents, CommonSecurityLog, DeviceNetworkEvents, Darktrace model breaches |
| **Hunt Frequency** | Weekly |
| **Author** | Faizaan Sajjad |

---

## Overview

DNS exfiltration abuses the DNS protocol to smuggle data out of a network. Adversaries encode data (base64, hex) into DNS query subdomains and send it to an attacker-controlled authoritative DNS server. Because DNS is rarely blocked and often not deeply inspected, it is a reliable covert channel.

**Common tools used by attackers:** iodine, dnscat2, DNSExfiltrator, custom scripts.

---

## Hypothesis

> An adversary with internal access is encoding and exfiltrating sensitive data through DNS queries to an external attacker-controlled domain, evading DLP and network monitoring that focuses on HTTP/S traffic.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| DNS query logging | Must be enabled on DNS servers or captured via network tap |
| Sentinel DNS connector | Microsoft DNS or Sysmon DNS event collection |
| Darktrace coverage | Darktrace's "Anomalous DNS Activity" models cover this well |
| Baseline of normal DNS | Needed to identify high-entropy or high-volume outliers |

---

## Hunt Steps

### Step 1 — Hunt for Unusually Long DNS Query Names

Exfiltration encodes data into subdomains. This produces abnormally long query strings.

**[KQL-Sentinel]**
```kql
DnsEvents
| where TimeGenerated >= ago(7d)
| extend QueryLength = strlen(Name)
| where QueryLength > 100   // Legitimate FQDNs rarely exceed 100 chars
| summarize
    QueryCount = count(),
    UniqueQueries = dcount(Name),
    SampleQueries = make_set(Name, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ClientIP, Computer
| sort by QueryCount desc
```

---

### Step 2 — Hunt for High-Entropy Subdomain Labels

Data encoded in base64 or hex has high character entropy. Look for subdomain labels that look random.

**[KQL-Sentinel]**
```kql
DnsEvents
| where TimeGenerated >= ago(7d)
| where Name matches regex @"[a-zA-Z0-9+/=]{20,}\."  // Long base64-like label
| summarize
    Count = count(),
    Domains = make_set(Name, 10),
    Sources = make_set(ClientIP, 10)
    by bin(TimeGenerated, 1h)
| sort by Count desc
```

---

### Step 3 — Hunt for High Query Volume to a Single External Domain

Exfiltration sends many queries to one domain (each query carries a chunk of data).

**[KQL-Sentinel]**
```kql
DnsEvents
| where TimeGenerated >= ago(24h)
| where Name !endswith "microsoft.com"
    and Name !endswith "windows.com"
    and Name !endswith "office.com"
    and Name !endswith "azure.com"   // Extend allowlist to your environment
| extend RootDomain = tostring(split(Name, ".")[-2]) + "." + tostring(split(Name, ".")[-1])
| summarize
    TotalQueries = count(),
    UniqueSubdomains = dcount(Name),
    Sources = make_set(ClientIP, 10)
    by RootDomain
| where UniqueSubdomains > 50   // Many unique subdomains to one root = exfil signal
| sort by UniqueSubdomains desc
```

---

### Step 4 — Darktrace Model Breach Review

In Darktrace, check for these model breaches (adjust names to your deployment):

- **Anomalous Connection / DNS Data Exfiltration**
- **Unusual DNS Activity**
- **Large Volume of DNS Queries to Rare Domain**
- **Device / Possible DNS Tunnelling**

For any breach, extract the destination domain and pivot to Steps 5–6.

---

### Step 5 — Enrich Suspicious Domains

For each suspicious root domain found in Steps 1–3:
- Query VirusTotal for domain reputation and passive DNS
- Check domain registration age (newly registered = red flag)
- Review authoritative nameservers (free DNS providers like Hurricane Electric used by attackers)
- Look for NS records pointing to known C2 infrastructure

---

### Step 6 — Correlate with Endpoint Activity

**[KQL-XDR]**
```kql
DeviceNetworkEvents
| where Timestamp >= ago(24h)
| where RemotePort == 53
| where RemoteUrl has "<suspicious_domain>"  // Replace with finding
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl
| sort by Timestamp asc
```

Identify which process is making the DNS queries. `nslookup`, `cmd.exe`, `powershell.exe`, or unknown processes sending DNS = highly suspicious.

---

## True Positive Indicators

- Subdomain labels > 30 characters with high character entropy
- 50+ unique subdomains to a single recently-registered domain
- DNS queries from a process that has no legitimate DNS need (cmd.exe, python.exe)
- Queries contain base64 or hex-decodable strings
- Domain has no web presence, no MX records, but has A/NS records pointing to VPS

---

## False Positive Guidance

| Source | Why it triggers | Action |
|---|---|---|
| CDN providers (Akamai, Cloudflare) | Long, encoded cache keys in subdomains | Allowlist known CDN domains |
| Security tools (CrowdStrike, Defender) | Telemetry sent over DNS-based channels | Verify vendor, allowlist |
| Software update mechanisms | Random-looking update server subdomains | Correlate with expected update traffic |
| Internal monitoring tools | Long query names from synthetic monitoring | Identify and allowlist |

---

## Response Actions

**If True Positive:**
1. Block destination domain at DNS sinkholes and firewall
2. Isolate source endpoint
3. Review what data was accessed on the source host in the 24–48 hours prior
4. Assess data sensitivity — if PII or confidential data, initiate breach notification process
5. Preserve full DNS query log for forensics
6. Conduct broader hunt — check if other endpoints queried the same domain

---

## MITRE ATT&CK Reference

| Field | Value |
|---|---|
| Tactic | Exfiltration |
| Technique | T1048 — Exfiltration Over Alternative Protocol |
| Sub-technique | T1048.003 — DNS |
| Reference | https://attack.mitre.org/techniques/T1048/003/ |

---

*Last updated: 2025 | Author: Faizaan Sajjad*
