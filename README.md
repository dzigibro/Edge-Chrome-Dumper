## EdgeSavedPasswordsDumper

Based on C# POC by [Tom Jøran Sønstebyseter Rønning](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper)

Ported to C (no dependencies) and extended to target Chrome. Likely works on any chromium based browser.

**Version 2** No UAC prompt. Dumps every other users stored passwords from Edge (Chrome must be running). Admin rights are still required to read other users processes, but the tool bypasses the UAC prompt.

---

## Instructions

1. Download `dumpington(v2).c`
2. Compile:  
   `gcc -o dumpington.exe dumpington.c`
3. Run as administrator or as local user(to obtain current users passwords).

---

## Detection

Most EDRs focus on LSASS, cookie access, and process injection, not `ReadProcessMemory` on browsers. Use the rules below to detect this behaviour.

### Splunk / SIEM query

```xml
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=10 
| where TargetImage in ("*chrome.exe", "*msedge.exe") 
| where AccessMask = 0x0410 
| where SourceImage not like "%\\Windows\\%"
| table TimeCreated, SourceImage, TargetImage, User, GrantedAccess
```

---

### Sysmon Rule 

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="contains">chrome.exe</TargetImage>
  <TargetImage condition="contains">msedge.exe</TargetImage>
  <AccessMask condition="is">0x0410</AccessMask>
  <SourceImage condition="not contains">C:\Windows\</SourceImage>
</ProcessAccess>
```




## Overview
This project is a simple C#/.NET 3.5 tool created to demonstrate that Edge stores credentials in cleartext in memory. It is intended for **educational and research purposes only**, especially for understanding memory inspection, credential handling, and security design differences across software.

I am **not an experienced C# developer**, so the code may contain rough edges, inefficiencies, or non‑idiomatic patterns. Contributions, improvements, and suggestions are welcome.

---

## Purpose
This tool was created to show that whenever a user stores credentials in Edge (using the Microsoft Password Manager feature, e.g. Autofill), ALL credentials are stored in plaintext in the parent Edge process memory. This is obviously problematic in a shared environment (e.g. on a terminal servers) as an attacker can access **all** Edge processes for **all** logged on and disconnected users, and dump their saved credentials.
Microsoft has said that this is "by design" and thus won't fix this.
The tool is meant to support learning, responsible disclosure, and security awareness — not misuse.

---

## Disclaimer
This software is provided **strictly for educational use**.

By using this project, you agree that:
- You are solely responsible for how you use this code  
- You will not use it to violate privacy, security policies, or any applicable laws  
- The author provides **no warranty** of any kind  
- The author **cannot be held liable** for any misuse, damage, or consequences resulting from this software  

You accept full responsibility for ensuring your actions comply with all legal and ethical requirements.

---

## Features
- Demonstrates that Edge stores save credentials in clear text in memory
- .NET 3.5 code in order to avoid potential future AMSI related issues

---

## Requirements
- Edge 147.0.3912.98 or older
- .NET Framework **3.5**  
- Administrator rights (to be able to read other users Edge processes memory)  
