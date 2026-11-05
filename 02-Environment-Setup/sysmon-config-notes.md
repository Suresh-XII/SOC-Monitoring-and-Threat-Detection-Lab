# Sysmon Configuration & Tuning Guide

## Overview

Microsoft Sysinternals **Sysmon (System Monitor)** is a Windows system service and device driver that remains resident across system reboots to monitor and log system activity to the Windows event log. In this lab, Sysmon v15.x is used to provide deep endpoint visibility beyond default Windows Event Auditing.

The driver logs into `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`.

---

## Installation & Deployment

Sysmon is installed with administrative privileges using the following command:

```cmd
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

To update an existing installation without restarting the service:
```cmd
Sysmon64.exe -c sysmonconfig.xml
```

---

## Sysmon Modular Configuration Snippets

### 1. Process Creation (Event ID 1)
Logs process creation with command-line arguments, parent process details, and cryptographic hashes (SHA256, MD5).

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="ProcessCreation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Suspicious user-writable execution paths -->
        <Image condition="contains">\AppData\Local\Temp\</Image>
        <Image condition="contains">\AppData\Roaming\</Image>
        <Image condition="contains">\Users\Public\</Image>
        <Image condition="contains">\Downloads\</Image>
        <Image condition="contains">\ProgramData\</Image>

        <!-- Common Living-off-the-Land Binaries (LOLBins) -->
        <Image condition="image">powershell.exe</Image>
        <Image condition="image">pwsh.exe</Image>
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">wmic.exe</Image>
        <Image condition="image">mshta.exe</Image>
        <Image condition="image">certutil.exe</Image>
        <Image condition="image">bitsadmin.exe</Image>
        <Image condition="image">regsvr32.exe</Image>
        <Image condition="image">cscript.exe</Image>
        <Image condition="image">wscript.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 2. Network Connections (Event ID 3)
Monitors TCP/UDP connections initiated by endpoints. Crucial for detecting reverse shells, command and control (C2) beaconing, and network scanning.

```xml
<RuleGroup name="NetworkConnections" groupRelation="or">
  <NetworkConnect onmatch="include">
    <!-- Monitor suspicious outbound ports -->
    <DestinationPort condition="is">22</DestinationPort>     <!-- SSH -->
    <DestinationPort condition="is">4444</DestinationPort>   <!-- Metasploit default -->
    <DestinationPort condition="is">1337</DestinationPort>   <!-- Common listener -->
    <DestinationPort condition="is">3389</DestinationPort>   <!-- RDP -->
    <DestinationPort condition="is">8080</DestinationPort>   <!-- Web proxy/alt HTTP -->

    <!-- Monitor network activity from script engines and shells -->
    <Image condition="image">powershell.exe</Image>
    <Image condition="image">cmd.exe</Image>
    <Image condition="image">wscript.exe</Image>
    <Image condition="image">cscript.exe</Image>
    <Image condition="image">rundll32.exe</Image>
  </NetworkConnect>
</RuleGroup>
```

### 3. File Creation (Event ID 11)
Detects file creation in sensitive or temporary folders, specifically targeting executable extensions (`.exe`, `.dll`, `.vbs`, `.ps1`, `.bat`).

```xml
<RuleGroup name="FileCreation" groupRelation="or">
  <FileCreate onmatch="include">
    <!-- Monitor executable drops into user-writable directories -->
    <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
    <TargetFilename condition="contains">\AppData\Roaming\</TargetFilename>
    <TargetFilename condition="contains">\Users\Public\</TargetFilename>
    <TargetFilename condition="contains">\Downloads\</TargetFilename>
    <TargetFilename condition="contains">\ProgramData\</TargetFilename>
  </FileCreate>
  <FileCreate onmatch="exclude">
    <!-- Exclude benign installer noise -->
    <TargetFilename condition="end with">.tmp</TargetFilename>
  </FileCreate>
</RuleGroup>
```

---

## Filtering Strategy & Noise Reduction

1. **Include-First Rules:** To prevent log volume exhaustion and licensing consumption in Splunk, rules are scoped to capture known attacker TTPs (e.g. execution out of `\Temp\` or `\Public\`) rather than logging all OS operations.
2. **Exclusion Tuning:** Standard Windows background processes (e.g. OneDrive updates, Windows Update, Defender telemetry) are explicitly excluded to maintain high signal-to-noise ratio.
