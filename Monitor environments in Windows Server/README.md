# Windows Server Auditing & Security Monitoring Guide

> **Comprehensive guide to implementing security auditing, diagnostics, and monitoring in Windows Server environments**

---

## Table of Contents

- [Overview](#overview)
- [Understanding Auditing Categories](#understanding-auditing-categories)
  - [Basic Auditing](#basic-auditing)
  - [Advanced Auditing](#advanced-auditing)
- [Detailed Category Explanations](#detailed-category-explanations)
- [Implementation Scenarios](#implementation-scenarios)
- [Configuration Guides](#configuration-guides)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

### What is Windows Server Auditing?

**Windows Server Auditing** is a security mechanism that records events and activities in the Windows Security Log. Think of it as a security camera system for your server—it watches, records, and alerts you to important security-related activities.

### Why Auditing Matters

```
┌─────────────────────────────────────────────────────────────┐
│  SECURITY LAYERS IN WINDOWS SERVER                          │
├─────────────────────────────────────────────────────────────┤
│  1. Prevention  → Firewalls, ACLs, Authentication           │
│  2. Detection   → AUDITING (what we focus on here)          │
│  3. Response    → Incident response, forensics              │
│  4. Recovery    → Backups, disaster recovery                │
└─────────────────────────────────────────────────────────────┘
```

### Key Benefits

| Benefit | Description | Business Impact |
|---------|-------------|-----------------|
| **Accountability** | Track who did what and when | Compliance requirements (SOX, HIPAA, GDPR) |
| **Threat Detection** | Identify malicious attempts | Early breach detection |
| **Forensics** | Historical data for investigations | Legal evidence, root cause analysis |
| **Compliance** | Prove security controls exist | Pass audits, avoid penalties |
| **Operational Insight** | Understand resource usage | Optimize permissions, identify misuse |

---

## Understanding Auditing Categories

Windows Server provides **two levels** of auditing granularity:

### Comparison: Basic vs. Advanced Auditing

| Feature | Basic Auditing | Advanced Auditing |
|---------|---------------|-------------------|
| **Categories** | 9 broad categories | 10 categories with 60+ sub-settings |
| **Granularity** | Broad (Success/Failure) | Highly specific (per-operation) |
| **Use Case** | Small-medium environments | Enterprise, high-security environments |
| **Log Volume** | Moderate | Potentially very high |
| **Configuration** | Simple | Requires planning |

---

## Basic Auditing Categories (Deep Dive)

### 1. Audit Account Logon Events

**What it tracks:** Authentication attempts against Active Directory accounts

```
SCENARIO: Domain User Login
─────────────────────────────────────────────────────────
User Action:     Alice logs into her workstation (WS-01)
Event Generated: Account Logon Event on DOMAIN CONTROLLER
Location:        Security Log on DC (NOT the workstation)
Event ID:        4768 (Kerberos TGT requested)
                 4769 (Kerberos service ticket requested)
                 4776 (NTLM authentication)

WHY THIS MATTERS:
- Tracks authentication at the domain level
- Helps detect: Password attacks, lateral movement
- Critical for: Identifying compromised credentials
```

**Real-World Use Case: Detecting Brute Force Attacks**

```powershell
# PowerShell: Detect multiple failed logon attempts
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4771, 4768  # Failed Kerberos pre-authentication
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object { $_.Properties[0].Value -eq '0x18' } |  # Bad password
Group-Object -Property { $_.Properties[2].Value } |       # Group by username
Where-Object { $_.Count -gt 5 } |                         # More than 5 failures
Select-Object Name, Count
```

**Configuration Recommendation:**
- **Enable Failure auditing** on all domain controllers
- **Enable Success auditing** only if you need login reports
- **Volume Impact:** High in large environments (every user login)

---

### 2. Audit Logon Events

**What it tracks:** Interactive and network logons to a specific computer

```
SCENARIO: Different Logon Types
─────────────────────────────────────────────────────────
Type 2  (Interactive):    User logs on at keyboard (console)
Type 3  (Network):        User accesses shared folder
Type 4  (Batch):          Scheduled task runs
Type 5  (Service):        Service starts with user account
Type 7  (Unlock):         Workstation unlocked
Type 10 (RemoteDesktop):  RDP connection established

EVENT IDs:
4624 - Successful logon
4625 - Failed logon
4634 - Logoff
4647 - User-initiated logoff
4648 - Explicit credential logon (RunAs)
```

**Real-World Use Case: Detecting Unauthorized RDP Access**

```
ALERT SCENARIO: After-Hours RDP Connection
─────────────────────────────────────────────────────────
Time:     2:47 AM (outside business hours)
User:     john.doe (marketing employee)
Source:   IP 185.220.101.x (foreign IP range)
Action:   Successful RDP logon (Type 10)

INVESTIGATION STEPS:
1. Check if john.doe is on vacation/traveling
2. Verify if IP is from VPN pool
3. Check for concurrent sessions (compromised credentials?)
4. Review recent password changes
5. Check for other accounts accessed from same IP
```

**Configuration Recommendation:**
- **Workstations:** Audit Failure (detect local admin abuse)
- **Servers:** Audit Success and Failure (track access)
- **Domain Controllers:** Audit Success and Failure

---

### 3. Audit Account Management

**What it tracks:** Changes to user, group, and computer accounts

```
CRITICAL EVENTS TO MONITOR:
─────────────────────────────────────────────────────────
4720 - User account created
4722 - User account enabled
4723 - Password change attempted
4724 - Password reset attempted
4725 - User account disabled
4726 - User account deleted
4732 - Member added to security-enabled local group
4735 - Security-enabled local group modified
4737 - Security-enabled global group modified
4756 - Member added to security-enabled universal group
```

**Real-World Use Case: Privilege Escalation Detection**

```
ATTACK SCENARIO: Malicious Insider
─────────────────────────────────────────────────────────
Timeline:
09:00 AM - User 'helpdesk_tech' logs in (normal)
09:15 AM - User added to 'Domain Admins' group (ALERT!)
09:20 AM - User accesses CEO's mailbox
09:45 AM - User removed from 'Domain Admins' (covering tracks)

DETECTION:
Event ID 4732: Member added to Domain Admins
Subject: helpdesk_tech
Target:  Domain Admins

RESPONSE:
1. Immediate account disable
2. Check what resources were accessed
3. Review all actions by this user in last 30 days
4. Check for other privilege escalations
```

**Configuration Recommendation:**
- **Always enable Success and Failure**
- **Critical for:** All domain controllers
- **Volume Impact:** Low to moderate (depends on account activity)

---

### 4. Audit Directory Service Access

**What it tracks:** Access to Active Directory objects (when SACLs are configured)

```
HOW IT WORKS:
─────────────────────────────────────────────────────────
1. Enable "Audit Directory Service Access" policy
2. Configure SACL on specific AD objects
3. Windows logs access attempts to those objects

EXAMPLE SACL CONFIGURATION:
Object:     OU=Finance,DC=company,DC=com
Principal:  Everyone
Access:     Write all properties
Audit:      Failure

RESULT: Logs any failed attempt to modify Finance OU
```

**Real-World Use Case: Protecting Sensitive OUs**

```
SCENARIO: Protecting Admin Accounts OU
─────────────────────────────────────────────────────────
Target:     OU=Tier0-Admins,DC=company,DC=com
SACL:       Everyone - Write - Failure

ATTACK ATTEMPT:
Attacker compromises helpdesk account
Attempts to add user to OU=Tier0-Admins
Action fails (insufficient permissions)
Event logged: Event ID 4662 (Failed DS access)

VALUE: Early warning of privilege escalation attempts
```

**Configuration Recommendation:**
- **Enable Success and Failure**
- **Configure SACLs** on sensitive OUs only (too verbose otherwise)
- **Volume Impact:** High if SACLs are broad

---

### 5. Audit Policy Change

**What it tracks:** Changes to security policies

```
EVENTS MONITORED:
─────────────────────────────────────────────────────────
4715 - Object access audit policy changed (SACL)
4719 - System audit policy changed
4739 - Domain policy changed
4902 - Per-user audit policy table created
4904 - Attempt to register security event source
4905 - Attempt to unregister security event source
4906 - CrashOnAuditFail value changed
4907 - Auditing settings on object changed
4912 - Per-user audit policy changed
```

**Real-World Use Case: Detecting Audit Policy Tampering**

```
ATTACK SCENARIO: Covering Tracks
─────────────────────────────────────────────────────────
Attacker gains admin access
Disables auditing to hide activities

DETECTION:
Event ID 4719: System audit policy changed
Subject: compromised_admin
Changes: "Audit Logon Events" changed from Success/Failure to No Auditing

IMMEDIATE ALERT: Any audit policy change should trigger investigation
```

**Configuration Recommendation:**
- **Always enable Success and Failure**
- **Critical for:** All systems
- **Volume Impact:** Low (policy changes are infrequent)

---

### 6. Audit Privilege Use

**What it tracks:** Use of sensitive privileges (user rights)

```
KEY PRIVILEGES TO MONITOR:
─────────────────────────────────────────────────────────
SeBackupPrivilege          - Bypass file security for backup
SeDebugPrivilege           - Debug programs (access any process)
SeRestorePrivilege         - Bypass file security for restore
SeTakeOwnershipPrivilege   - Take ownership of objects
SeTcbPrivilege             - Act as part of OS (highest risk)
SeSecurityPrivilege        - Manage auditing and security log
SeLoadDriverPrivilege      - Load/unload device drivers
```

**Real-World Use Case: Detecting Credential Dumping**

```
ATTACK SCENARIO: Mimikatz Usage
─────────────────────────────────────────────────────────
Tool:       Mimikatz (credential dumping)
Requires:   SeDebugPrivilege (to read LSASS memory)

DETECTION:
Event ID 4673: Sensitive privilege use
Privilege: SeDebugPrivilege
Process:   C:\Users\hacker\mimikatz.exe
Result:    Success (if policy allows) or Failure

NOTE: Legitimate processes (antivirus, system tools) also use this
      Requires baseline of normal activity
```

**Configuration Recommendation:**
- **Enable Failure** (Success can be very noisy)
- **Focus on:** SeDebugPrivilege, SeBackupPrivilege
- **Volume Impact:** Very high if Success is enabled

---

### 7. Audit System Events

**What it tracks:** System-level security events

```
EVENTS MONITORED:
─────────────────────────────────────────────────────────
512  - Windows startup
513  - Windows shutdown
514  - Authentication package loaded
515  - Logon process registered
516  - Internal resources allocated for queuing
517  - Audit log cleared (CRITICAL!)
518  - Notification package loaded
519  - Process using invalid local RPC
520  - System time changed

SECURITY IMPLICATIONS:
- Event 517: Attacker clearing logs to hide tracks
- Event 512/513: Unexpected reboots (possible crash/patch)
- Event 520: Time changes (affect log correlation)
```

**Real-World Use Case: Log Clearing Detection**

```
CRITICAL ALERT SCENARIO:
─────────────────────────────────────────────────────────
Event ID: 517 (Legacy) or 1102 (Modern)
Action:   Security log cleared
User:     SYSTEM or specific admin

IMMEDIATE ACTIONS:
1. Verify if this was authorized (change management?)
2. If unauthorized: Assume breach
3. Check for other logs (System, Application, Forwarded Events)
4. Review network logs for same timeframe
5. Check backup integrity

ATTACK CONTEXT:
- Common step in APT (Advanced Persistent Threat) cleanup
- Often preceded by mass failed logon attempts
- May indicate successful privilege escalation
```

**Configuration Recommendation:**
- **Always enable Success and Failure**
- **Critical for:** All systems
- **Volume Impact:** Low

---

### 8. Audit Process Tracking

**What it tracks:** Process creation and termination

```
EVENTS MONITORED:
─────────────────────────────────────────────────────────
4688 - Process created (NEW PROCESS NAME)
4689 - Process exited
4696 - Primary token assigned to process

DETAILS CAPTURED:
- New Process Name (executable path)
- Creator Process Name (parent process)
- Process Command Line (arguments)
- Token Elevation Type (admin rights?)
```

**Real-World Use Case: Detecting Malicious PowerShell**

```
DETECTION SCENARIO:
─────────────────────────────────────────────────────────
Event ID: 4688
New Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Command Line: powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==
Parent Process: C:\Windows\System32\svchost.exe (suspicious!)

DECODED COMMAND: Start-Sleep -s 10

RED FLAGS:
1. Base64 encoded command (hiding intent)
2. Unusual parent process (should be explorer.exe or cmd.exe)
3. Network connections from PowerShell process

RECOMMENDED: Enable command line logging via GPO
Computer Config > Admin Templates > System > Audit Process Creation > Include command line
```

**Configuration Recommendation:**
- **Enable Success** for high-security environments
- **Volume Impact:** Very high (every program launch)
- **Mitigation:** Use only on critical servers, not workstations

---

### 9. Audit Object Access

**What it tracks:** Access to files, folders, registry keys, printers (when SACLs configured)

```
CONFIGURATION STEPS:
─────────────────────────────────────────────────────────
1. Enable "Audit Object Access" policy (Success/Failure)
2. Configure SACL on specific files/folders
3. Monitor Security Log for events

EVENT IDs:
4663 - Attempt to access object
4656 - Handle to object requested
4658 - Handle to object closed
4664 - Hard link created
4670 - Permissions changed on object
```

**Real-World Use Case: Monitoring Sensitive File Access**

```
SCENARIO: Customer Database Protection
─────────────────────────────────────────────────────────
Resource:   D:\Data\CustomerDB.mdf
SACL:       Everyone - Write, Delete - Failure
            Domain Admins - Full Control - Success

NORMAL ACTIVITY:
- SQL Server service account reads file (expected)
- Backup account reads file (expected)

ALERT TRIGGERED:
Event ID 4663 - Failed access attempt
User: marketing_intern
Access: WriteData (attempted modification)
Process: C:\Windows\System32\notepad.exe

INVESTIGATION:
- Why is marketing intern accessing production database?
- Possible data exfiltration attempt?
- Check if file was copied elsewhere
```

**Configuration Recommendation:**
- **Enable Failure** on sensitive data locations
- **Enable Success** only for compliance requirements
- **Volume Impact:** Extremely high if broadly applied

---

## Implementation Scenarios

### Scenario 1: Financial Services Compliance (SOX)

**Requirements:**
- Track all access to financial data
- Monitor changes to financial applications
- Detect unauthorized privilege escalation
- Retain logs for 7 years

**Solution Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│  TIER 1: DOMAIN CONTROLLERS                                 │
│  • Audit Account Logon Events: Success, Failure             │
│  • Audit Account Management: Success, Failure               │
│  • Audit Directory Service Access: Success, Failure         │
│  • Audit Policy Change: Success, Failure                    │
│  • Audit System Events: Success, Failure                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  TIER 2: FINANCIAL APPLICATION SERVERS                      │
│  • Audit Logon Events: Success, Failure                     │
│  • Audit Object Access: Failure (with SACLs on data)        │
│  • Audit Process Tracking: Success                          │
│  • Audit Privilege Use: Failure                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  TIER 3: WORKSTATIONS                                       │
│  • Audit Logon Events: Failure                              │
│  • Audit Object Access: Failure (sensitive shares only)     │
└─────────────────────────────────────────────────────────────┘
```

**Implementation Steps:**

```powershell
# Step 1: Create GPO for Financial Servers
$GPO = New-GPO -Name "Financial-Server-Auditing" 
New-GPLink -Name "Financial-Server-Auditing" -Target "OU=Finance-Servers,DC=corp,DC=com"

# Step 2: Configure via Group Policy Management Editor
# Computer Config > Policies > Windows Settings > Security Settings > Local Policies > Audit Policy

# Step 3: Configure SACLs on critical data
$path = "\\server\finance\"
$acl = Get-Acl $path

# Add audit rule for Everyone, Failed Write/Delete
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    [System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Delete,
    [System.Security.AccessControl.AuditFlags]::Failure
)
$acl.AddAuditRule($auditRule)
Set-Acl $path $acl

# Step 4: Configure event log retention (7 years)
wevtutil sl Security /rt:true /ab:true /ms:2147483648  # 2GB max size, auto backup

# Step 5: Forward events to SIEM
wecutil cs subscription.xml  # Configure Windows Event Collector
```

---

### Scenario 2: Detecting Ransomware Activity

**Attack Pattern:**
1. Initial compromise (phishing, RDP brute force)
2. Lateral movement
3. Privilege escalation
4. Mass file encryption

**Detection Strategy:**

```
PHASE 1: INITIAL ACCESS DETECTION
─────────────────────────────────────────────────────────
Policy: Audit Logon Events (Failure)
Alert:  10+ failed logons from single IP in 5 minutes
Event:  4625 (Failed logon)

Policy: Audit Account Logon Events (Failure)  
Alert:  Multiple failed Kerberos pre-authentication
Event:  4771 (Kerberos pre-auth failed)

PHASE 2: LATERAL MOVEMENT DETECTION
─────────────────────────────────────────────────────────
Policy: Audit Logon Events (Success)
Alert:  Same account logging to multiple systems rapidly
Event:  4624 (Successful logon)

Policy: Audit Process Tracking (Success)
Alert:  PsExec, WMIExec, or PowerShell remoting
Event:  4688 (Process creation with suspicious parent)

PHASE 3: PRIVILEGE ESCALATION
─────────────────────────────────────────────────────────
Policy: Audit Privilege Use (Failure)
Alert:  SeDebugPrivilege usage by non-admin tools
Event:  4673 (Sensitive privilege use)

Policy: Audit Account Management (Success)
Alert:  Account added to Domain Admins
Event:  4728 (Member added to global group)

PHASE 4: ENCRYPTION DETECTION
─────────────────────────────────────────────────────────
Policy: Audit Object Access (Failure)
Alert:  Mass file access denials (files being encrypted)
Event:  4663 (Access to object - WriteData)

Policy: Audit Process Tracking (Success)
Alert:  Unknown process accessing many files rapidly
Event:  4688 (Process creation - suspicious .exe)
```

**Automated Response Script:**

```powershell
# Ransomware Detection & Response
# Run as scheduled task every 5 minutes

$AlertThreshold = 100  # File modifications in 5 minutes
$TimeWindow = (Get-Date).AddMinutes(-5)

# Check for mass file modifications
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
    StartTime = $TimeWindow
} | Where-Object { $_.Message -like "*WriteData*" -or $_.Message -like "*Delete*" }

$grouped = $events | Group-Object -Property { $_.Properties[1].Value }  # Group by process name

foreach ($process in $grouped) {
    if ($process.Count -gt $AlertThreshold) {
        # Potential ransomware activity detected
        $processName = $process.Name
        $processId = ($process.Group | Select-Object -First 1).Properties[2].Value

        # Immediate actions
        Write-EventLog -LogName Application -Source "RansomwareDetection" -EventId 9999 -EntryType Warning -Message "Potential ransomware: $processName modified $($process.Count) files"

        # Isolate system (disable network adapter)
        # Get-NetAdapter | Disable-NetAdapter -Confirm:$false

        # Kill process
        # Stop-Process -Id $processId -Force

        # Send alert
        Send-MailMessage -To "security@company.com" -From "alerts@company.com" -Subject "CRITICAL: Potential Ransomware Activity" -Body "Process $processName on $env:COMPUTERNAME"
    }
}
```

---

### Scenario 3: Insider Threat Detection

**Threat Model:**
- Departing employees stealing data
- Privileged users abusing access
- Contractors accessing unauthorized resources

**Monitoring Strategy:**

```
DATA EXFILTRATION INDICATORS:
─────────────────────────────────────────────────────────
1. Unusual access patterns
   - Accessing files outside normal hours
   - Accessing files never touched before
   - Bulk copying to USB (Event ID 6416 - new USB device)

2. Permission changes
   - Creating backdoor accounts (Event 4720)
   - Adding self to privileged groups (Event 4732)
   - Modifying SACLs to hide activity (Event 4715)

3. Data staging
   - Zipping large amounts of data
   - Accessing database export tools
   - Connecting to personal cloud storage

AUDIT CONFIGURATION:
─────────────────────────────────────────────────────────
Workstations:
- Audit Logon Events: Success, Failure
- Audit Object Access: Success, Failure (on sensitive shares)
- Audit Process Tracking: Success (high disk usage, consider filtering)
- Audit Removable Storage: Success (requires additional policy)

Servers:
- Audit Logon Events: Success, Failure
- Audit Object Access: Failure (prevent data access)
- Audit Account Management: Success, Failure
- Audit Privilege Use: Failure
```

**User Behavior Analytics Query:**

```powershell
# Detect anomalous file access
# Compare current week to previous 4-week baseline

$currentWeek = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
    StartTime = (Get-Date).AddDays(-7)
} | Group-Object -Property { $_.Properties[0].Value }  # Group by username

$baseline = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
    StartTime = (Get-Date).AddDays(-28)
    EndTime = (Get-Date).AddDays(-7)
} | Group-Object -Property { $_.Properties[0].Value }

foreach ($user in $currentWeek) {
    $baselineAvg = ($baseline | Where-Object { $_.Name -eq $user.Name }).Count / 4
    $currentCount = $user.Count

    if ($currentCount -gt ($baselineAvg * 3)) {  # 3x normal activity
        Write-Output "ALERT: User $($user.Name) has $currentCount file accesses vs baseline $baselineAvg"
    }
}
```

---

## Configuration Guides

### Method 1: Local Security Policy (Single Server)

```
Step-by-Step:
─────────────────────────────────────────────────────────
1. Run: secpol.msc
2. Navigate to: Security Settings > Local Policies > Audit Policy
3. Double-click policy to configure
4. Check "Define these policy settings"
5. Select Success and/or Failure
6. Click OK
7. Run: gpupdate /force (or wait for automatic refresh)

VERIFICATION:
- Open Event Viewer (eventvwr.msc)
- Navigate to Windows Logs > Security
- Verify events are being generated
```

### Method 2: Group Policy (Domain Environment)

```
Best Practice: Create separate GPOs for different server tiers
─────────────────────────────────────────────────────────

1. Open Group Policy Management (gpmc.msc)
2. Create New GPO: "Domain-Controller-Auditing"
3. Link to Domain Controllers OU
4. Edit GPO:

   Computer Configuration > Policies > Windows Settings > 
   Security Settings > Local Policies > Audit Policy

5. Configure settings:

   Policy Setting                    Value
   ─────────────────────────────────────────────
   Audit account logon events        Success, Failure
   Audit account management          Success, Failure
   Audit directory service access    Success, Failure
   Audit logon events                Success, Failure
   Audit object access               Failure
   Audit policy change               Success, Failure
   Audit privilege use               Failure
   Audit process tracking            No auditing
   Audit system events               Success, Failure

6. Create additional GPOs:
   - "File-Server-Auditing" (focused on object access)
   - "Application-Server-Auditing" (focused on process tracking)
   - "Workstation-Auditing" (minimal, failure only)

7. Use Security Filtering or WMI Filtering to target specific systems
```

### Method 3: Advanced Audit Policy (Recommended for Enterprise)

```
Why Use Advanced Auditing?
─────────────────────────────────────────────────────────
- Granular control (60+ subcategories)
- Can exclude specific operations
- Better performance (audit only what you need)
- Overrides basic audit policy when configured

Configuration:
Computer Configuration > Policies > Windows Settings > 
Security Settings > Advanced Audit Policy Configuration > 
System Audit Policies

EXAMPLE: Detailed Logon Auditing
─────────────────────────────────────────────────────────
Logon/Logoff:
  - Audit Logon: Success, Failure
  - Audit Logoff: Success
  - Audit Account Lockout: Failure
  - Audit IPsec Main Mode: No auditing
  - Audit IPsec Quick Mode: No auditing
  - Audit Other Logon/Logoff Events: Success, Failure
  - Audit Network Policy Server: Success, Failure
  - Audit User / Device Claims: No auditing
  - Audit Group Membership: Success

This level of granularity is impossible with basic auditing!
```

---

## Best Practices

### The Goldilocks Principle

```
NOT ENOUGH AUDITING                    TOO MUCH AUDITING
───────────────────                    ─────────────────
Miss security incidents                Log flooding
Fail compliance audits                 SIEM license overages
Cannot investigate breaches            Storage costs explode
No forensic capability                 Miss real alerts in noise

JUST RIGHT:
─────────────────────────────────────────────────────────
• Audit failures broadly (cheap, high signal)
• Audit successes selectively (expensive, know why)
• Focus on critical assets
• Tune based on operational experience
```

### Recommended Default Configuration

| System Type | Critical Policies | Volume Management |
|-------------|-------------------|-------------------|
| **Domain Controllers** | Account Logon, Account Mgmt, Policy Change, System Events | Monitor closely, centralize logs |
| **Member Servers** | Logon Events, Account Mgmt, Object Access (targeted) | Filter noise, alert on anomalies |
| **Workstations** | Logon Events (Failure), Object Access (sensitive only) | Minimal retention, forward alerts |
| **File Servers** | Object Access (SACLs), Logon Events | Archive old logs, monitor trends |

### Log Management Strategy

```
ARCHITECTURE: Centralized Log Collection
─────────────────────────────────────────────────────────

Windows Servers → Windows Event Collector (WEC) → SIEM → Long-term Storage
     │                    │                        │
     └─ Local 24h retention    └─ 90 day hot storage      └─ 7 year cold storage
     └─ Forward critical         └─ Real-time alerting      └─ Compliance archive
        events immediately

CONFIGURATION:
1. Configure subscription on WEC server:
   wecutil cs subscription.xml

2. Configure source computers to forward:
   winrm quickconfig
   wecutil qc

3. Set log sizes appropriately:
   - Security log: 1GB minimum (circular if needed)
   - Forwarded Events: 10GB+ (centralized storage)
   - Archive to .evtx files monthly

4. Monitor log health:
   - Alert if logs stop flowing
   - Alert if log volume spikes
   - Alert if Event ID 1104 (log full) occurs
```

### Compliance Mapping

| Regulation | Requirement | Audit Policy |
|------------|-------------|--------------|
| **SOX** | Track financial data access | Object Access + SACLs |
| **HIPAA** | Monitor PHI access | Object Access + Logon Events |
| **PCI-DSS** | Track cardholder data environment | Account Logon + Object Access |
| **GDPR** | Track personal data processing | Directory Service Access + Object Access |
| **NIST 800-53** | Comprehensive audit trail | All categories with SIEM correlation |

---

## Troubleshooting

### Common Issues

**Issue 1: Events Not Being Logged**

```
DIAGNOSIS:
1. Check policy application: gpresult /r /scope:computer
2. Verify policy not overwritten: rsop.msc
3. Check for conflicting GPOs
4. Verify service status: Get-Service EventLog
5. Check log not full: Get-WinEvent -ListLog Security

SOLUTIONS:
- Force GP update: gpupdate /force
- Check Advanced Audit Policy isn't overriding basic
- Verify SACLs are configured (for Object Access)
- Ensure system has sufficient disk space
```

**Issue 2: Log Flooding**

```
SYMPTOMS:
- Security log fills up in hours
- System performance degraded
- SIEM overwhelmed

DIAGNOSIS:
Get-WinEvent -LogName Security -MaxEvents 100 | 
    Group-Object Id | Sort-Object Count -Descending

COMMON CAUSES:
1. Process Tracking enabled on busy server
   FIX: Disable or filter specific processes

2. Object Access auditing too broad
   FIX: Narrow SACLs to specific folders

3. Privilege Use Success auditing
   FIX: Switch to Failure only

4. Loop in application causing repeated events
   FIX: Identify and fix application

MITIGATION:
wevtutil sl Security /ms:1073741824  # Increase to 1GB
wevtutil sl Security /rt:true         # Enable retention (don't overwrite)
```

**Issue 3: Log Tampering**

```
DETECTION:
Event ID 1102 - Audit log cleared

PREVENTION:
1. Forward events in real-time to SIEM/WEC
2. Use write-once media for archives
3. Restrict "Manage auditing and security log" privilege
4. Monitor for privilege escalation

RESPONSE:
If logs are cleared:
1. Assume system is compromised
2. Isolate system from network
3. Capture memory dump before shutdown
4. Analyze from forensic image
5. Check other systems for similar activity
```

---

## Quick Reference

### Essential Event IDs

| ID | Description | Category | Priority |
|----|-------------|----------|----------|
| 4624 | Successful logon | Logon Events | Medium |
| 4625 | Failed logon | Logon Events | High |
| 4720 | User account created | Account Management | Critical |
| 4728 | Member added to security group | Account Management | Critical |
| 4732 | Member added to local group | Account Management | High |
| 4663 | Object access attempt | Object Access | Medium |
| 4673 | Sensitive privilege use | Privilege Use | High |
| 4719 | System audit policy changed | Policy Change | Critical |
| 1102 | Audit log cleared | System Events | Critical |
| 4688 | Process created | Process Tracking | Medium |

### PowerShell Commands

```powershell
# View current audit policy
auditpol /get /category:*

# Set specific category
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Export audit policy
auditpol /backup /file:"C:\auditpolicy.csv"

# Import audit policy  
auditpol /restore /file:"C:\auditpolicy.csv"

# Search for specific event
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Export security log
Get-WinEvent -LogName Security | Export-Csv security.csv

# Clear security log (requires privileges)
Clear-EventLog -LogName Security
```

---

## Summary

Effective Windows Server auditing requires:

1. **Strategic Planning**: Know what you're looking for before you start logging
2. **Gradual Implementation**: Start with failures, add successes selectively  
3. **Active Monitoring**: Logs are useless without review and alerting
4. **Regular Tuning**: Adjust policies based on operational experience
5. **Integration**: Centralize logs in SIEM for correlation and retention

Remember: **More auditing ≠ Better security**. Focused, well-managed auditing that you can actually analyze provides far more value than verbose logging that gets ignored.

---

## Additional Resources

- [Microsoft Security Auditing Overview](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Advanced Security Auditing FAQ](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq)
- [Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft Audit Policy Recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)

---

