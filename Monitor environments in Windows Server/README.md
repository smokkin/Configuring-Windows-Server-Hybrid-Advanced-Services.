# Windows Server Basic Auditing: Complete Implementation Guide

> **Master Windows Server Security Auditing: From Fundamentals to Enterprise Implementation**  
> A practical guide to configuring, managing, and analyzing security audit policies in Windows Server environments

---

## 📋 Table of Contents

1. [Introduction to Windows Server Auditing](#introduction)
2. [Understanding Basic vs. Advanced Auditing](#basic-vs-advanced)
3. [The 9 Basic Auditing Categories Explained](#basic-categories)
4. [Implementation Scenarios](#implementation-scenarios)
5. [File and Folder Auditing](#file-folder-auditing)
6. [Security Log Analysis](#security-log-analysis)
7. [Real-World Use Cases](#real-world-use-cases)
8. [Best Practices & Optimization](#best-practices)
9. [Troubleshooting Guide](#troubleshooting)
10. [Quick Reference](#quick-reference)

---

## Introduction

### What is Windows Server Auditing?

Windows Server auditing is a security feature that records system activities and events to the **Security Log**, enabling administrators to:

- 🔍 **Detect Security Threats**: Identify unauthorized access attempts and malicious activity
- 📊 **Ensure Compliance**: Meet regulatory requirements (SOX, HIPAA, PCI-DSS, GDPR)
- 🔎 **Forensic Investigation**: Trace the sequence of events during security incidents
- 📈 **Operational Monitoring**: Track system changes and administrative actions
- ⚖️ **Accountability**: Document who performed specific actions and when

### How Auditing Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     Auditing Workflow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  User/Process Action                                            │
│        │                                                         │
│        ▼                                                         │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐   │
│  │   System    │────▶│   Audit     │────▶│   Security      │   │
│  │   Event     │     │   Policy    │     │   Event Log     │   │
│  │   Occurs    │     │   Check     │     │   (.evtx)       │   │
│  └─────────────┘     └─────────────┘     └─────────────────┘   │
│                              │                         │        │
│                              ▼                         ▼        │
│                    ┌─────────────────┐      ┌──────────────┐   │
│                    │  Policy Match?  │      │  Event       │   │
│                    │  (Success/      │      │  Viewer /    │   │
│                    │   Failure)      │      │  SIEM /      │   │
│                    └─────────────────┘      │  Azure       │   │
│                                             │  Monitor     │   │
│                                             └──────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Concepts

| Concept | Description | Example |
|---------|-------------|---------|
| **Audit Policy** | Configuration that defines what to audit | Audit failed logon attempts |
| **SACL** | System Access Control List - specifies auditing for objects | Audit "Domain Users" failed access to \Finance\ |
| **Security Log** | Protected event log storing audit events | Event ID 4625: Failed logon |
| **Success Auditing** | Logs when an action completes successfully | User successfully logs on |
| **Failure Auditing** | Logs when an action fails (often more critical) | Failed password attempt |

---

## Basic vs. Advanced Auditing

### Comparison Overview

| Feature | Basic Auditing | Advanced Auditing |
|---------|----------------|-------------------|
| **Categories** | 9 broad categories | 10 categories with 60+ subcategories |
| **Granularity** | High-level (e.g., all logons) | Fine-grained (e.g., only NPS logons) |
| **Configuration** | Local Security Policy or GPO | GPO or AuditPol.exe |
| **Best For** | Small environments, quick setup | Enterprise, compliance requirements |
| **Log Volume** | Can be excessive (broad net) | Optimized (precise targeting) |

> ⚠️ **CRITICAL WARNING**: Do not use Basic and Advanced auditing simultaneously. When Advanced auditing is applied via Group Policy, Windows **clears all Basic audit settings**. Choose one approach and stick with it.

### Decision Matrix: Which to Choose?

```
Environment Size          Complexity          Recommendation
─────────────────────────────────────────────────────────────
< 10 servers              Low                 Basic Auditing
10-50 servers             Medium              Advanced Auditing
> 50 servers              High                Advanced Auditing
Domain Controllers        Critical            Advanced Auditing
File Servers              High                Advanced Auditing (File System)
Compliance Required       Any                 Advanced Auditing
```

---

## The 9 Basic Auditing Categories Explained

### 1. Audit Account Logon Events 🔐

**What it Tracks:**
Authentication attempts against Active Directory accounts (domain authentication).

**When Events Are Generated:**
- User logs on to any computer in the domain
- Service account authenticates to domain resources
- Computer account authenticates to the domain

**Key Event IDs:**
| Event ID | Description | Priority |
|----------|-------------|----------|
| 4624 | Successful account logon | Medium |
| 4625 | Failed account logon | **Critical** |
| 4648 | Explicit credential logon (RunAs) | High |
| 4771 | Kerberos pre-authentication failed | **Critical** |
| 4776 | NTLM authentication attempt | Medium |

**Detailed Scenario: Detecting Brute Force Attacks**

```
Attack Scenario:
────────────────
Attacker attempts to guess passwords for multiple domain accounts
using automated tools from a compromised workstation.

Detection Strategy:
───────────────────
1. Enable "Audit account logon events" - Failure
2. Monitor for Event ID 4625 (Failed logon)
3. Correlate by Source IP and Time Window
4. Alert on >5 failed attempts per account in 10 minutes
```

**Implementation:**

```powershell
# Method 1: Local Security Policy (Single Server)
# Run as Administrator
secedit /export /cfg C:\security_config.inf
# Edit cfg file: AuditAccountLogon = 2 (Failure only)
# Or use GUI: Local Security Policy -> Audit Policy

# Method 2: Group Policy (Recommended for Domains)
# GPMC.msc -> Computer Configuration -> Policies -> 
# Windows Settings -> Security Settings -> Local Policies -> 
# Audit Policy -> Audit account logon events

# Method 3: Command Line (AuditPol - works for both)
auditpol /set /subcategory:"Account Logon" /failure:enable /success:disable

# Verification
auditpol /get /category:"Account Logon"
```

**PowerShell Analysis Script:**
```powershell
# Detect potential brute force attacks
function Get-BruteForceAttempts {
    param(
        [int]$Threshold = 5,
        [int]$TimeWindowMinutes = 10
    )

    $startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = $startTime
    } | Group-Object { 
        $_.Properties[5].Value  # TargetUserName
    } | Where-Object { $_.Count -ge $Threshold } | 
    ForEach-Object {
        [PSCustomObject]@{
            TargetUser = $_.Name
            FailedAttempts = $_.Count
            SourceIPs = $_.Group | ForEach-Object { $_.Properties[19].Value } | 
                         Select-Object -Unique
            TimeWindow = "$TimeWindowMinutes minutes"
            RiskLevel = if ($_.Count -gt 10) { "CRITICAL" } else { "HIGH" }
        }
    }
}

# Usage
Get-BruteForceAttempts -Threshold 5 -TimeWindowMinutes 10 | 
    Format-Table -AutoSize
```

---

### 2. Audit Logon Events 🖥️

**What it Tracks:**
Logon events to the specific computer (local logons, network logons, RDP).

**The Critical Difference:**
- **Account Logon**: Authentication to domain (occurs on DC)
- **Logon Events**: Session establishment on target computer

**Logon Types Reference:**
| Type | Description | Use Case |
|------|-------------|----------|
| 2 | Interactive (Console) | Local login at keyboard |
| 3 | Network | SMB shares, RPC, IIS |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Windows services starting |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS Basic Auth |
| 9 | NewCredentials | RunAs with /netonly |
| 10 | RemoteInteractive | RDP connections |
| 11 | CachedInteractive | Offline logon with cached credentials |

**Detailed Scenario: Monitoring Privileged Access**

```
Scenario: Contoso Financial Services
─────────────────────────────────────
Requirement: Track all administrative access to SQL Servers
containing customer financial data for SOX compliance.

Implementation:
1. Enable "Audit logon events" - Success and Failure
2. Filter for Logon Type 10 (RDP) and Type 3 (Network)
3. Correlate with privileged group membership
4. Forward to SIEM for retention and alerting
```

**Implementation:**

```powershell
# Enable via Group Policy
# Computer Configuration -> Policies -> Windows Settings ->
# Security Settings -> Local Policies -> Audit Policy ->
# Audit logon events: Success, Failure

# Query recent administrative logons
function Get-AdminLogons {
    param(
        [string[]]$AdminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins"),
        [int]$HoursBack = 24
    )

    $startTime = (Get-Date).AddHours(-$HoursBack)

    # Get events
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    }

    # Process and enrich
    $events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $logonType = [int]$xml.Event.EventData.Data | 
                     Where-Object {$_.Name -eq 'LogonType'} | 
                     Select-Object -ExpandProperty '#text'
        $username = $xml.Event.EventData.Data | 
                    Where-Object {$_.Name -eq 'TargetUserName'} | 
                    Select-Object -ExpandProperty '#text'
        $domain = $xml.Event.EventData.Data | 
                  Where-Object {$_.Name -eq 'TargetDomainName'} | 
                  Select-Object -ExpandProperty '#text'

        # Check if user is in admin groups (simplified - requires AD module)
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = "$domain\$username"
            LogonType = $logonType
            LogonTypeName = switch ($logonType) {
                2 { "Interactive" }
                3 { "Network" }
                10 { "RemoteDesktop" }
                default { "Other($logonType)" }
            }
            Workstation = $xml.Event.EventData.Data | 
                          Where-Object {$_.Name -eq 'WorkstationName'} | 
                          Select-Object -ExpandProperty '#text'
            SourceIP = $xml.Event.EventData.Data | 
                       Where-Object {$_.Name -eq 'IpAddress'} | 
                       Select-Object -ExpandProperty '#text'
        }
    } | Where-Object { $_.LogonType -in @(2, 3, 10) }
}

Get-AdminLogons -HoursBack 24 | Format-Table -AutoSize
```

---

### 3. Audit Account Management 👥

**What it Tracks:**
Changes to user accounts, group accounts, and computer accounts.

**Critical Event IDs:**
| Event ID | Description | Security Impact |
|----------|-------------|-----------------|
| 4720 | User account created | **Critical** - New account could be backdoor |
| 4722 | User account enabled | **Critical** - Re-enabling disabled account |
| 4723 | Password change attempt | Medium - User or admin changing password |
| 4724 | Password reset attempt | **Critical** - Admin resetting password |
| 4725 | User account disabled | Medium - Account deactivation |
| 4726 | User account deleted | **Critical** - Covering tracks |
| 4738 | User account changed | High - Privilege escalation |
| 4740 | Account locked out | Medium - Possible brute force |
| 4728 | Member added to global group | **Critical** - Privilege escalation |
| 4732 | Member added to local group | **Critical** - Local admin addition |

**Detailed Scenario: Detecting Privilege Escalation**

```
Attack Pattern: The "Shadow Admin"
────────────────────────────────────
Attacker compromises helpdesk account, adds their account to 
"Domain Admins" group during off-hours, then removes audit logs.

Detection Strategy:
───────────────────
1. Enable "Audit account management" - Success
2. Monitor Event ID 4728 (Global group member added)
3. Alert on changes to privileged groups
4. Forward logs immediately to SIEM (immutable storage)
5. Monitor for Event ID 1102 (Audit log cleared) - CRITICAL
```

**Implementation:**

```powershell
# Enable auditing
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable

# Real-time monitoring for privilege escalation
function Watch-PrivilegedGroupChanges {
    param(
        [string[]]$ProtectedGroups = @(
            "Domain Admins",
            "Enterprise Admins", 
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators"
        )
    )

    Write-Host "Monitoring for changes to privileged groups..." -ForegroundColor Green
    Write-Host "Protected groups: $($ProtectedGroups -join ', ')" -ForegroundColor Yellow

    # Query existing events
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4728, 4732, 4756  # Member added to groups
        StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $targetGroup = ($xml.Event.EventData.Data | 
                       Where-Object {$_.Name -eq 'TargetUserName'}).
                       '#text'

        if ($ProtectedGroups -contains $targetGroup) {
            $subject = ($xml.Event.EventData.Data | 
                       Where-Object {$_.Name -eq 'SubjectUserName'}).
                       '#text'
            $member = ($xml.Event.EventData.Data | 
                      Where-Object {$_.Name -eq 'MemberName'}).
                      '#text'

            Write-Warning @"
PRIVILEGED GROUP MODIFICATION DETECTED!
Time: $($event.TimeCreated)
Group: $targetGroup
Added By: $subject
Member Added: $member
"@

            # Send alert (example: email or webhook)
            # Send-MailMessage or Invoke-RestMethod here
        }
    }
}

# Run monitoring
Watch-PrivilegedGroupChanges
```

---

### 4. Audit Directory Service Access 📁

**What it Tracks:**
Access to Active Directory objects (users, groups, OUs, GPOs) based on SACLs.

**Key Characteristics:**
- Requires both policy enablement AND SACL configuration on objects
- Events generated on Domain Controllers
- Critical for tracking AD reconnaissance

**Detailed Scenario: Protecting Sensitive AD Objects**

```
Scenario: High-Value Target Protection
──────────────────────────────────────
Contoso has a "C-Level Executives" OU containing CEO, CFO accounts.
Security team needs to detect any access to these accounts.

Implementation Steps:
1. Enable "Audit directory service access" - Success and Failure
2. Configure SACL on "C-Level Executives" OU
3. Audit all authenticated users for "Read All Properties"
4. Monitor Event ID 4662 (Operation performed on object)
5. Alert on unusual access patterns (non-IT users accessing)
```

**Implementation:**

```powershell
# Step 1: Enable policy
auditpol /set /subcategory:"DS Access" /success:enable /failure:enable

# Step 2: Configure SACL on specific OU via PowerShell
Import-Module ActiveDirectory

$ouPath = "OU=C-Level Executives,DC=contoso,DC=com"
$ou = Get-ADObject -Identity $ouPath -Properties nTSecurityDescriptor

# Create audit rule
$auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0"),  # Everyone
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
    [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)

# Apply SACL
$ou.nTSecurityDescriptor.AddAuditRule($auditRule)
Set-ADObject -Identity $ouPath -Replace @{
    nTSecurityDescriptor = $ou.nTSecurityDescriptor
}

# Step 3: Monitor for access
function Get-ADObjectAccess {
    param(
        [string]$TargetOU = "C-Level Executives",
        [int]$HoursBack = 24
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4662
        StartTime = (Get-Date).AddHours(-$HoursBack)
    } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $objectName = ($xml.Event.EventData.Data | 
                      Where-Object {$_.Name -eq 'ObjectName'}).
                      '#text'

        if ($objectName -like "*$TargetOU*") {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Subject = ($xml.Event.EventData.Data | 
                          Where-Object {$_.Name -eq 'SubjectUserName'}).
                          '#text'
                Object = $objectName
                Operation = ($xml.Event.EventData.Data | 
                            Where-Object {$_.Name -eq 'OperationType'}).
                            '#text'
                Properties = ($xml.Event.EventData.Data | 
                             Where-Object {$_.Name -eq 'Properties'}).
                             '#text'
            }
        }
    }
}

Get-ADObjectAccess -HoursBack 24 | Format-Table -AutoSize
```

---

### 5. Audit Policy Change ⚙️

**What it Tracks:**
Changes to audit policies, user rights assignments, and trust relationships.

**Why It Matters:**
Attackers often disable auditing to cover their tracks. This category detects that.

**Critical Event IDs:**
| Event ID | Description | Impact |
|----------|-------------|--------|
| 4719 | System audit policy changed | **Critical** - Auditing disabled/modified |
| 4739 | Domain policy changed | **Critical** - Domain-wide changes |
| 608 | User right assigned | High - Privilege escalation |
| 609 | User right removed | Medium - Potential Denial of Service |

**Detailed Scenario: Detecting Audit Tampering**

```
Attack Pattern: Covering Tracks
───────────────────────────────
Attacker gains admin rights, disables auditing to perform 
malicious actions without logging, then re-enables auditing.

Detection Strategy:
───────────────────
1. Enable "Audit policy change" - Success
2. Monitor Event ID 4719 (System audit policy changed)
3. Alert on ANY audit policy change
4. Correlate with change management tickets
5. If no ticket exists, escalate to Security Team
```

**Implementation:**

```powershell
# Enable via command line
auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable

# Monitor for audit policy changes
function Watch-AuditPolicyChanges {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4719
        StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $subject = ($xml.Event.EventData.Data | 
                   Where-Object {$_.Name -eq 'SubjectUserName'}).
                   '#text'
        $category = ($xml.Event.EventData.Data | 
                    Where-Object {$_.Name -eq 'CategoryId'}).
                    '#text'
        $subcategory = ($xml.Event.EventData.Data | 
                       Where-Object {$_.Name -eq 'SubcategoryId'}).
                       '#text'

        Write-Warning @"
ALERT: Audit Policy Modified!
Time: $($event.TimeCreated)
Changed By: $subject
Category ID: $category
Subcategory ID: $subcategory
This could indicate an attempt to disable logging!
"@

        # Immediate notification
        # Consider: disabling the account, requiring MFA re-auth, etc.
    }
}

# Set up continuous monitoring (run as scheduled task)
Watch-AuditPolicyChanges
```

---

### 6. Audit Privilege Use 🛡️

**What it Tracks:**
Usage of specific user rights (privileges) such as:
- SeDebugPrivilege (debug programs)
- SeBackupPrivilege (backup files)
- SeRestorePrivilege (restore files)
- SeTakeOwnershipPrivilege (take ownership)

**Detailed Scenario: Detecting Credential Dumping**

```
Attack Pattern: LSASS Memory Dump
─────────────────────────────────
Attacker uses Mimikatz or similar tool to dump credentials
from LSASS process memory, requiring SeDebugPrivilege.

Detection Strategy:
───────────────────
1. Enable "Audit privilege use" for sensitive privileges
2. Monitor for SeDebugPrivilege use by non-system accounts
3. Alert on usage by non-IT users
4. Correlate with process creation events
```

**Implementation:**

```powershell
# Enable (Warning: High volume in busy environments)
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable

# Focus on specific high-risk privileges
# Note: Requires Advanced Auditing for granularity
# With Basic Auditing, this generates many events

# Analysis script for privilege usage
function Get-SuspiciousPrivilegeUse {
    param(
        [string[]]$SensitivePrivileges = @(
            "SeDebugPrivilege",
            "SeBackupPrivilege", 
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege"
        ),
        [int]$HoursBack = 1
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4672  # Special privileges assigned
        StartTime = (Get-Date).AddHours(-$HoursBack)
    } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $privileges = ($xml.Event.EventData.Data | 
                      Where-Object {$_.Name -eq 'PrivilegeList'}).
                      '#text'
        $username = ($xml.Event.EventData.Data | 
                    Where-Object {$_.Name -eq 'SubjectUserName'}).
                    '#text'

        # Check if any sensitive privilege was used
        $usedSensitive = $SensitivePrivileges | Where-Object { 
            $privileges -contains $_ 
        }

        if ($usedSensitive -and $username -notin @("SYSTEM", "NETWORK SERVICE")) {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $username
                PrivilegesUsed = $usedSensitive -join ', '
                AllPrivileges = $privileges
            }
        }
    }
}

Get-SuspiciousPrivilegeUse | Format-Table -AutoSize
```

---

### 7. Audit System Events 🖥️

**What it Tracks:**
System-level changes: restarts, shutdowns, security log management.

**Critical Event IDs:**
| Event ID | Description | Priority |
|----------|-------------|----------|
| 512 | Windows startup | Info |
| 513 | Windows shutdown | Info |
| 1102 | Audit log cleared | **CRITICAL** |

**Detailed Scenario: Detecting Log Tampering**

```
Attack Pattern: Evidence Destruction
────────────────────────────────────
Attacker clears Security log to remove traces of their activity.
This is logged as Event ID 1102, but only if this policy is enabled!

Detection Strategy:
───────────────────
1. Enable "Audit system events" - Success
2. Monitor Event ID 1102 obsessively
3. Immediate high-priority alert
4. Correlation: Who cleared logs? From where? When?
5. Automated response: Preserve logs from SIEM, snapshot VM
```

**Implementation:**

```powershell
# Enable
auditpol /set /subcategory:"System" /success:enable /failure:enable

# Critical monitoring for log clearing
function Watch-LogClearing {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 1102
        StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 1 -ErrorAction SilentlyContinue

    if ($event) {
        $xml = [xml]$event.ToXml()
        $subject = ($xml.Event.EventData.Data | 
                   Where-Object {$_.Name -eq 'SubjectUserName'}).
                   '#text'
        $sid = ($xml.Event.EventData.Data | 
               Where-Object {$_.Name -eq 'SubjectUserSid'}).
               '#text'

        $alert = @"
🚨 CRITICAL SECURITY ALERT 🚨
Audit Log Cleared Detected!
Time: $($event.TimeCreated)
User: $subject
SID: $sid
Computer: $($event.MachineName)

IMMEDIATE ACTION REQUIRED:
1. Verify if this was authorized change management
2. If unauthorized: Disable account immediately
3. Preserve SIEM logs (if forwarding enabled)
4. Initiate incident response procedure
5. Check for other indicators of compromise
"@

        Write-Host $alert -ForegroundColor Red -BackgroundColor Black

        # Send email/Teams/Slack alert
        # Invoke-RestMethod to webhook
        # Disable-ADAccount if unauthorized
    }
}

# Run every 5 minutes via Task Scheduler
Watch-LogClearing
```

---

### 8. Audit Process Tracking 🔄

**What it Tracks:**
Process creation and termination.

**Use Cases:**
- Malware execution detection
- Unauthorized software installation
- Command-line auditing (with proper configuration)

**Note:** High volume policy. Consider using Advanced Auditing for granularity.

**Implementation:**

```powershell
# Enable (Warning: Very high event volume)
auditpol /set /subcategory:"Process Tracking" /success:enable /failure:enable

# Process creation generates Event ID 4688
# Requires additional policy: "Include command line in process creation events"
# Computer Configuration -> Administrative Templates -> 
# System -> Audit Process Creation -> Include command line

# Analysis: Find suspicious processes
function Get-SuspiciousProcesses {
    param([int]$HoursBack = 1)

    $suspiciousPatterns = @(
        "mimikatz",
        "pwdump",
        "nc.exe", 
        "ncat",
        "powershell -enc",
        "powershell -exec bypass",
        "cmd.exe /c",
        "rundll32",
        "regsvr32",
        "certutil -urlcache",
        "bitsadmin"
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4688
        StartTime = (Get-Date).AddHours(-$HoursBack)
    } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $cmdLine = ($xml.Event.EventData.Data | 
                   Where-Object {$_.Name -eq 'CommandLine'}).
                   '#text'

        foreach ($pattern in $suspiciousPatterns) {
            if ($cmdLine -like "*$pattern*") {
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    Process = ($xml.Event.EventData.Data | 
                              Where-Object {$_.Name -eq 'NewProcessName'}).
                              '#text'
                    CommandLine = $cmdLine
                    User = ($xml.Event.EventData.Data | 
                           Where-Object {$_.Name -eq 'SubjectUserName'}).
                           '#text'
                    ParentProcess = ($xml.Event.EventData.Data | 
                                    Where-Object {$_.Name -eq 'ParentProcessName'}).
                                    '#text'
                    MatchedPattern = $pattern
                }
                break
            }
        }
    }
}

Get-SuspiciousProcesses | Format-Table -AutoSize -Wrap
```

---

### 9. Audit Object Access 📂

**What it Tracks:**
Access to files, folders, registry keys, and printers with configured SACLs.

**This is the most commonly used auditing category for data protection.**

---

## File and Folder Auditing

### The Three-Step Process

```
Step 1: Enable Policy
─────────────────────
Enable "Audit object access" - Success, Failure (or both)

Step 2: Configure SACL
──────────────────────
Right-click folder -> Properties -> Security -> Advanced -> Auditing
Add principals and permissions to monitor

Step 3: Monitor Events
──────────────────────
View in Event Viewer -> Security Log
Event ID 4663: An attempt was made to access an object
```

### Detailed Implementation: Protecting Sensitive Data

**Scenario:** Contoso needs to monitor access to \FileServer\Finance\QuarterlyReports

**Step-by-Step:**

```powershell
# Step 1: Enable policy (if not already enabled via GPO)
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Step 2: Configure SACL via PowerShell (more scalable than GUI)
$path = "\ileserverinance\QuarterlyReports"
$acl = Get-Acl $path -Audit

# Remove existing audit rules to avoid conflicts
$acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | 
    ForEach-Object { $acl.RemoveAuditRule($_) | Out-Null }

# Add comprehensive audit rule
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Authenticated Users",                    # Who to audit
    "Read, Write, Modify, Delete",           # What actions
    "ContainerInherit,ObjectInherit",        # Apply to subfolders/files
    "None",                                  # No propagation flags
    "Success, Failure"                       # Log both outcomes
)

$acl.AddAuditRule($auditRule)
Set-Acl $path $acl

# Verify
(Get-Acl $path -Audit).GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | 
    Format-List

# Step 3: Monitor with PowerShell
function Get-FileAccessEvents {
    param(
        [string]$TargetPath = "QuarterlyReports",
        [int]$MinutesBack = 30
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4663
        StartTime = (Get-Date).AddMinutes(-$MinutesBack)
    } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $objectName = ($xml.Event.EventData.Data | 
                      Where-Object {$_.Name -eq 'ObjectName'}).
                      '#text'

        if ($objectName -like "*$TargetPath*") {
            $accessMask = ($xml.Event.EventData.Data | 
                          Where-Object {$_.Name -eq 'AccessMask'}).
                          '#text'

            # Decode access mask
            $accessType = switch ($accessMask) {
                "0x10000" { "Delete" }
                "0x6" { "Read/Write" }
                "0x40000" { "Write Attributes" }
                "0x80000" { "Write Extended Attributes" }
                default { "Other ($accessMask)" }
            }

            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = ($xml.Event.EventData.Data | 
                       Where-Object {$_.Name -eq 'SubjectUserName'}).
                       '#text'
                Object = Split-Path $objectName -Leaf
                AccessType = $accessType
                Result = if ($_.KeywordsDisplayNames -contains "Audit Success") { 
                    "Success" 
                } else { 
                    "Failure" 
                }
                FullPath = $objectName
            }
        }
    } | Sort-Object Time -Descending
}

# Real-time monitoring
while ($true) {
    Clear-Host
    Write-Host "Monitoring Finance Share Access... ($(Get-Date))" -ForegroundColor Green
    Get-FileAccessEvents -MinutesBack 5 | Format-Table -AutoSize
    Start-Sleep -Seconds 10
}
```

### Access Mask Reference Table

| Access Mask | Permission | Description |
|-------------|------------|-------------|
| 0x1 | Read Data | Read file contents |
| 0x2 | Write Data | Write to file |
| 0x4 | Append Data | Add to end of file |
| 0x8 | Read EA | Read extended attributes |
| 0x10 | Write EA | Write extended attributes |
| 0x20 | Execute | Run file |
| 0x40 | Delete Child | Delete subdirectory |
| 0x10000 | Delete | Delete file/folder |
| 0x40000 | Write Attributes | Modify attributes |
| 0x100000 | Synchronize | Synchronize access |

---

## Implementation Scenarios

### Scenario A: Small Business (10-50 Users)

**Requirements:**
- Monitor failed logons
- Track file access to sensitive shares
- Basic compliance for cyber insurance
- Minimal administrative overhead

**Recommended Configuration:**

```powershell
# Enable via Local Security Policy or GPO
# Focus on high-value, low-volume events

$basicAuditConfig = @{
    "Account Logon" = "Failure"        # Detect brute force
    "Logon" = "Success, Failure"       # Track access
    "Account Management" = "Success"   # Track changes
    "Object Access" = "Failure"        # Failed file access only
    "Policy Change" = "Success"        # Detect tampering
    "System" = "Success"               # Log clearing detection
}

foreach ($category in $basicAuditConfig.Keys) {
    $setting = $basicAuditConfig[$category]
    Write-Host "Configuring $category : $setting"
    # auditpol /set /subcategory:"$category" /$($setting.ToLower().Replace(', ', ' /')):enable
}

# Configure SACL on sensitive folder only
$path = "C:\CompanyData\Sensitive"
if (Test-Path $path) {
    $acl = Get-Acl $path -Audit
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "Modify", "Success, Failure"
    )
    $acl.AddAuditRule($rule)
    Set-Acl $path $acl
}
```

---

### Scenario B: Enterprise Domain (1000+ Users)

**Requirements:**
- SOX compliance for financial data
- Detect privilege escalation
- Monitor administrative actions
- Centralized log aggregation

**Architecture:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    SIEM / Azure Sentinel                         │
│                    (Central Analysis)                            │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ WEF / AMA
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
   │ Domain  │          │ File    │          │ SQL     │
   │Controllers│         │ Servers │          │ Servers │
   │         │          │         │          │         │
   │ • Account│          │ • File  │          │ • DB    │
   │   Logon │          │   Access│          │   Access│
   │ • DS    │          │ • Share │          │ • Admin │
   │   Access│          │   Access│          │   Actions
   └─────────┘          └─────────┘          └─────────┘
```

**Group Policy Configuration:**

```powershell
# Create GPO for different server tiers
Import-Module GroupPolicy

# Domain Controllers - Maximum auditing
New-GPO -Name "Audit-DC-High" | New-GPLink -Target "OU=Domain Controllers,DC=contoso,DC=com"
# Configure: Account Logon, DS Access, Account Management, Policy Change - All Success and Failure

# File Servers - Focus on data access
New-GPO -Name "Audit-FileServers" | New-GPLink -Target "OU=FileServers,DC=contoso,DC=com"
# Configure: Object Access (File System), Account Management

# General Servers - Balanced
New-GPO -Name "Audit-General" | New-GPLink -Target "OU=Servers,DC=contoso,DC=com"
# Configure: Logon, Account Management, System

# Configure via Group Policy Preferences or Security Templates
```

---

### Scenario C: Ransomware Detection

**Requirements:**
- Detect mass file modifications
- Identify encryption behavior
- Alert on suspicious process execution

**Detection Strategy:**

```powershell
# Layer 1: Monitor for mass file access (Event ID 4663 flood)
function Test-RansomwareActivity {
    param(
        [int]$Threshold = 100,  # Events per minute
        [int]$MinutesBack = 5
    )

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4663
        StartTime = (Get-Date).AddMinutes(-$MinutesBack)
    } -ErrorAction SilentlyContinue

    $grouped = $events | Group-Object { 
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | 
         Where-Object {$_.Name -eq 'SubjectUserName'}).
         '#text'
    }

    $suspicious = $grouped | Where-Object { 
        $_.Count -gt ($Threshold * $MinutesBack) 
    }

    if ($suspicious) {
        Write-Warning "Potential Ransomware Activity Detected!"
        $suspicious | ForEach-Object {
            [PSCustomObject]@{
                User = $_.Name
                FileOperations = $_.Count
                TimeWindow = "$MinutesBack minutes"
                SampleEvents = $_.Group | Select-Object -First 3 | 
                    ForEach-Object { $_.TimeCreated }
            }
        }

        # Automated response: Disable user, isolate machine
        # Disable-ADAccount -Identity $suspicious[0].Name
    }
}

# Layer 2: Monitor for suspicious process patterns
# (Requires Process Tracking enabled)
$ransomwareIndicators = @(
    "vssadmin.exe delete shadows",
    "wbadmin.exe delete catalog",
    "bcdedit.exe /set {default} recoveryenabled no",
    "wmic.exe shadowcopy delete"
)

# Layer 3: File extension monitoring
# Monitor for bulk file extension changes (requires script-based monitoring)
```

---

## Security Log Analysis

### Event Viewer Navigation

```
Event Viewer (eventvwr.msc)
├── Windows Logs
│   ├── Security  <-- Audit events stored here
│   │   ├── Filter Current Log... (by Event ID)
│   │   ├── Find... (keyword search)
│   │   └── Save All Events As... (evtx or XML)
│   ├── System
│   └── Application
└── Subscriptions (for event forwarding)
```

### PowerShell Analysis Techniques

```powershell
# 1. Export security log for offline analysis
$logPath = "C:\SecurityLogs\Security_$(Get-Date -Format 'yyyyMMdd').evtx"
wevtutil epl Security $logPath

# 2. Query specific time range
$start = (Get-Date).AddDays(-1)
$end = Get-Date
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = $start
    EndTime = $end
    ID = 4624, 4625, 4720, 4728
} | Export-Csv -Path "C:\Reports\security_events.csv" -NoTypeInformation

# 3. Real-time monitoring
Get-WinEvent -LogName Security -MaxEvents 1 -Wait | 
    Where-Object { $_.Id -eq 4625 } |
    ForEach-Object { 
        Send-MailMessage -To "security@contoso.com" -Subject "Failed Logon Detected" 
    }

# 4. Statistical analysis
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = (Get-Date).AddDays(-7)
} | Group-Object Id | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending |
    Format-Table -AutoSize
```

---

## Best Practices

### 1. Start Conservative

```powershell
# Week 1: Enable failure-only auditing
auditpol /set /subcategory:"Logon" /failure:enable /success:disable

# Monitor log growth
$initialSize = (Get-WinEvent -ListLog Security).FileSize
Start-Sleep -Seconds 3600  # Wait 1 hour
$finalSize = (Get-WinEvent -ListLog Security).FileSize
$growthRate = ($finalSize - $initialSize) * 24 / 1MB  # MB per day
Write-Host "Estimated daily log growth: $([math]::Round($growthRate, 2)) MB"

# If manageable (< 500 MB/day), enable success auditing for critical categories
```

### 2. Use Group Policy for Consistency

```
Best Practice Hierarchy:
────────────────────────
Domain Controllers OU    → Maximum auditing (all categories)
File Servers OU          → Object Access focus
Application Servers OU   → Process tracking, Logon
Workstations OU          → Logon, Account Management
```

### 3. Centralize Log Collection

```powershell
# Configure Windows Event Forwarding (WEF)
# OR use Azure Monitor Agent

# Azure Monitor Agent installation
$workspaceId = "your-workspace-id"
$workspaceKey = "your-workspace-key"

# Download and install AMA
# Configure data collection rules for Security log
# Set retention policy (7 years for compliance)
```

### 4. Regular Review Schedule

| Frequency | Task | Responsible |
|-----------|------|-------------|
| Daily | Review critical alerts (1102, 4719, 4728) | Security Team |
| Weekly | Analyze failed logon trends | Security Analyst |
| Monthly | Audit policy compliance check | Compliance Officer |
| Quarterly | Full audit configuration review | Security Architect |

### 5. Log Protection

```powershell
# Prevent log clearing (additional layer)
wevtutil sl Security /ca:O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;BO)

# Enable forwarding before events can be cleared
# Use SIEM with WORM storage (Write Once Read Many)
```

---

## Troubleshooting

### Issue: No Events Appearing in Security Log

**Diagnostic Steps:**
```powershell
# 1. Check if auditing is enabled
auditpol /get /category:*

# 2. Verify log not full
Get-WinEvent -ListLog Security | Select-Object LogMode, MaximumSizeInBytes, FileSize

# 3. Check GPO application
gpresult /r | Select-String "Audit"

# 4. Verify SACL configuration (for Object Access)
Get-Acl C:\Path\To\Folder -Audit | Format-List

# 5. Check for filtering policies
auditpol /get /category:* | Select-String "No Auditing"
```

### Issue: Log Volume Too High

**Solutions:**
```powershell
# 1. Switch to failure-only for high-volume categories
auditpol /set /subcategory:"Object Access" /failure:enable /success:disable

# 2. Use Advanced Auditing for granularity
# Instead of auditing all files, audit specific folders

# 3. Increase log size
wevtutil sl Security /ms:1073741824  # 1 GB

# 4. Enable auto-backup when full
wevtutil sl Security /rt:true /ab:true
```

### Issue: GPO Settings Not Applying

```powershell
# Force refresh
gpupdate /force

# Check resultant policy
Get-ResultantAuditPolicy  # Requires RSAT

# Review event logs for errors
Get-WinEvent -LogName System | Where-Object { 
    $_.Message -like "*Group Policy*" -and $_.LevelDisplayName -eq "Error" 
} | Select-Object -First 10
```

---

## Quick Reference

### Essential Event IDs

| ID | Description | Category | Priority |
|----|-------------|----------|----------|
| 4624 | Successful logon | Logon/Account Logon | Medium |
| 4625 | Failed logon | Account Logon | **Critical** |
| 4648 | Explicit credential logon | Account Logon | High |
| 4720 | User account created | Account Management | **Critical** |
| 4728 | Member added to global group | Account Management | **Critical** |
| 4732 | Member added to local group | Account Management | **Critical** |
| 4663 | Object access attempt | Object Access | Medium |
| 4662 | Operation on AD object | DS Access | High |
| 4719 | Audit policy changed | Policy Change | **Critical** |
| 1102 | Audit log cleared | System | **CRITICAL** |

### AuditPol Quick Commands

```powershell
# View all settings
auditpol /get /category:*

# Backup configuration
auditpol /backup /file:"C:\audit_backup_$(Get-Date -Format 'yyyyMMdd').txt"

# Restore configuration
auditpol /restore /file:"C:\audit_backup.txt"

# Clear all settings (use with caution!)
auditpol /clear /y
```

### Configuration Checklist

- [ ] Document current audit policy
- [ ] Identify compliance requirements
- [ ] Choose Basic or Advanced auditing
- [ ] Configure via GPO (domains) or Local Policy (workgroups)
- [ ] Set appropriate log sizes (minimum 1GB recommended)
- [ ] Configure SACLs on sensitive data
- [ ] Set up event forwarding to SIEM
- [ ] Create alerting rules for critical events
- [ ] Establish review procedures
- [ ] Test incident response with simulated events


---

## Conclusion

Windows Server Basic Auditing provides essential security visibility for organizations of all sizes. By understanding the nine categories and implementing them strategically, you can:

- Detect security threats in real-time
- Meet compliance requirements efficiently
- Maintain forensic evidence for investigations
- Optimize system performance through targeted auditing

Remember: **More auditing is not always better.** Focus on high-value events that align with your security objectives and operational capabilities.

For enterprise environments, consider graduating to Advanced Auditing for granular control and reduced log volume.

---

## Additional Resources

- [Microsoft Security Auditing Overview](https://docs.microsoft.com/windows/security/threat-protection/auditing/)
- [Advanced Security Auditing](https://docs.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [Windows Event Log Analysis](https://docs.microsoft.com/windows/win32/eventlog/event-logging)
