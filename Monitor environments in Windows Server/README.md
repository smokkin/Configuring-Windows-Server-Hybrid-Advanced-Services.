Introduction

You can use Azure Monitor for virtual machines (VMs) to observe performance, diagnostic, and dependency information about Windows Server Infrastructure as a service (IaaS) VMs.

Scenario
Contoso is a medium-size financial services company in London with a branch office in New York. Most of its compute environment runs on-premises on Windows Server. This includes virtualized workloads on Windows Server 2016 hosts. Contoso's IT staff are in the process of migrating Contoso servers to Windows Server 2025.

Contoso’s IT director realizes that Contoso has an outdated operational model with limited automation and reliance on dated technology. The Contoso IT Engineering team has started exploring Azure capabilities. They want to determine whether Azure services might assist with modernizing the current operational model through automation and virtualization.

As part of the initial design, the Contoso IT team asked you, their lead system engineer and server administrator, to set up a proof of concept environment. This environment must verify whether Azure services can help to modernize the IT infrastructure and meet business goals.

As the lead system engineer, you've been asked to conduct further research into how to consolidate and analyze event log data from Windows Server IaaS VMs. They also want you to configure a task to run in Azure when a specific event is written to an event log on a Windows Server IaaS VM.

This module covers enabling Azure Monitor for VMs, and how to enable Azure Monitor. It will also discuss how to use Azure Monitor to collect data in a hybrid environment, and how to use it to monitor VMs. Finally, you learn how to integrate Azure Monitor with Operations Manager.

By the end of this module, you're able to implement Azure Monitor for IaaS VMs in Azure, implement Azure Monitor in on-premises environments, and use dependency maps.

Learning objectives
After completing this module, you'll be able to:

Enable Azure Monitor for VMs.
Monitor an Azure VM with Azure Monitor.
Enable Azure Monitor in hybrid scenarios.
Collect data from a Windows computer in a hybrid environment.
Integrate Azure Monitor with Microsoft Operations Manager.
Prerequisites
In order to get the best learning experience from this module, it's important that you have knowledge and experience of the following:

Managing the Windows Server operating system (OS) and Windows Server workloads in on-premises scenarios including AD DS, Domain Name System (DNS), the Distributed File System (DFS), Microsoft Hyper-V, and file and storage services.
Common Windows Server management tools.
Core Microsoft compute, storage, networking, and virtualization technologies.
On-premises resiliency Windows Server–based compute and storage technologies.
Implementing and managing IaaS services in Azure.
Microsoft Entra ID.
Security-related technologies such as firewalls, encryption, and multifactor authentication.
Windows PowerShell scripting.
Automation and monitoring.

Describe basic auditing categories

Auditing logs record security events and activities in the Windows security log. You then can monitor these auditing logs to identify issues that warrant further investigation. Auditing successful activities also can be useful because doing so provides documentation of changes. Auditing can also log failed attempts by malicious hackers or unauthorized users to access enterprise resources. When configuring auditing, you specify audit settings, enable an audit policy, and then monitor events in the security logs.

Windows Server provides two categories of auditing:

Basic auditing. Nine values are provided that enable you to audit the fundamental security events.
Advanced auditing. Ten categories of events, which contain more detailed policy settings. There are over 60 configurable policy settings available.
What are the basic auditing categories?
The following table describes the basic auditing categories.

Audit policy setting	Description
Audit account logon events	Creates an event when a user or computer attempts to use a Windows Server Active Directory account to authenticate. For example, when a user logs on to any computer in the domain, an account logon event is generated.
Audit logon events	Creates an event when a user logs on interactively (locally) to a computer or over the network (remotely). For example, if a workstation and a server are configured to audit logon events, the workstation audits a user logging on directly to that workstation. When the user connects to a shared folder on the server, the server logs that remote log in. When a user logs on, the domain controller records a logon event because logon scripts and policies are retrieved from the domain controller.
Audit account management	Audits events, including the creation, deletion, or modification of user, group, or computer accounts and the resetting of user passwords.
Audit directory service access	Audits events that are specified in the system access control list (SACL), which you can see in an Active Directory object’s Properties Advanced Security Settings dialog box. In addition to defining the audit policy with this setting, you must also configure auditing for the specific object or objects by using the SACL of the object or objects. This policy is similar to the Audit Object Access policy that you use to audit files and folders, but this policy applies to Active Directory objects.
Audit policy change	Audits changes to user rights assignment policies, audit policies, or trust policies.
Audit privilege use	Audits the use of a permission or user right. See the explanatory text for this policy in the Group Policy Management Editor.
Audit system events	Audits system restarts, shutdowns, or changes that affect the system or security logs.
Audit process tracking	Audits events such as program activations and process exits. See the explanatory text for this policy in the Group Policy Management Editor.
Audit object access	Audits access to objects such as files, folders, registry keys, and printers that have their own SACLs. In addition to enabling this audit policy, you must configure the auditing entries in the objects’ SACLs.
Configure basic auditing
You can review and configure these basic auditing categories by using the Local Security Policy console, as displayed in the following screenshot. Here, the administrator has selected the Audit Policy node in the Local Security Policy console, and configure Success and Failure audit settings.

This screenshot displays the Local Security Policy console and the basic auditing categories. The Audit Policy node is selected and various Success and Failure audit settings have been configured.
<img width="725" height="452" alt="image" src="https://github.com/user-attachments/assets/387f1a64-62ca-44bd-859e-8a52405987de" />


 Tip

You can also use Group Policy, which makes it easier to configure settings for multiple computers.

Alternatively, in the Group Policy Management console:

Locate and select the appropriate Group Policy Object (GPO), and open the GPO for editing.
In the Group Policy Management Editor, under the Computer Configuration node, expand Policies\Windows Settings\Security Settings\Local Policies, and then select Audit Policy.
In the Group Policy Management Editor, open any policy setting.
Select the Define these policy settings check box, and then select whether to enable the auditing of success events, failure events, or both. Then select OK.
It can be tempting to enable all auditing values across all the available settings. However, this can generate a large audit trail that you must analyze. So, think about being more focused and only enable what's useful for you.

For example, if you audit failed account logon events, you can expose attempts by a malicious hacker to access the domain by repeatedly trying to sign in as a domain user without knowing the account’s password. Auditing successful account logon events is not especially useful as it probably indicates a legitimate logon event.

 Tip

Auditing failed account management events can reveal a malicious hacker who is attempting to manipulate the membership of a security-sensitive group.

One of your most important tasks is to balance and align the audit policy with your corporate policies and with what is realistic for your organization. For example, your corporate policy might state that all failed logon and successful changes to Active Directory users and groups must be audited. That's easy to achieve in Active Directory Domain Services (AD DS). But you should decide how you'll use that information before implementing audit policies.

 Tip

Verbose auditing logs are useless if you don't know how to effectively manage those logs or don't have the tools to do so.

To implement auditing, you must have a well-configured audit policy and the tools with which to manage audited events.

Specify auditing settings on a file or folder
Many organizations choose to audit file access. Windows Server supports granular auditing based on user or group accounts and the specific actions that those accounts perform.

To configure file or folder auditing, you must complete three steps:

Define the Audit object access settings, and choose Success, Failure, or both.

 Note

Enabling Success auditing can generate a large volume of logging data which might be of limited use. After all, it tells you that someone successfully accessed a file or folder. It's more interesting to know when someone fails.

Locate the folder you want to track. Right-click the folder and then select Properties.

On the Security tab, select Advanced.

Select the Auditing tab on the Advanced Security Settings page.

Select Add, choose the security principals whose activity you want to audit on the folder, and then choose the activities you want to track.

In the Type list, choose All, Success, or Fail.

Then choose the permissions you want to track, and finally, select OK twice.

In the following screenshot, the administrator has selected the audit settings for a folder called SalesReports. They have selected to audit Fail access for Domain Users.

This screenshot displays the audit settings for a folder name SalesReports. An audit type of Fail has been selected for Domain users attempting to access the SalesReports folder.
<img width="752" height="425" alt="image" src="https://github.com/user-attachments/assets/a5a30e2c-ba07-4d1d-b1ea-67e45ab7293f" />

Typical usage
You can audit successes for the following purposes:

To log resource access for reporting and billing.
To monitor access suggesting that users are performing actions greater than what you had planned, indicating that permissions are too generous.
To identify access that is out of character for a particular account, which might be a sign that a malicious hacker has breached a user account.
You can audit failed events for the following purposes:

To monitor attempts to access a resource by unauthorized users.
To identify failed attempts to access a file or folder to which a user does require access. This indicates that the permissions are not sufficient to meet a business requirement.
 Warning

Audit logs can grow large quite rapidly. Therefore, configure the bare minimum required to achieve your organization’s security objective.

Evaluate events in the security log
After you enable the Audit Object Access policy setting and use object SACLs to specify the access you want to audit, Windows Server starts to log access according to the audit entries. You can view the resulting events in the server’s security event log. To do this, in Administrative Tools, open the Event Viewer console, and then expand Windows Logs\Security, as displayed in the following screenshot. The administrator has selected the Security log and has highlighted an event with the ID of 4663; this relates to an attempt to access a file object.

This screenshot displays the Event Viewer console in Administrative Tools. Windows Logs\Security is expanded with the Security log selected. An event of ID 4336 is highlighted.
<img width="752" height="425" alt="image" src="https://github.com/user-attachments/assets/dda4a5c3-c206-4ea3-9848-7661f7c18aa2" />

Describe advanced categories

In addition to, or rather instead of, the basic auditing categories described in the last unit, you can implement advanced auditing categories in Windows Server Group Policy. These advanced categories enable you to gather more detailed information about activities in your environment.

For example, in the basic auditing category, you can use Audit logon events. This provides simple success or fail audit logging. However, in advanced categories, you can select the Logon/Logoff category. This provides for 11 policy settings. The following screenshot displays these advanced categories in the Group Policy Management Editor. The administrator has selected the Logon/Logoff category, and 11 subcategories are displayed.

This screenshot displays the Group Policy Management Editor. The Logon/Logoff category is selected and eleven subcategories are displayed.
<img width="983" height="706" alt="image" src="https://github.com/user-attachments/assets/7df34559-c2dd-419b-9abb-abc5014bc139" />

 Warning

Basic audit policy settings aren't compatible with advanced audit policy settings that you apply with Group Policy. When you apply advanced audit policy settings with Group Policy, Windows clears the current computer's audit policy settings before it applies the resulting advanced audit policy settings.

These security auditing enhancements can help your organization’s audit compliance with important business-related and security-related rules by tracking precisely defined activities, such as:

A group administrator modifying settings or data on servers that contain financial information.
An employee within a defined group accessing an important file.
The correct SACL being applied to every file, folder, or registry key on a computer or file share, as a verifiable safeguard against undetected access.
What are the advanced auditing categories?
The following table describes the basic auditing categories.

Advanced audit policy category	Description
Account Logon	These settings enable auditing the validation of credentials and other Kerberos-specific authentication and ticket operation events. The validation of credentials in a domain environment occurs on domain controllers, which means that the auditing entries are logged on domain controllers.
Account Management	You can enable auditing for events that are related to the modification of user accounts, computer accounts, and groups with these settings. This group of auditing settings also logs password change events.
Detailed Tracking	These settings control the auditing of encryption events, Windows process creation and termination events, and remote procedure call (RPC) events.
DS Access	These audit settings involve access to AD DS, including general access, changes, and replication.
Logon/Logoff	This group of settings audits standard logon and logoff events. They also audit other account-specific activity, such as Internet Protocol security (IPsec), Network Policy Server, and other uncategorized logon and logoff events. This is a little different than a related setting, named Account Logon. For Logon/Logoff auditing, these audit events capture events at the destination server. Thus, events are logged to the event log on the destination server. However, the events aren't related to the validation of credentials.
Object Access	These settings enable auditing for any access to AD DS, the registry, applications, and file storage. One of the available subcategories of Object Access is Audit Removable Storage. By auditing removable storage, an administrator can track each time a user accesses or attempts to access data on a removable storage device.
Policy Change	When you configure these settings, internal changes to audit policy settings are audited.
Privilege Use	When you configure these settings, Windows Server 2012 audits attempts at privilege use within the Windows environment.
System	These settings are used for auditing changes to the state of the security subsystem.
Global Object Access Auditing	These settings are for controlling the SACL settings for all objects on one or more computers. When settings in this group are configured and applied with Group Policy, the configuration of the policy setting determines SACL membership, and the SACLs are configured directly on the server itself. You can configure SACLs for file system and registry access under Global Object Access Auditing.
 Important

Don't use both the basic audit policy settings and the advanced policy settings. Using both advanced and basic audit policy settings can cause unexpected results in audit reporting.

Use AuditPol
In addition to using Group Policy, you can use a built-in command-line tool to manage the advanced audit policy settings. The tool is named AuditPol (Auditpol.exe), which offers the following functionality:

Configuring auditing on individual computers. AuditPol manages auditing settings on individual computers, especially computers that aren't joined to an Active Directory domain and thus aren't available for targeting by using Group Policy. AuditPol is especially useful in perimeter networks, where it's common to find standalone computers that aren't domain joined.
Getting the current auditing settings. By running the auditpol /get /category:* command, you can quickly see the current auditing settings across all of the advanced auditing categories.
Update the current auditing settings. By running the auditpol /set /user:Contoso\User1 /subcategory:"Logon" /success:enable /failure:enable /include command, for example, you can audit successful and unsuccessful sign-in access by Contoso\User1.
Backing up and restoring settings across computers. AuditPol has a switch to back up all of the auditing settings and another switch to restore all of the backup settings. This allows administrators to configure auditing settings once, back up the settings, and then use the restore switch to implement the settings on other computers.
Use expression-based audit policies
Dynamic Access Control greatly enhances the way that you can grant access to resources by providing real-time control of access based on predefined expressions. It offers the functionality to apply access control to resources based on:

The classification of the resource.
The device that is being used for access.
The user and specific Active Directory attributes.
Expression-based auditing leverages these capabilities, enabling you to perform auditing based on the result of dynamic access control expressions. The following table describes the capabilities this provides.

Capability	Description
Auditing files and folders based on their classification	If a file or folder is classified as Confidential, it can be audited automatically. As new files and folders are classified, they're audited automatically based on the auditing configuration.
Auditing files and folders based on a specific user and a specific action	Auditing can be granular and allow for targeted auditing based on specific requirements.
Adding contextual information into audit events	Adding information to the events allows for easier filtering and monitoring of events.
Demonstration: Configure advanced auditing
In this demonstration, you learn how to:

Create a folder and enable auditing.
Create a GPO for advanced auditing.
Verify audit entries.
Create a folder and enable auditing
On a server in your domain, create a folder called C:\Marketing and share it.
Right-click the Marketing folder, and select Security.
Ensure the Domain Users group has full control on the folder.
On the Security tab, select Advanced and then select Auditing.
Select Add, and then choose Select a principal.
In the Name box, type Authenticated Users, and then select OK.
Leave the default settings for the Applies to option.
Select the check box next to Modify, and then select OK.
On the Advanced Security Settings for Marketing, select OK.
Select Close, and then share the folder.
Create a GPO for advanced auditing
On your domain controller, from Server Manager, open Active Directory Users and Computers.
Create a new organizational unit (OU) in Contoso.com named File Servers.
Move a server computer from the Computers container to the File Servers OU.
On your domain controller, open Group Policy Management.
Create a new GPO named File Audit, and then link it to the File Servers OU.
Edit the File Audit GPO, and then under Computer Configuration, browse to the Advanced Audit Policy Configuration\Audit Policies\Object Access node.
Configure both the Audit Detailed File Share and Audit Removable Storage settings to record Success and Failure events.
Restart the domain controller, and then sign in.
Verify audit entries
On a client machine, sign in as a user with permissions on the Marketing share.
In File Explorer, map a network drive to the share Marketing folder.
Create and edit a file.
Modify the file contents.
Sign out and switch to your domain controller.
Open Event Viewer, and then view the audit success events in the Security log.
Double-click one of the log entries that has a Source of Microsoft Windows security auditing and a Task Category of Detailed File Share.
Select the Details tab, and then note the access that was performed.

Log user access

User Access Logging (UAL) helps you quantify the number of unique client requests of the roles and services on a local server.

 Important

UAL is installed and enabled by default. You can stop and disable UAL by using Windows PowerShell, the Net Start command, or with Netsh.exe.

Using UAL, you can:

Quantify the following for local servers (physical or virtual):

Client user requests
Client user requests for installed software products
Retrieve data on a local server running Hyper-V to identify periods of high and low demand on a Hyper-V VM.

Retrieve data from multiple remote servers (physical or virtual).

 Tip

You can retrieve UAL data by using WMI or Windows PowerShell interfaces.

What server roles and services are supported?
UAL supports the following server roles and services:

Active Directory Certificate Services (AD CS)
Active Directory Rights Management Services (AD RMS)
BranchCache
Domain Name System (DNS)
Dynamic Host Configuration Protocol (DHCP)
Fax Server
File Services
File Transfer Protocol (FTP) Server
Hyper-V
Web Server (IIS)
Microsoft Message Queue (MSMQ) Services
Network Policy and Access Services
Print and Document Services
Routing and Remote Access Service (RRAS)
Windows Deployment Services (WDS)
Windows Server Update Services (WSUS)
What data is logged?
UAL can log both user and device-related data. The following table describes the user-related data logged by UAL.

Data	Description
UserName	The user name on the client that accompanies the UAL entries from installed roles and products, if applicable.
ActivityCount	The number of times a particular user accessed a role or service.
FirstSeen	The date and time when a user first accesses a role or service.
LastSeen	The date and time when a user last accessed a role or service.
ProductName	The name of the software parent product, such as Windows, that is providing UAL data.
RoleGUID	The UAL assigned or registered GUID that represents the server role or installed product.
RoleName	The name of the role, component, or subproduct that is providing UAL data. This is also associated with a ProductName and a RoleGUID.
TenantIdentifier	A unique GUID for a tenant client of an installed role or product that accompanies the UAL data, if applicable.
The following table describes the device-related data logged by UAL.

Data	Description
IPAddress	The IP address of a client device that is used to access a role or service.
ActivityCount	The number of times a particular device accessed the role or service.
FirstSeen	The date and time when an IP address was first used to access a role or service.
LastSeen	The date and time when an IP address was last used to access a role or service.
ProductName	The name of the software parent product, such as Windows, that is providing UAL data.
RoleGUID	The UAL-assigned or registered GUID that represents the server role or installed product.
RoleName	The name of the role, component, or subproduct that is providing UAL data. This is also associated with a ProductName and a RoleGUID.
TenantIdentifier	A unique GUID for a tenant client of an installed role or product that accompanies the UAL data, if applicable.
 Note

UAL data is stored in C:\Windows\System32\LogFiles\Sum.

 Tip

Because UAL logs the username, the source IP address and details of the service being accessed, it can help you identify unusual or suspicious activity.

Collect UAL data
You can use Windows PowerShell to collect UAL data. The following table describes the available cmdlets.

Cmdlet	Description
Get-UalOverview	Provides UAL related details and history of installed products and roles.
Get-UalServerUser	Provides client user access data for the local or targeted server.
Get-UalServerDevice	Provides client device access data for the local or targeted server.
Get-UalUserAccess	Provides client user access data for each role or product installed on the local or targeted server.
Get-UalDeviceAccess	Provides client device access data for each role or product installed on the local or targeted server.
Get-UalDailyUserAccess	Provides client user access data for each day of the year.
Get-UalDailyDeviceAccess	Provides client device access data for each day of the year.
Get-UalDailyAccess	Provides both client device and user access data for each day of the year.
Get-UalHyperV	Provides virtual machine data relevant to the local or targeted server.
Get-UalDns	Provides DNS client specific data of the local or targeted DNS server.
Get-UalSystemId	Provides system specific data to uniquely identify the local or targeted server.

Enable setup and boot event collection

You can use Setup and Boot Event Collection to review startup and setup events from a number of source computers on a designated collector computer. After data is collected, you can analyze it using Event Viewer, Wevutil.exe, or Windows PowerShell.

What can you monitor?
You can monitor the following events:

Loading of kernel modules and drivers

Enumeration of devices and initialization of their drivers

Verification and mounting of file systems

Starting of executable files

Starting and completions of system updates

The points when the system:

Becomes available for logon
Establishes connection with a domain controller
Completion of service starts
Availability of network shares
Install the collector service
You can install the collector service by using the following command at an elevated Command Prompt: dism /online /enable-feature /featurename:SetupAndBootEventCollection.

Verify correct installation by running the following Windows PowerShell command at an elevated prompt: get-service -displayname *boot*.

The Boot Event Collector service should display as Running, as displayed in the following screenshot.

The screenshot displays a PowerShell session running in a command window. The Boot Event Collector service displays a status of Running.
<img width="1103" height="483" alt="image" src="https://github.com/user-attachments/assets/7ae32404-f191-4f7d-9f5e-aa43b5dea1cf" />

Configure the collector service
After you've installed the collector, you must configure it. This involves two steps:

On the target computers (the ones you collect events from), you must enable the KDNET/EVENT-NET transport and enable the forwarding of events.
On the collector computer, specify from which computers you accept events and define a save location for those events.
Follow the instructions in this document for details: Collect events with Setup and Boot Event Collection.

After you completed configuration, you must restart the target computer(s). After the targets are restarted, they connect to the collector, and events are collected.

Review logs
After events have begun to be collected, you can review them. You can find the log for the collector service itself under: Microsoft-Windows-BootEvent-Collector/Admin.

You can use Event Viewer for a graphical interface for the events. Use the following procedure:

Create a new view.
Expand Applications and Services Logs, then expand Microsoft and then Windows.
Find BootEvent-Collector, expand it, and find Admin.
You can also review use Windows PowerShell: Get-WinEvent -LogName Microsoft-Windows-BootEvent-Collector/Admin.

And from a command prompt: wevtutil qe Microsoft-Windows-BootEvent-Collector/Admin.
