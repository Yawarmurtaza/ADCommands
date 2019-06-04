# Powershell.net - Commands

# PING like commands:
# Test-Connection...
PS C:\> "server1","server2","dc1", "10.0.0.7" | Where-Object {Test-Connection -Quiet -computername $_ -count 1}


# ==== checking if the DNS is running on a server1
PS C:\> "server1", "server2", "dc1" | foreach { Test-NetConnection -ComputerName $_ -Port 53}
WARNING: TCP connect to (10.0.0.51 : 53) failed


ComputerName           : server1
RemoteAddress          : 10.0.0.51
RemotePort             : 53
InterfaceAlias         : Ethernet 2
SourceAddress          : 10.0.0.60
PingSucceeded          : True
PingReplyDetails (RTT) : 3 ms
TcpTestSucceeded       : False

WARNING: TCP connect to (10.0.0.52 : 53) failed
ComputerName           : server2
RemoteAddress          : 10.0.0.52
RemotePort             : 53
InterfaceAlias         : Ethernet 2
SourceAddress          : 10.0.0.60
PingSucceeded          : True
PingReplyDetails (RTT) : 3 ms
TcpTestSucceeded       : False

ComputerName     : dc1
RemoteAddress    : 10.0.0.50
RemotePort       : 53
InterfaceAlias   : Ethernet 2
SourceAddress    : 10.0.0.60
TcpTestSucceeded : True

Filter:
PS C:\> "server1", "server2", "dc1" | foreach { Test-NetConnection -ComputerName $_ -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue }
False
False
True


PS C:\> Test-NetConnection -ComputerName www.pluralsight.com -CommonTCPPort HTTP -InformationLevel Detailed

PS C:\> Resolve-DnsName 10.0.0.50 -- its like nslookup command


PS C:\> Get-Service -Name bits -ComputerName server1, server2, dc1 | stop-Service -Force -PassThru | select machineName, status, DisplayName

MachineName  Status DisplayName                            
-----------  ------ -----------                            
server1     Stopped Background Intelligent Transfer Service
server2     Stopped Background Intelligent Transfer Service
dc1         Stopped Background Intelligent Transfer Service


Get processes:

PS C:\> get-process lsass -ComputerName dc1,server1,server2 | select machinename, id, name, handles, vm, ws | sort handles, machinename -Descending | ft

MachineName  Id Name  Handles            VM       WS
-----------  -- ----  -------            --       --
dc1         520 lsass    1479 2199199809536 50176000
server1     648 lsass     850 2199074119680 13848576




PS C:\> Get-EventLog -ComputerName dc1, server1, server2 -list | where log -EQ "system" | ft -GroupBy log -Property 
@{ Name="ComputerName"; Expression={$_.MachineName}}, 
overflowaction,
@{Name="MaxKB";Expression={$_.maximumkilobytes}}, 
@{name="retain";Expression={$_.MinimumRetentionDays}}, 
@{Name="RecordCount";Expression={$_.entries.count}}


   Log: System

ComputerName    OverflowAction MaxKB retain RecordCount
------------    -------------- ----- ------ -----------
dc1          OverwriteAsNeeded 20480      0        2165
server1      OverwriteAsNeeded 20480      0        3261
server2      OverwriteAsNeeded 20480      0        1698


PS C:\> Get-EventLog -List -ComputerName server1, server2, dc1 | 
	Where-Object {$_.entries.count -gt 0 } | 
	SORT  machineName, log | 
	FT -GroupBy @{Name="ComputerName";Expression = {$_.MachineName.ToUpper()}}


   ComputerName: DC1

  Max(K) Retain OverflowAction        Entries Log                                                                                                                                                    
  ------ ------ --------------        ------- ---                                                                                                                                                    
     512      7 OverwriteOlder            100 Active Directory Web Services                                                                                                                          
  20,480      0 OverwriteAsNeeded       1,165 Application                                                                                                                                            
  15,168      0 OverwriteAsNeeded         111 DFS Replication                                                                                                                                        
     512      0 OverwriteAsNeeded         207 Directory Service                                                                                                                                      
 102,400      0 OverwriteAsNeeded         105 DNS Server                                                                                                                                             
 131,072      0 OverwriteAsNeeded      13,922 Security                                                                                                                                               
  20,480      0 OverwriteAsNeeded       2,165 System                                                                                                                                                 
  15,360      0 OverwriteAsNeeded          50 Windows PowerShell                                                                                                                                     


   ComputerName: SERVER1

  Max(K) Retain OverflowAction        Entries Log                                                                                                                                                    
  ------ ------ --------------        ------- ---                                                                                                                                                    
  20,480      0 OverwriteAsNeeded       1,180 Application                                                                                                                                            
  20,480      0 OverwriteAsNeeded       1,843 Security                                                                                                                                               
  20,480      0 OverwriteAsNeeded       3,262 System                                                                                                                                                 
  15,360      0 OverwriteAsNeeded         140 Windows PowerShell                                                                                                                                     


   ComputerName: SERVER2

  Max(K) Retain OverflowAction        Entries Log                                                                                                                                                    
  ------ ------ --------------        ------- ---                                                                                                                                                    
  20,480      0 OverwriteAsNeeded         720 Application                                                                                                                                            
  20,480      0 OverwriteAsNeeded       1,071 Security                                                                                                                                               
  20,480      0 OverwriteAsNeeded       1,698 System                                                                                                                                                 
  15,360      0 OverwriteAsNeeded          70 Windows PowerShell 
  

# Get all the commands that take ComputerName as parameter:
PS C:\> Get-Command -CommandType Cmdlet -ParameterName ComputerName


#G et-Command can also help us to find the commands for certain nouns like:

PS C:\> Get-Command -Noun netfirewallrule

CommandType     Name                                               Version    Source                                                                                                                 
-----------     ----                                               -------    ------                                                                                                                 
Function        Copy-NetFirewallRule                               2.0.0.0    NetSecurity                                                                                                            
Function        Disable-NetFirewallRule                            2.0.0.0    NetSecurity                                                                                                            
Function        Enable-NetFirewallRule                             2.0.0.0    NetSecurity                                                                                                            
Function        Get-NetFirewallRule                                2.0.0.0    NetSecurity                                                                                                            
Function        New-NetFirewallRule                                2.0.0.0    NetSecurity                                                                                                            
Function        Remove-NetFirewallRule                             2.0.0.0    NetSecurity                                                                                                            
Function        Rename-NetFirewallRule                             2.0.0.0    NetSecurity                                                                                                            
Function        Set-NetFirewallRule                                2.0.0.0    NetSecurity                                                                                                            
Function        Show-NetFirewallRule                               2.0.0.0    NetSecurity                                                                                                            



PS C:\> Get-Command -Noun computer

CommandType     Name                                               Version    Source                                                                                                                 
-----------     ----                                               -------    ------                                                                                                                 
Cmdlet          Add-Computer                                       3.1.0.0    Microsoft.PowerShell.Management                                                                                        
Cmdlet          Checkpoint-Computer                                3.1.0.0    Microsoft.PowerShell.Management                                                                                        
Cmdlet          Remove-Computer                                    3.1.0.0    Microsoft.PowerShell.Management                                                                                        
Cmdlet          Rename-Computer                                    3.1.0.0    Microsoft.PowerShell.Management                                                                                        
Cmdlet          Restart-Computer                                   3.1.0.0    Microsoft.PowerShell.Management                                                                                        
Cmdlet          Restore-Computer                                   3.1.0.0    Microsoft.PowerShell.Management                                                                                        
Cmdlet          Stop-Computer                                      3.1.0.0    Microsoft.PowerShell.Management                                                                                        



PS C:\> Get-Command -Noun adorganizationalunit

CommandType     Name                                               Version    Source                                                                                                                 
-----------     ----                                               -------    ------                                                                                                                 
Cmdlet          Get-ADOrganizationalUnit                           1.0.0.0    ActiveDirectory                                                                                                        
Cmdlet          New-ADOrganizationalUnit                           1.0.0.0    ActiveDirectory                                                                                                        
Cmdlet          Remove-ADOrganizationalUnit                        1.0.0.0    ActiveDirectory                                                                                                        
Cmdlet          Set-ADOrganizationalUnit                           1.0.0.0    ActiveDirectory      


# get firewall rules...

PS C:\> Get-NetFirewallRule -Enabled True | Select-Object displayName,Description, Direction | ft 


# -whatif parameter allows us to write a query without actually taking action..
PS C:\> Get-NetFirewallRule remote* | where {$_.Profile -contains "domain" -and $_.Enabled -eq "true"} | Enable-NetFirewallRule -WhatIf
What if: Enable-NetFirewallRule DisplayName: RemoteAssistance-RAServer-In-TCP-NoScope-Active
What if: Enable-NetFirewallRule DisplayName: RemoteAssistance-RAServer-Out-TCP-NoScope-Active
What if: Enable-NetFirewallRule DisplayName: RemoteAssistance-DCOM-In-TCP-NoScope-Active


#===================================================
#				POWERSHELL REMOTING
#===================================================

# By default the WINRM service is stopped  and the firewall rules are disabled. This prevents other PCs to connect to the computer using powershell.
# To enable remote powershell do these:

# 1. enable powershell remoting on the target computer
PS C:\> Enable-PSRemoting 
WinRM is already set up to receive requests on this computer.
WinRM is already set up for remote management on this computer.


#2. Test-WSMan
PS C:\> Test-WSMan -ComputerName dc1

wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0

# 3. start powershell session...
PS C:\> Enter-PSSession -ComputerName server1


# To stop a computer from remote powershell...

# 1. Disable remote powersehll

PS C:\> Disable-PSRemoting -Force
WARNING: Disabling the session configurations does not undo all the changes made by the Enable-PSRemoting or Enable-PSSessionConfiguration cmdlet. You might have to manually undo the 
changes by following these steps:
    1. Stop and disable the WinRM service.
    2. Delete the listener that accepts requests on any IP address.
    3. Disable the firewall exceptions for WS-Management communications.
    4. Restore the value of the LocalAccountTokenFilterPolicy to 0, which restricts remote access to members of the Administrators group on the computer.

#2. stop WINRM service
PS C:\> Stop-Service winrm

#3. Disable WINRM Service
PS C:\> Set-Service winrm -StartupType Disabled

#4. Disable firewall rules

PS C:\> Get-NetFirewallRule -Name *winrm* | select name, enable, profile, action |ft

Name                             enable         Profile Action
----                             ------         ------- ------
WINRM-HTTP-In-TCP-NoScope               Domain, Private  Allow
WINRM-HTTP-In-TCP                                Public  Allow
WINRM-HTTP-Compat-In-TCP-NoScope                 Domain  Allow
WINRM-HTTP-Compat-In-TCP                Private, Public  Allow

# Disable winrm-http-in-TCP* firewall rules...

PS C:\> Disable-NetFirewallRule -Name winrm-http-in-tcp*

# or block the rule like this:
PS C:\> Set-NetFirewallRule -Name winrm-http-in-tcp* -Action Block

PS C:\> Get-NetFirewallRule -Name *winrm* | select name, enable, profile, action |ft

Name                             enable         Profile Action
----                             ------         ------- ------
WINRM-HTTP-In-TCP-NoScope               Domain, Private  Block
WINRM-HTTP-In-TCP                                Public  Block
WINRM-HTTP-Compat-In-TCP-NoScope                 Domain  Allow
WINRM-HTTP-Compat-In-TCP                Private, Public  Allow

#
# INVOKE COMMAND
#

PS C:\Users\yawar> $v = Invoke-Command -ScriptBlock {

Get-Item HKLM:\SYSTEM\CurrentControlSet\Control\BitlockerStatus




} -ComputerName server1

PS C:\Users\yawar> $v


    Hive: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control


Name                           Property                                                                    PSComputerName                                                             
----                           --------                                                                    --------------                                                             
BitlockerStatus                BootStatus : 0                                                              server1                                                                    



PS C:\Users\yawar> $v | Get-Member


   TypeName: Deserialized.Microsoft.Win32.RegistryKey

Name               MemberType   Definition                                                                                                                                            
----               ----------   ----------                                                                                                                                            
ToString           Method       string ToString(), string ToString(string format, System.IFormatProvider formatProvider), string IFormattable.ToString(string format, System.IForma...
Property           NoteProperty Deserialized.System.String[] Property=BootStatus                                                                                                      
PSChildName        NoteProperty string PSChildName=BitlockerStatus                                                                                                                    
PSComputerName     NoteProperty string PSComputerName=server1                                                                                                                         
PSDrive            NoteProperty Deserialized.System.Management.Automation.PSDriveInfo PSDrive=HKLM                                                                                    
PSIsContainer      NoteProperty bool PSIsContainer=True                                                                                                                               
PSParentPath       NoteProperty string PSParentPath=Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control                                           
PSPath             NoteProperty string PSPath=Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BitlockerStatus                                 
PSProvider         NoteProperty Deserialized.System.Management.Automation.ProviderInfo PSProvider=Microsoft.PowerShell.Core\Registry                                                  
PSShowComputerName NoteProperty bool PSShowComputerName=True                                                                                                                          
RunspaceId         NoteProperty guid RunspaceId=97563446-5db5-4004-9f7e-70cbdc49d1b4                                                                                                  
Handle             Property     System.String {get;set;}                                                                                                                              
Name               Property     System.String {get;set;}                                                                                                                              
SubKeyCount        Property     System.Int32 {get;set;}                                                                                                                               
ValueCount         Property     System.Int32 {get;set;}                                                                                                                               
View               Property     System.String {get;set;}     




PS C:\> Invoke-Command -ScriptBlock {
Get-Process | SORT WS -Descending | SELECT -First 5
} -ComputerName SERVER1, SERVER2 -Credential POWERSHELL\ADMINISTRATOR

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                    PSComputerName                                               
-------  ------    -----      -----     ------     --  -- -----------                                                    --------------                                               
   1075      39    96328     124060      14.63   3728   3 powershell                                                     SERVER2                                                      
    576      27    60440      74628       0.67   3212   0 wsmprovhost                                                    SERVER2                                                      
    583      21    42616      47904       1.95   1004   0 svchost                                                        SERVER2                                                      
    390      56    97172      46932       8.33   1668   0 MsMpEng                                                        SERVER2                                                      
   1190      42    16800      35480       6.39    840   0 svchost                                                        SERVER2                                                      
   1038      36    94348     116104      12.17   1760   1 powershell                                                     SERVER1                                                      
    475      54   121108      77124      10.22   1580   0 MsMpEng                                                        SERVER1                                                      
    566      27    60412      74608       0.73   1372   0 wsmprovhost                                                    SERVER1                                                      
    599      20    33204      42200       1.97   1004   0 svchost                                                        SERVER1                                                      
   1211      43    16236      35568       6.95    436   0 svchost                                                        SERVER1             
   
   
   

PS C:\> $sessions = New-PSSession -ComputerName server1, server2, dc1

PS C:\> $sessions

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  7 WinRM7          dc1             RemoteMachine   Opened        Microsoft.PowerShell     Available
  5 WinRM5          server1         RemoteMachine   Opened        Microsoft.PowerShell     Available
  6 WinRM6          server2         RemoteMachine   Opened        Microsoft.PowerShell     Available   
  
  
  
PS C:\> $sessionServer1 = Get-PSSession | where computername -EQ server1

PS C:\> $sessionServer1

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  5 WinRM5          server1         RemoteMachine   Opened        Microsoft.PowerShell     Available
  
  
  
PS C:\> Invoke-Command {$x=100} -Session $sessionServer1

PS C:\> Invoke-Command {$x+$X} -Session $sessionServer1
200
  
PS C:\> Invoke-Command {Get-Service bits } -Session $sessions

Status   Name               DisplayName                            PSComputerName                                                                                                     
------   ----               -----------                            --------------                                                                                                     
Stopped  bits               Background Intelligent Transfer Ser... dc1                                                                                                                
Stopped  bits               Background Intelligent Transfer Ser... server2                                                                                                            
Stopped  bits               Background Intelligent Transfer Ser... server1                                                                                                            


PS C:\> $serverInfo = {
$fileObject = New-Object -Com scripting.fileSystemObject
$fileObject.drives | where drivetype -EQ 2 | select Path, 
@{name="sizeGB";Expression={$_.totalsize/1gb -as [int]}},
@{name="freeGB";Expression={$_.freespace/1gb}},
@{name="availGB";Expression={$_.availableSptaceGB/1gb}},
@{name="computername";Expression={$env:omputerName}}

}

PS C:\> $serverInfo = {

$fileObject = New-Object -Com scripting.fileSystemObject
$fileObject.drives | where drivetype -EQ 2 | select Path, 
@{name="sizeGB";Expression={$_.totalsize/1gb -as [int]}},
@{name="freeGB";Expression={$_.freespace/1gb}},
@{name="availGB";Expression={$_.availableSptaceGB/1gb}},
@{name="computername";Expression={$env:computerName}}

}



PS C:\> Invoke-Command -ScriptBlock $serverInfo -Session $sessions


Path           : C:
sizeGB         : 19
freeGB         : 11.6613159179688
availGB        : 0
computername   : 
PSComputerName : dc1
RunspaceId     : 2b29f6c2-48d5-4939-a0ae-0cca02782c98

Path           : C:
sizeGB         : 14
freeGB         : 7.67639541625977
availGB        : 0
computername   : 
PSComputerName : server2
RunspaceId     : 2f1534fd-5965-47e5-8ecb-cd7127ce6504

Path           : C:
sizeGB         : 14
freeGB         : 7.5555305480957
availGB        : 0
computername   : 
PSComputerName : server1
RunspaceId     : ad11ac4a-b2eb-4951-af95-b86ba5472630




PS C:\> Invoke-Command -ScriptBlock $serverInfo -Session $sessions | ft

Path sizeGB           freeGB availGB computername PSComputerName RunspaceId                          
---- ------           ------ ------- ------------ -------------- ----------                          
C:       19 11.6613159179688       0              dc1            2b29f6c2-48d5-4939-a0ae-0cca02782c98
C:       14 7.67639541625977       0              server2        2f1534fd-5965-47e5-8ecb-cd7127ce6504
C:       14  7.5555305480957       0              server1        ad11ac4a-b2eb-4951-af95-b86ba5472630


PS C:\> Invoke-Command -ScriptBlock $serverInfo -Session $sessions -HideComputerName | Select-Object * -ExcludeProperty runspaceid | ft

Path sizeGB           freeGB availGB computername
---- ------           ------ ------- ------------
C:       19 11.6613159179688       0 DC1         
C:       14 7.67639541625977       0 SERVER2     
C:       14 7.55546951293945       0 SERVER1     


# Remove sessions:

PS C:\> Remove-PSSession -Session $sessions


#
#   For a non domain computer 
#

PS C:\> Invoke-Command {Get-Service } -computername server3


#ERROR:
PS C:\> Test-WSMan -ComputerName server3 -Credential $cred -Authentication Negotiate
# Test-WSMan : <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="1312" Machine="WIN-10-Client.Powershell.net"><f:Message>WinRM cannot process the 
# request. The following error with error code 0x8009030e occurred while using Negotiate authentication: A specified logon session does not exist. It may already have been terminated. 
 
 # This can occur if the provided credentials are not valid on the target server, or if the server identity could not be verified.  If you trust the server identity, add the server 
# name to the TrustedHosts list, and then retry the request. Use winrm.cmd to view or edit the TrustedHosts list. Note that computers in the TrustedHosts list might not be 
# authenticated. For more information about how to edit the TrustedHosts list, run the following command: winrm help config. </f:Message></f:WSManFault>
# At line:1 char:1
# + Test-WSMan -ComputerName server3 -Credential $cred -Authentication Ne ...
# + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # + CategoryInfo          : InvalidOperation: (server3:String) [Test-WSMan], InvalidOperationException
    # + FullyQualifiedErrorId : WsManError,Microsoft.WSMan.Management.TestWSManCommand
 
# Reason: WSman needs to have a way to verify that the server name is who it says it is. In this case its Server3 

PS C:\> Get-Item -Path WSMan:\localhost\Client\TrustedHosts


   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Client

Type            Name                           SourceOfValue   Value                                                                                                                  
----            ----                           -------------   -----                                                                                                                  
System.String   TrustedHosts                        



PS C:\> Test-WSMan -ComputerName server3 -Credential $cred -Authentication Negotiate


wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 10.0.14393 SP: 0.0 Stack: 3.0


PS C:\> Invoke-Command {Get-Service -Name WinRM } -computername server3 -Credential $cred

Status   Name               DisplayName                            PSComputerName                                                                                                     
------   ----               -----------                            --------------                                                                                                     
Running  WinRM              Windows Remote Management (WS-Manag... server3    

#========================================================================================================================
#														Windows Management Instrumentation (WMI)
#========================================================================================================================


PS C:\> Get-WmiObject -Class win32_operatingsystem -List

PS C:\> $servers = "dc1", "server1", "server2", "workpc"

PS C:\> Get-WmiObject -Class win32_operatingsystem -ComputerName $servers | select __server, caption, OSarchitecture, installdate | ft

__SERVER caption                                             OSarchitecture installdate              
-------- -------                                             -------------- -----------              
DC1      Microsoft Windows Server 2016 Datacenter Evaluation 64-bit         20190530035935.000000+060
SERVER1  Microsoft Windows Server 2016 Datacenter Evaluation 64-bit         20190530035707.000000+060
SERVER2  Microsoft Windows Server 2016 Datacenter Evaluation 64-bit         20190530035735.000000+060


PS C:\> Get-WmiObject -Class win32_operatingsystem -ComputerName $servers | select __server, caption, OSarchitecture, installdate,servicepackmajorversion,
 @{name="Installed"; expression={$_.ConvertoDatetime($_.InstallDate)}} | ft

__SERVER caption                                             OSarchitecture installdate               servicepackmajorversion Installed
-------- -------                                             -------------- -----------               ----------------------- ---------
DC1      Microsoft Windows Server 2016 Datacenter Evaluation 64-bit         20190530035935.000000+060                       0          
SERVER1  Microsoft Windows Server 2016 Datacenter Evaluation 64-bit         20190530035707.000000+060                       0          
SERVER2  Microsoft Windows Server 2016 Datacenter Evaluation 64-bit         20190530035735.000000+060                       0         


PS C:\> Get-WmiObject win32_process -ComputerName server2 | select *  | ft

PSComputerName ProcessName         Handles            VM       WS Path                              __GENUS __CLASS       __SUPERCLASS __DYNASTY               
-------------- -----------         -------            --       -- ----                              ------- -------       ------------ ---------               
SERVER2        System Idle Process       0         65536     4096                                         2 Win32_Process CIM_Process  CIM_ManagedSystemElement
SERVER2        System                  733       3567616   131072                                         2 Win32_Process CIM_Process  CIM_ManagedSystemElement
SERVER2        smss.exe                 54 2199029915648  1212416                                         2 Win32_Process CIM_Process  CIM_ManagedSystemElement
SERVER2        csrss.exe               202 2199072215040  4313088                                         2 Win32_Process CIM_Process  CIM_ManagedSystemElement
# this list is all the processes on server2


PS C:\> Get-WmiObject win32_process -ComputerName server2 | Where-Object {$_.name -eq "lsass.exe"} | ft

__GENUS __CLASS       __SUPERCLASS __DYNASTY                __RELPATH                  __PROPERTY_COUNT __DERIVATION                                                __SERVER __NAMESP
                                                                                                                                                                             ACE     
------- -------       ------------ ---------                ---------                  ---------------- ------------                                                -------- --------
      2 Win32_Process CIM_Process  CIM_ManagedSystemElement Win32_Process.Handle="648"               45 {CIM_Process, CIM_LogicalElement, CIM_ManagedSystemElement} SERVER2  root\...

	  

# WITH SELECT QUERY ... THIS WILL RUN ON THE TARGET SERVER 	AND WILL RETURN ON THE RESULT OF SELECT QUERY:

PS C:\> Get-WmiObject -ComputerName "server2" -Query "SELECT * FROM WIN32_PROCESS WHERE NAME = 'LSASS.EXE'" | FT

__GENUS __CLASS       __SUPERCLASS __DYNASTY                __RELPATH                  __PROPERTY_COUNT __DERIVATION                                                __SERVER __NAMESP
                                                                                                                                                                             ACE     
------- -------       ------------ ---------                ---------                  ---------------- ------------                                                -------- --------
      2 Win32_Process CIM_Process  CIM_ManagedSystemElement Win32_Process.Handle="648"               45 {CIM_Process, CIM_LogicalElement, CIM_ManagedSystemElement} SERVER2  root\...
	  
	  
	  
PS C:\> Get-WmiObject win32_logicaldisk -Filter "deviceid='c:'" -ComputerName $servers -Credential $cred | select * | ft

PSComputerName Status Availability DeviceID StatusInfo __GENUS __CLASS           __SUPERCLASS    __DYNASTY                __RELPATH                      
-------------- ------ ------------ -------- ---------- ------- -------           ------------    ---------                ---------                      
DC1                                C:                        2 Win32_LogicalDisk CIM_LogicalDisk CIM_ManagedSystemElement Win32_LogicalDisk.DeviceID="C:"
SERVER1                            C:                        2 Win32_LogicalDisk CIM_LogicalDisk CIM_ManagedSystemElement Win32_LogicalDisk.DeviceID="C:"
SERVER2                            C:                        2 Win32_LogicalDisk CIM_LogicalDisk CIM_ManagedSystemElement Win32_LogicalDisk.DeviceID="C:"


PS C:\> Get-WmiObject win32_logicaldisk -Filter "deviceid='c:'" -ComputerName $servers -Credential $cred | select pscomputername, caption, 
@{name="sizegb";expression={($_.sezegb / 1gb)}}, @{name="freegb";express={($_.freespace/1gb)}}, @{name="pctfree";express={($_.freespace/$_.size)*100}}, 
@{name="Total";expression={$_.size/1gb}}  | ft 

PSComputerName caption sizegb           freegb          pctfree            Total
-------------- ------- ------           ------          -------            -----
DC1            C:           0 11.6539916992188 59.9291409681217 19.4462852478027
SERVER1        C:           0 7.54981231689453 52.2612712360975 14.4462852478027
SERVER2        C:           0 7.67166519165039  53.104760566854 14.4462852478027


# with credentials:	 

PS C:\> Get-WmiObject win32_logicaldisk -Filter "deviceid='c:'" -ComputerName "server3" -Credential server3\administrator | select __server, @{Name="TotalSpace";expression={$_.Size/1gb}} | ft

__SERVER       TotalSpace
--------       ----------
SERVER3  14.4462852478027


# Windows Management Instrumentation - TEST TOOL: 
# wbemtest
  