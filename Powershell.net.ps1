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



