#Configuring Active Directory Domain Controller

#to register dns: ipconfig /registerdns


# To allow all incomming and out going traffic in the firewall:
New-NetFireWall -DisplayName "<Name of firewall rule>" -Direction Outbound / Inboud -Action Allow

# Get the list of features installed and available on windows machine.
Get-WindowsFeature
Install-WindowsFeature DNS

#Connect to DC1 registery and navigate to the tcip ==> parameters then add domain and NV domain both equal to killer.dev

#try this if nslookup dc1 doesnt work...

ipconfig -registerdns
--- Install active direcotry services & management tools

install-windowsFeature -Name ad-domain-services -IncludeManagementTools
install-ADDSForest -DomainName "Killer.dev"
Get-aduser -filter *

To promote another domain controller server DC2 use:
Install-AddsDomainController -DomainName "killer.dev" -credentail (get-credentail killer\adminstrator)
then type the password etc...

To add new computer to the AD 
Add-Computer -DomainName "killer.dev" -Restart -NewName "<should you wish to change the name of this laptop>"

Manage AD using command line : "ntdsutil" = NT Directory Services Utility -- be carefull while using this command.
so type ntdsutil then press enter
to activate this servers active directory type "activate instance ntds"
to create IFM type ifm and enter
then type "create sysvol full <folder address>"
type quit to exit

once the snapshot is ready
logon to the DC3 and install acitve direcotry domain services using
install-windowsFeature ad-domain-services -domain
then
install-addsdomaincontroller -domainname "killer.dev" -credentail (get-credentail killer\adminstrator) -installationMediaPath "<path where the ifm folder is saved>"

to move OperationalMaster role: Move-ADDirectoryServerOperationMasterRole


==================== Users and Computers ====================================
New-ADUser -Name OKhuwaja -GivenName Okash -Surname Khuwaja -Path "OU=SoftwareDevs, DC=Killer,DC=Dev"
and

@password = "P@ssw0rd" | ConvertTo-SecureString -AsPlainText -Force
New-ADUser -GivenName Okash -Surname Khuwaja -Name OKhuwaja -Path "OU=SoftwareDevs, DC=killer, DC=Dev" -OtherAttributes @{'title'="Senior Software Engineer"; 'mail'="OKhuwaja@killer.dev" } -AccountPassword @password -ChangePasswordAtLogon $true -Enabled $true

==========================
command: CSVDE - csv direcotry exchange
CSVDE c:\FolderName\output.csv --- this will create a csv file containing all objects in the AD.
ldifde - ???? try it!
dsadd - add new objects like users and computers 
dsmod - adjust the configuration of objects.

Bulk Insert into AD

create a csv file..

Name,FirstName,LastName,Password,Title,Mail
YKhuwaja,Yawar,Khuwaja,Pakistan11,Software Engineer,ykhuwaja@killer.dev
ZKhuwaja,Zafar,Khuwaja,Pakistan11,Surgeon,ZKhuwaja@killer.dev
IZainab,Iman,Zainab,Pakistan11,Beautician,IZainab@killer.dev
MKhuwaja,Murtaza,Khuwaja,Pakistan11,Doctor,MKhuwaja@killer.dev


$OU = "OU=SoftwareDevs,DC=Killer,DC=Dev"
$import = Import-Csv -Path "<path of csv file contain users data>"

foreach ($user in $import) {
	$password = $user.password | ConvertTo-SecureString -AsPlainText -Force
	New-ADUser -Name $user.Name -GivenName $user.FirstName -Surname $user.LastName -Path $OU -AccountPassword $password 
	-OtherAttributes @{'mail'=$user.mail;'title'=$user.Title} -ChangePasswordAtLogon $true -Enabled $true 
	}

change company of all software engineers

get-aduser -filter {title -eq 'software engineer'} | set-aduser -company "Killer Solutions"
get-aduser -filter {title -eq 'software engineer'} | disable-adaccount
Get-ADUser -filter * -Properties name, lastlogondate | ft name, lastlogondate will yield a table with name and last logon date columns 

Get-ADUser -filter * -Properties name,givenname,surname,title,mail,canonicalname | ft name, givenname, surname,title, mail, canonicalname 	

Search-ADAccount -PasswordNeverExpires | ft name
=============================

Join Server1 offline
create the file on a domain PC using 
djoin /Provision /domain killer.dev /machine server1 /savefile c:\aduserstobeadded\server1.txt

copy server1.txt file onto the server1...
then logon to the Server1 and run 

djoin /requestodj /loadfile <server1 file path> /windowspath c:\windows /localos

===============================================
Organisational Units OUs 

Create new OU:
New-ADOrganizationalUnit "DevMachines"

redirusr /?  it redirects the default OU for users 

redirusr  "CN=Users,DC=Killer,DC=Dev"  will redirect the default container for users to the "Users"

redirusr CONTAINER-DN
    where CONTAINER-DN is the distinguished name of the container
    that will become the default location for newly created user objects

same for the computers
redircmp "OU=DevMachines,DC=Killer,DC=Dev"

New-ADGroup -Name "GroupWithAllPropertiesSet" -GroupScope DomainLocal -Path "OU=SoftwareDevs,DC=Killer,DC=Dev"  -Description "This is a test group that I am creating using powershell command."

Add-ADGroupMember "BadUsers" ykhuwaja,IZainab
Get-ADGroupMember "badusers"

==================== [AD Groups Nesting] ====================
Best Practice:
Add users into a global group, add this global group into  a domain local group. Assign permissions to this domain local 
group.

USersGlobalGroupLocalGroupAccess

Get-ADUser -Filter 'memberof -recursivematch "cn=GroupWithAllPropertiesSet,OU=SoftwareDevs,DC=Killer,DC=Dev"' | ft name

The End
 