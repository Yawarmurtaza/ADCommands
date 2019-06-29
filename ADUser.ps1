$RequiredUsername = "<username>"
$AdminGroup = [ADSI]"WinNT://LOCALHOST/Administrators,group"
$User = [ADSI]"WinNT://DEV.Net/$RequiredUsername,user"
$AdminGroup.Add($User.Path)