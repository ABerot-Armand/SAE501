$CSVFile = "C:\BDD-Script\base.csv"
$CSVData = Import-CSV -Path $CSVFile -delimiter "," -Encoding UTF8
 
$CSVFileComp = "C:\BDD-Script\ListComp.csv"
$CSVDataComp = Import-CSV -Path $CSVFileComp -delimiter "," -Encoding UTF8
 
New-ADOrganizationalUnit -Name "HQ" -Path "DC=hq,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Users" -Path "OU=HQ,DC=hq,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Groups" -Path "OU=HQ,DC=hq,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Computers" -Path "OU=HQ,DC=hq,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Shadow Groups" -Path "DC=hq,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADGroup -Name "OU_Shadow" -GroupScope Global -Path "OU=Shadow Groups,DC=hq,dc=wsl2024,dc=org" -GroupCategory Security 
 
New-Item -Path "D:\shares" -Name "Public" -ItemType "Directory" -Force
 
 
 
foreach ($ListComp in $CSVDataComp){
    $NomComp = $ListComp.NameComp
    New-ADComputer -Name $NomComp -Path "OU=Computers,OU=HQ,DC=hq,dc=wsl2024,dc=org" -Enabled $true
    }
 
 
foreach ($base in $CSVData){
    $ADGroup = $base.AdGroup
    New-ADOrganizationalUnit -Name $ADGroup -Path "OU=Users,OU=HQ,DC=hq,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
    New-ADGroup -Name "$ADGroup" -GroupScope Global -Path "OU=Groups,OU=HQ,DC=hq,dc=wsl2024,dc=org" -GroupCategory 1
    New-Item -Path "D:\shares\Department" -Name "$ADGroup" -ItemType "Directory" -Force
 
    $acl = Get-ACL -Path "D:\shares\Department\$ADGroup"
    $acl.SetAccessRuleProtection($true, $false)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateur", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("HQ\$ADGroup", "Modify", "Allow")
    $acl.AddAccessRule($AccessRule)
    $acl | Set-Acl -Path "D:\shares\Department\$ADGroup"
 
 
    New-Item -Path "D:\shares\Public" -Name "$ADGroup" -ItemType "Directory" -Force
 
    $acl = Get-ACL -Path "D:\shares\Department\$ADGroup"
    $acl.SetAccessRuleProtection($true, $false)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateur", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("HQ\$ADGroup", "Read, Write", "Allow")
    $acl.AddAccessRule($AccessRule)
    $acl | Set-Acl -Path "D:\shares\Public\$ADGroup"
 
 
    }
 
 
foreach ($base in $CSVData){
    $Prenom = $base.Prenom
    $Nom = $base.Nom
    $Login = $base.Login
    $AdGroupPerso = $base.AdGroup
    $Email = $base.email
    $OfficeNb = $base.OfficeNumber
 
    $ScriptPath = "\\HQDCSRV\scripts"
 
    New-ADUser -Name "$Prenom $Nom" -Path "OU=$AdGroupPerso,OU=Users,OU=HQ,DC=hq,dc=wsl2024,dc=org" -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd" -Force) -DisplayName "$Prenom $Nom" -GivenName "$Prenom" -Surname "$Nom" -ScriptPath "$Prenom $Nom.bat"
    Add-ADGroupMember -Identity "CN=OU_Shadow,OU=Shadow Groups,DC=hq,dc=wsl2024,dc=org" -Members "$Prenom $Nom"
    Add-ADGroupMember -Identity "CN=$ADGroupPerso,OU=GROUPS,OU=HQ,DC=hq,dc=wsl2024,dc=org" -Members "$Prenom $Nom"
 
    New-Item -Path "D:\shares\datausers" -Name "$Prenom $Nom" -ItemType "Directory" -Force
 
    $acl = Get-ACL -Path "D:\shares\datausers\$Prenom $Nom"
    $acl.SetAccessRuleProtection($true, $false)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateur", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("HQ\$Prenom $Nom", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $acl | Set-Acl -Path "D:\shares\datausers\$Prenom $Nom"
 
    New-Item -Path "$ScriptPath" -Name "$Prenom $Nom.bat" -ItemType "File" -Value "
net use \\HQDCSRV\users\$Prenom $Nom
net use \\HQDCSRV\Department\$ADGroupPerso
net use \\HQDCSRV\Public\$ADGroupPerso"
 
    $acl = Get-ACL -Path "$ScriptPath\$Prenom $Nom.bat"
    $acl.SetAccessRuleProtection($true, $false)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateur", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("HQ\$Prenom $Nom", "READ", "Allow")
    $acl.AddAccessRule($AccessRule)
    $acl | Set-Acl -Path "$ScriptPath\$Prenom $Nom.bat"
 
    }
 
# Message de fin du script
Write-Host "Fin du script"
