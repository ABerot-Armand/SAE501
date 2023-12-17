$CSVFile = "C:\BDD-Script\baseP.csv"
$CSVData = Import-CSV -Path $CSVFile -delimiter "," -Encoding UTF8
 
$CSVFileComp = "C:\BDD-Script\ListComp.csv"
$CSVDataComp = Import-CSV -Path $CSVFileComp -delimiter "," -Encoding UTF8
 
New-ADOrganizationalUnit -Name "REM" -Path "DC=rem,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Workers" -Path "OU=REM,DC=rem,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Groups" -Path "DC=rem,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Computers" -Path "OU=REM,DC=rem,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False

 

 
foreach ($ListComp in $CSVDataComp){
    $NomComp = $ListComp.NameComp
    New-ADComputer -Name $NomComp -Path "OU=Computers,OU=REM,DC=rem,dc=wsl2024,dc=org" -Enabled $true
    }
 
 
foreach ($base in $CSVData){
    $ADGroup = $base.AdGroup
    New-ADOrganizationalUnit -Name $ADGroup -Path "OU=Users,OU=REM,DC=rem,dc=wsl2024,dc=org" -ProtectedFromAccidentalDeletion $False
    New-ADGroup -Name "$ADGroup" -GroupScope Global -Path "OU=Groups,DC=rem,dc=wsl2024,dc=org" -GroupCategory 1
    New-Item -Path "\\rem.wsl2024.org\Department" -Name "$ADGroup" -ItemType "Directory" -Force
 
    $acl = Get-ACL -Path "\\rem.wsl2024.org\Department\$ADGroup"
    $acl.SetAccessRuleProtection($true, $false)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateur", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("HQ\$ADGroup", "Modify", "Allow")
    $acl.AddAccessRule($AccessRule)
    $acl | Set-Acl -Path "\\rem.wsl2024.org\Department\$ADGroup"
 
    }
 
 
foreach ($base in $CSVData){
    $Prenom = $base.Prenom
    $Nom = $base.Nom
    $Login = $base.Login
    $AdGroupPerso = $base.AdGroup
    $Email = $base.email
    $OfficeNb = $base.OfficeNumber
 
    $ScriptPath = "\\REMDCSRV\scripts"
 
    New-ADUser -Name "$Prenom $Nom" -Path "OU=$AdGroupPerso,OU=Users,OU=HQ,DC=hq,dc=wsl2024,dc=org" -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd" -Force) -DisplayName "$Prenom $Nom" -GivenName "$Prenom" -Surname "$Nom" -ScriptPath "$Prenom $Nom.bat"
    if ($AdGroupPerso -eq "IT")
	{
		Add-ADGroupMember -Identity "Administrateur" -Members "$Prenom $Nom"
	}
    Add-ADGroupMember -Identity "CN=$ADGroupPerso,OU=GROUPS,OU=HQ,DC=hq,dc=wsl2024,dc=org" -Members "$Prenom $Nom"
 
    New-Item -Path "\\rem.wsl2024.org\users" -Name "$Prenom $Nom" -ItemType "Directory" -Force
 
    $acl = Get-ACL -Path "\\rem.wsl2024.org\users\$Prenom $Nom"
    $acl.SetAccessRuleProtection($true, $false)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateur", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("HQ\$Prenom $Nom", "FullControl", "Allow")
    $acl.AddAccessRule($AccessRule)
    $acl | Set-Acl -Path "\\rem.wsl2024.org\users\$Prenom $Nom"
 
    New-Item -Path "$ScriptPath" -Name "$Prenom $Nom.bat" -ItemType "File" -Value "
net use \\REMDCSRV\users\$Prenom $Nom
net use \\REMDCSRV\Department\$ADGroupPerso"
 
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
