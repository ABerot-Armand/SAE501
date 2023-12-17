# Spécifiez le chemin du fichier CSV de sortie
$CSVFilePath = "C:\BDD-Script\base_auto.csv"
 
# Array pour stocker les données des utilisateurs
$UserData = @()
 
# Ajoutez les utilisateurs créés automatiquement au tableau
for ($i = 1; $i -le 1000; $i++) {
    $username = "wslusr{0:D3}" -f $i
    $userPrincipalName = "$username@hq.wsl2024.org"
 
    # Déterminez à quel groupe l'utilisateur appartient
    $group = if ($i -le 500) { "FirstGroup" } else { "LastGroup" }
 
    # Créez un objet PSObject pour chaque utilisateur avec l'ordre spécifié
    $userObject = [PSCustomObject]@{
        Prenom          = "wslusr"
        Nom             = $i
        Login           = $username
        ADgroup      = $group
        email           = $userPrincipalName
        OfficeNumber = "XXX"
    }
 
    # Ajoutez l'objet utilisateur au tableau
    $UserData += $userObject
}
 
# Convertir les données en objet CSV et exporter vers le fichier CSV
$UserData | Select-Object Prenom, Nom, Login, ADgroup, email, OfficeNumber | 
    ConvertTo-Csv -Delimiter "," -NoTypeInformation | 
    ForEach-Object { $_ -replace '"', '' } | 
    Out-File -FilePath $CSVFilePath -Encoding UTF8
 
# Message de fin du script
Write-Host "Le fichier CSV a été généré avec succès : $CSVFilePath"
 
