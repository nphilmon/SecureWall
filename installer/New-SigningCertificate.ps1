<#
.SYNOPSIS
    Crée un certificat de signature de code AUTO-SIGNÉ pour SecureWall (à utiliser tant qu'on n'a pas de vrai certificat).
.DESCRIPTION
    - Certificat RSA 3072 / SHA-256, usage « signature de code », créé dans le magasin PERSONNEL de l'utilisateur (Cert:\CurrentUser\My).
    - Aucun certificat n'est ajouté aux autorités racine ni aux éditeurs approuvés : rien n'est modifié dans la confiance de Windows.
    - Exporte dans installer\keys\ (dossier ignoré par git) : le .cer (public), le .pfx (clé privée protégée par mot de passe),
      le mot de passe du .pfx et l'empreinte utilisée par sign.ps1.
    Un certificat auto-signé garantit l'intégrité des fichiers et affiche l'éditeur, mais Windows SmartScreen avertit tant que le
    certificat n'est pas approuvé (voir README) : seul un certificat d'une autorité reconnue supprime l'avertissement.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\New-SigningCertificate.ps1
    powershell -ExecutionPolicy Bypass -File installer\New-SigningCertificate.ps1 -Subject "Nicolas Philmon" -Years 5
#>
param(
    [string]$Subject = "SecureWall Security",
    [ValidateRange(1, 10)][int]$Years = 3,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$keys = Join-Path $PSScriptRoot "keys"
New-Item -ItemType Directory -Force $keys | Out-Null
$thumbFile = Join-Path $keys "codesign-thumbprint.txt"
if ((Test-Path $thumbFile) -and -not $Force) {
    throw "Un certificat de signature existe déjà (empreinte dans $thumbFile). Relancez avec -Force pour en créer un nouveau (l'ancien reste dans le magasin)."
}

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$Subject" -FriendlyName "SecureWall - signature de code (auto-signé)" `
    -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears($Years)

$cer = Join-Path $keys "SecureWall-codesign.cer"
$pfx = Join-Path $keys "SecureWall-codesign.pfx"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null

# Mot de passe aléatoire (24 octets) pour la sauvegarde .pfx.
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes)
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString $password -AsPlainText -Force) | Out-Null
Set-Content (Join-Path $keys "codesign-pfx-password.txt") $password -Encoding ASCII
Set-Content $thumbFile $cert.Thumbprint -Encoding ASCII

Write-Host "Certificat créé : CN=$Subject" -ForegroundColor Green
Write-Host "  Empreinte  : $($cert.Thumbprint)"
Write-Host "  Valide     : jusqu'au $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Fichiers   : $keys  (public : SecureWall-codesign.cer ; sauvegarde : .pfx + mot de passe) — ne les partagez JAMAIS, sauf le .cer."
