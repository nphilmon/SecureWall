<#
.SYNOPSIS
    Signe des fichiers (Authenticode, SHA-256, horodatés) avec le certificat de signature de code de SecureWall.
.DESCRIPTION
    Choix du certificat, dans l'ordre :
      1. SECUREWALL_SIGN_PFX (+ SECUREWALL_SIGN_PFX_PASSWORD) : fichier .pfx d'un vrai certificat (Sectigo, DigiCert, SSL.com…) ;
      2. SECUREWALL_SIGN_THUMBPRINT : empreinte d'un certificat du magasin (jeton matériel / carte à puce compris) ;
      3. installer\keys\codesign-thumbprint.txt : certificat auto-signé créé par New-SigningCertificate.ps1.
    Utilisé par build-installer.ps1 et appelé par Inno Setup (SignTool) pour l'installateur et le désinstalleur.
    N'exige pas signtool.exe (cmdlet Set-AuthenticodeSignature de Windows PowerShell).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\sign.ps1 publish\SecureWall\SecureWall.exe
#>
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)][string[]]$Path,
    [string]$TimestampServer = $(if ($env:SECUREWALL_SIGN_TIMESTAMP) { $env:SECUREWALL_SIGN_TIMESTAMP } else { "http://timestamp.digicert.com" }),
    [switch]$NoTimestamp
)

$ErrorActionPreference = "Stop"

function Get-SigningCertificate {
    if ($env:SECUREWALL_SIGN_PFX) {
        if (-not (Test-Path $env:SECUREWALL_SIGN_PFX)) { throw "SECUREWALL_SIGN_PFX : fichier introuvable ($env:SECUREWALL_SIGN_PFX)." }
        $pfxPassword = $env:SECUREWALL_SIGN_PFX_PASSWORD
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new($env:SECUREWALL_SIGN_PFX, $pfxPassword)
    }
    $thumb = $env:SECUREWALL_SIGN_THUMBPRINT
    if (-not $thumb) {
        $f = Join-Path $PSScriptRoot "keys\codesign-thumbprint.txt"
        if (Test-Path $f) { $thumb = (Get-Content $f -Raw).Trim() }
    }
    if (-not $thumb) {
        throw "Aucun certificat de signature : créez-en un avec installer\New-SigningCertificate.ps1 ou définissez SECUREWALL_SIGN_PFX / SECUREWALL_SIGN_THUMBPRINT."
    }
    $c = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if (-not $c) { throw "Certificat $thumb introuvable dans les magasins personnels." }
    return $c
}

$cert = Get-SigningCertificate
if (-not $cert.HasPrivateKey) { throw "Le certificat n'a pas de clé privée accessible." }
if ($cert.NotAfter -lt (Get-Date)) { throw "Le certificat de signature a expiré le $($cert.NotAfter.ToString('yyyy-MM-dd'))." }
if ($cert.EnhancedKeyUsageList.ObjectId -notcontains '1.3.6.1.5.5.7.3.3') { throw "Ce certificat n'a pas l'usage « signature de code »." }

$bad = 'HashMismatch', 'NotSigned', 'NotSupportedFileFormat', 'Incompatible'
foreach ($file in $Path) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Fichier introuvable : $file" }
    $sign = @{ FilePath = $file; Certificate = $cert; HashAlgorithm = 'SHA256' }
    if (-not $NoTimestamp) { $sign.TimestampServer = $TimestampServer }
    try { $null = Set-AuthenticodeSignature @sign }
    catch {
        if ($NoTimestamp) { throw }
        Write-Warning "Horodatage impossible ($($_.Exception.Message)) : signature sans horodatage pour $(Split-Path $file -Leaf)."
        $sign.Remove('TimestampServer'); $null = Set-AuthenticodeSignature @sign
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $file
    # « UnknownError / NotTrusted » est normal pour un certificat auto-signé (racine non approuvée) ; HashMismatch ou NotSigned = échec.
    if ($sig.Status -in $bad -or $sig.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
        throw "Échec de la signature de $file (état : $($sig.Status))."
    }
    Write-Host "  signé : $(Split-Path $file -Leaf)  [$($sig.Status)]"
}

