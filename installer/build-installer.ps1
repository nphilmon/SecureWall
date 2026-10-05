<#
.SYNOPSIS
    Publie SecureWall (application + service privilégié, win-x64 autonome) puis génère l'installateur avec Inno Setup.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\build-installer.ps1
.NOTES
    Prérequis : SDK .NET 8, Inno Setup 6 (ISCC.exe). Aucun paramètre du système n'est modifié.
#>
param(
    [string]$Configuration = "Release",
    [switch]$SkipInstaller,
    [switch]$NoSign      # ne pas signer (par défaut : signature avec le certificat de installer\sign.ps1)
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root "publish\SecureWall"
if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }

Write-Host "== Publication de l'application et du service privilégié ==" -ForegroundColor Cyan
foreach ($proj in "src\SecureWall.App\SecureWall.App.csproj", "src\SecureWall.PrivilegedService\SecureWall.PrivilegedService.csproj") {
    dotnet publish (Join-Path $root $proj) -c $Configuration -r win-x64 --self-contained true -o $publish `
        -p:DebugType=none -p:DebugSymbols=false
    if ($LASTEXITCODE -ne 0) { throw "Échec de la publication de $proj" }
}

if (-not (Test-Path (Join-Path $publish "SecureWall.exe"))) { throw "SecureWall.exe est introuvable dans $publish" }
if (-not (Test-Path (Join-Path $publish "SecureWall.PrivilegedService.exe"))) { throw "SecureWall.PrivilegedService.exe est introuvable dans $publish" }

$signScript = Join-Path $PSScriptRoot "sign.ps1"
if (-not $NoSign) {
    Write-Host "== Signature des binaires SecureWall ==" -ForegroundColor Cyan
    # Uniquement nos assemblages : on ne re-signe jamais les DLL de Microsoft ni des bibliothèques tierces.
    $own = Get-ChildItem $publish -Recurse -File | Where-Object { $_.Name -like "SecureWall*.exe" -or $_.Name -like "SecureWall*.dll" } | ForEach-Object FullName
    & $signScript -Path $own
    if ($LASTEXITCODE -gt 0) { throw "Échec de la signature des binaires" }
}
if ($SkipInstaller) { Write-Host "Publication terminée : $publish"; exit 0 }

$iscc = @(
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup (6 ou 7) est introuvable. Installez-le (winget install JRSoftware.InnoSetup) puis relancez." }

Write-Host "== Compilation de l'installateur ==" -ForegroundColor Cyan
$isccArgs = @()
if (-not $NoSign) {
    $isccArgs += "/DSign=1"
    $isccArgs += ('/Ssw=powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" $f' -f $signScript)
}
& $iscc @isccArgs (Join-Path $PSScriptRoot "SecureWall.iss")
if ($LASTEXITCODE -ne 0) { throw "Échec d'Inno Setup" }
Write-Host "Installateur : $(Join-Path $root 'publish\SecureWall-Setup-2.0.2.exe')" -ForegroundColor Green

if (-not $NoSign) {
    $setup = Join-Path $root 'publish\SecureWall-Setup-2.0.2.exe'
    $sig = Get-AuthenticodeSignature $setup
    Write-Host ("Signature de l'installateur : {0} — {1}" -f $sig.Status, $sig.SignerCertificate.Subject) -ForegroundColor Green
}