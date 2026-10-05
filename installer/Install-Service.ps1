<#
.SYNOPSIS
    Installe ou désinstalle manuellement le service privilégié SecureWall (hors installateur). Exécuter en administrateur.
.EXAMPLE
    .\Install-Service.ps1 -Path "C:\Program Files\SecureWall"
    .\Install-Service.ps1 -Uninstall
#>
param(
    [string]$Path = (Split-Path -Parent $PSScriptRoot),
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$name = "SecureWallPrivilegedService"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit être exécuté dans une fenêtre PowerShell lancée en tant qu'administrateur."
}

if ($Uninstall) {
    if (Get-Service $name -ErrorAction SilentlyContinue) {
        Stop-Service $name -ErrorAction SilentlyContinue
        sc.exe delete $name | Out-Null
        Write-Host "Service $name supprimé." -ForegroundColor Green
    } else { Write-Host "Le service $name n'est pas installé." }
    exit 0
}

$exe = Join-Path $Path "SecureWall.PrivilegedService.exe"
if (-not (Test-Path $exe)) { throw "Introuvable : $exe" }
# Le service n'est accepté par l'application que s'il est situé à côté de SecureWall.exe.
if (-not (Test-Path (Join-Path $Path "SecureWall.exe"))) { throw "SecureWall.exe doit se trouver dans le même dossier que le service." }

if (Get-Service $name -ErrorAction SilentlyContinue) { throw "Le service $name existe déjà (utilisez -Uninstall d'abord)." }
sc.exe create $name binPath= "`"$exe`"" start= auto DisplayName= "SecureWall - Service privilégié" | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/30000// | Out-Null
Start-Service $name
Write-Host "Service $name installé et démarré." -ForegroundColor Green
