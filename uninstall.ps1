<#
.SYNOPSIS
    SATGuardian Edge WAF - Windows Server Automated Uninstaller
    Stops and removes the Windows Service, deletes installed binaries, and cleans PATH.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\SATGuardian\WAF",
    [string]$ConfigDir = "C:\ProgramData\SATGuardian\WAF",
    [switch]$PurgeData = $false
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Red
Write-Host "Uninstalling SATGuardian Edge WAF from Windows" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red

# Elevation check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Administrator rights required to uninstall Windows Service."
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 0
}

# 1. Stop and Delete Windows Service
foreach ($ServiceName in @("SATGuardianWAF", "ExactorWAF")) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "Stopping service '$ServiceName'..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Write-Host "Removing service '$ServiceName'..." -ForegroundColor Yellow
        & sc.exe delete $ServiceName | Out-Null
        Write-Host "Removed Windows Service: $ServiceName." -ForegroundColor Green
    }
}

# 2. Remove from PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
foreach ($dir in @($InstallDir, "C:\Program Files\Exactor\WAF")) {
    if ($CurrentPath -like "*$dir*") {
        $NewPath = ($CurrentPath.Split(';') | Where-Object { $_ -ne $dir -and $_ -ne "" }) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::Machine)
        Write-Host "Removed $dir from System PATH." -ForegroundColor Green
    }
}

# 3. Remove Program Files
foreach ($dir in @($InstallDir, "C:\Program Files\Exactor\WAF")) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        Write-Host "Removed installation directory: $dir" -ForegroundColor Green
    }
}

# 4. Config & Data Directory
if ($PurgeData) {
    foreach ($cfg in @($ConfigDir, "C:\ProgramData\Exactor\WAF")) {
        if (Test-Path $cfg) {
            Remove-Item -Recurse -Force $cfg -ErrorAction SilentlyContinue
            Write-Host "Purged configuration and database: $cfg" -ForegroundColor Green
        }
    }
} else {
    Write-Host "Configuration and ledger database preserved at: $ConfigDir" -ForegroundColor Cyan
    Write-Host "(To remove completely, delete $ConfigDir manually or run with -PurgeData)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "SATGuardian Edge WAF uninstallation complete." -ForegroundColor Green
