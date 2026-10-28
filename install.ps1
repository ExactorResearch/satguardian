<#
.SYNOPSIS
    SATGuardian Edge WAF - Zero-Dependency Windows Automated Installer
    Installs the standalone precompiled binary, default configuration, and registers as a Windows Service.
    Requires NO external dependencies, NO Rust, and NO compilers on the target machine.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\Satguardian\WAF",
    [string]$ConfigDir = "C:\ProgramData\Satguardian\WAF",
    [switch]$AsService = $true,
    [switch]$StartService = $true,
    [switch]$BuildFromSource = $false,
    [string]$ReleaseVersion = "v0.3.0"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "SATGuardian Edge WAF - Windows Server Installer" -ForegroundColor Cyan
Write-Host "Deterministic SAT Cyber-Defense and Reverse Proxy (100% Free Edge)" -ForegroundColor Cyan
Write-Host "Cloud Boolean Optimization: https://satguardian.tech" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Administrator Privilege Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Administrator rights required to install Windows Service and configure System PATH."
    if ($PSCommandPath) {
        Write-Host "Requesting elevation..." -ForegroundColor Yellow
        try {
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $($MyInvocation.UnboundArguments -join ' ')" -Verb RunAs
            exit 0
        } catch {
            Write-Error "Failed to elevate. Please right-click PowerShell and select 'Run as Administrator'."
            exit 1
        }
    } else {
        Write-Error "Administrator privileges required. Please reopen PowerShell as Administrator."
        exit 1
    }
}

$ScriptDir = ""
if ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $ScriptDir = (Get-Location).Path
}
$BinarySrc = ""

# 2. Locate Bundled Pre-Compiled Binary or Download
Write-Host "`n[1/5] Locating standalone binary..." -ForegroundColor Yellow

if (Test-Path "$ScriptDir\satguardian-waf.exe") {
    $BinarySrc = "$ScriptDir\satguardian-waf.exe"
    Write-Host "Found bundled satguardian-waf binary in package root." -ForegroundColor Green
} elseif (Test-Path "$ScriptDir\exactor-waf-guardian.exe") {
    $BinarySrc = "$ScriptDir\exactor-waf-guardian.exe"
    Write-Host "Found bundled exactor-waf-guardian binary in package root." -ForegroundColor Green
} elseif (Test-Path "$ScriptDir\bin\satguardian-waf.exe") {
    $BinarySrc = "$ScriptDir\bin\satguardian-waf.exe"
    Write-Host "Found bundled binary in bin/ directory." -ForegroundColor Green
} elseif (Test-Path "$ScriptDir\target\release\satguardian-waf.exe") {
    $BinarySrc = "$ScriptDir\target\release\satguardian-waf.exe"
    Write-Host "Found local release target binary." -ForegroundColor Green
} elseif (Test-Path "$ScriptDir\target\release\exactor-waf-guardian.exe") {
    $BinarySrc = "$ScriptDir\target\release\exactor-waf-guardian.exe"
    Write-Host "Found local release target binary." -ForegroundColor Green
} elseif ($BuildFromSource) {
    Write-Host "Building release binary from source via cargo..." -ForegroundColor Yellow
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Push-Location $ScriptDir
        try {
            cargo build --release -p satguardian-waf -j 1
        } finally {
            Pop-Location
        }
        $BinarySrc = "$ScriptDir\target\release\satguardian-waf.exe"
    } else {
        Write-Error "Cargo was not found. Please install Rust or supply the precompiled satguardian-waf.exe."
        exit 1
    }
} else {
    # Zero-install: Download precompiled Windows x86_64 binary
    $DownloadUrl = "https://github.com/ExactorResearch/exactor-waf-guardian/releases/download/$ReleaseVersion/satguardian-waf-x86_64-pc-windows-msvc.exe"
    $TempBin = "$env:TEMP\satguardian-waf.exe"
    Write-Host "Downloading pre-compiled standalone binary from release ($ReleaseVersion)..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempBin -UseBasicParsing
        $BinarySrc = $TempBin
        Write-Host "Downloaded standalone executable successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Online download unavailable: $_"
        Write-Error "No local satguardian-waf.exe found. Place the precompiled binary next to install.ps1 or run with -BuildFromSource."
        exit 1
    }
}

# 3. Stop Existing Service If Running
$ServiceName = "SATGuardianWAF"
$legacyServiceName = "ExactorWAF"

$legacySvc = Get-Service -Name $legacyServiceName -ErrorAction SilentlyContinue
if ($legacySvc) {
    Write-Host "`n[2/5] Stopping and decommissioning legacy ExactorWAF service..." -ForegroundColor Yellow
    Stop-Service -Name $legacyServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $legacyServiceName | Out-Null
}

$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "`n[2/5] Stopping running SATGuardianWAF service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
} else {
    Write-Host "`n[2/5] Preparing fresh service registration." -ForegroundColor Gray
}

# 4. Create Target Directories and Copy Executable
Write-Host "`n[3/5] Deploying binary and directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

$TargetExe = "$InstallDir\satguardian-waf.exe"
$LegacyExe = "$InstallDir\exactor-waf-guardian.exe"
Copy-Item -Path $BinarySrc -Destination $TargetExe -Force
Copy-Item -Path $BinarySrc -Destination $LegacyExe -Force
Write-Host "Executable deployed to: $TargetExe (with legacy alias at $LegacyExe)" -ForegroundColor Green

# 5. Configuration Setup
Write-Host "`n[4/5] Configuring WAF settings..." -ForegroundColor Yellow
$TargetConfig = "$ConfigDir\waf_config.toml"
$WinDbPath = "$ConfigDir\waf_ledger.db" -replace '\\', '\\'

if (-not (Test-Path $TargetConfig)) {
    if (Test-Path "$ScriptDir\waf_config.toml") {
        # Copy template and adapt db path for Windows
        $cfgContent = Get-Content "$ScriptDir\waf_config.toml" -Raw
        $cfgContent = $cfgContent -replace 'database_path\s*=\s*"[^"]*"', "database_path = `"$WinDbPath`""
        Set-Content -Path $TargetConfig -Value $cfgContent -Encoding utf8
    } else {
        # Inline default config
        $defaultConfigLines = @(
            'listen_addr = "0.0.0.0:8080"',
            'upstream_url = "http://127.0.0.1:3000"',
            'mode = "block"',
            'satguardian_api_url = "https://satguardian.tech/api/simplify"',
            "database_path = `"$WinDbPath`"",
            'autonomous_sync_interval_secs = 300',
            'auto_sync_enabled = true'
        )
        $defaultConfig = $defaultConfigLines -join "`r`n"
        Set-Content -Path $TargetConfig -Value $defaultConfig -Encoding utf8
    }
    Write-Host "Created production configuration at: $TargetConfig" -ForegroundColor Green
} else {
    Write-Host "Existing configuration preserved: $TargetConfig" -ForegroundColor Gray
}

# 6. Add to System PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$InstallDir", [EnvironmentVariableTarget]::Machine)
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "Added $InstallDir to System PATH." -ForegroundColor Green
}

# 7. Service Installation or Interactive Launcher
Write-Host "`n[5/5] Service and Launch Registration..." -ForegroundColor Yellow
if ($AsService) {
    $BinPathWithArgs = "`"$TargetExe`" proxy --config `"$TargetConfig`""
    if (-not $existingSvc) {
        & sc.exe create $ServiceName binPath= $BinPathWithArgs start= auto DisplayName= "SATGuardian Edge WAF" | Out-Null
        & sc.exe description $ServiceName "Deterministic SAT Cyber-Defense WAF and Reverse Proxy powered by satguardian.tech" | Out-Null
        Write-Host "Registered Windows Service '$ServiceName' (auto-start)." -ForegroundColor Green
    } else {
        & sc.exe config $ServiceName binPath= $BinPathWithArgs | Out-Null
        Write-Host "Updated existing Windows Service '$ServiceName'." -ForegroundColor Green
    }

    if ($StartService) {
        Start-Service -Name $ServiceName
        Start-Sleep -Milliseconds 800
        $svcStatus = (Get-Service -Name $ServiceName).Status
        if ($svcStatus -eq 'Running') {
            Write-Host "Service '$ServiceName' is RUNNING and protecting the server!" -ForegroundColor Green
        } else {
            Write-Host "Service status: $svcStatus. Check Event Viewer if issues arise." -ForegroundColor Yellow
        }
    }
}

# Create a convenient run-interactive.bat in the install folder
$BatLines = @(
    '@echo off',
    'title SATGuardian Edge WAF - Interactive Console',
    'echo Starting SATGuardian Edge WAF...',
    "`"$TargetExe`" proxy --config `"$TargetConfig`"",
    'pause'
)
$BatContent = $BatLines -join "`r`n"
Set-Content -Path "$InstallDir\run-interactive.bat" -Value $BatContent -Encoding ascii

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "SATGuardian Edge WAF successfully installed!" -ForegroundColor Green
Write-Host "   Executable    : $TargetExe" -ForegroundColor Cyan
Write-Host "   Configuration : $TargetConfig" -ForegroundColor Cyan
Write-Host "   Service       : $ServiceName (Automatic)" -ForegroundColor Cyan
Write-Host "   Entitlement   : satguardian-waf entitlement" -ForegroundColor Cyan
Write-Host "   Quick Test    : satguardian-waf inspect --query `"id=1' OR 1=1--`"" -ForegroundColor Cyan
Write-Host "   Benchmark     : satguardian-waf benchmark" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Green
