# CertHound Agent Installer - Windows
# Requires: PowerShell 5.1+, run as Administrator
# Get your install command (including key and endpoint) from the CertHound dashboard.

param(
    [string]$Key = "",
    [string]$Endpoint = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ReleasesUrl  = "https://github.com/deadbolthq/certhound-agent/releases/latest/download"
$InstallDir   = "C:\Program Files\CertHound"
$BinaryPath   = "$InstallDir\certhound-agent.exe"
$ServiceName  = "CertHoundAgent"
$DisplayName  = "CertHound Agent"

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

if (-not $Key) {
    Write-Error "Error: -Key is required. Get your install command from the CertHound dashboard."
    exit 1
}

if (-not $Endpoint) {
    Write-Error "Error: -Endpoint is required. Get your install command from the CertHound dashboard."
    exit 1
}

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------

Write-Host "==> Installing CertHound agent (windows/amd64)"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$BinaryUrl = "$ReleasesUrl/certhound-agent-windows-amd64.exe"
Write-Host "==> Downloading from $BinaryUrl"
Invoke-WebRequest -Uri $BinaryUrl -OutFile $BinaryPath -UseBasicParsing
Write-Host "==> Binary installed to $BinaryPath"

# ---------------------------------------------------------------------------
# Provision (writes key + config to C:\ProgramData\CertHound\)
# ---------------------------------------------------------------------------

Write-Host "==> Provisioning agent..."
& $BinaryPath --provision --key $Key --endpoint $Endpoint
if ($LASTEXITCODE -ne 0) {
    Write-Error "Provisioning failed."
    exit 1
}

# ---------------------------------------------------------------------------
# Install Windows Service
# ---------------------------------------------------------------------------

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "==> Removing existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "==> Creating Windows service..."
New-Service `
    -Name        $ServiceName `
    -DisplayName $DisplayName `
    -Description "CertHound certificate monitoring agent" `
    -BinaryPathName "$BinaryPath --watch" `
    -StartupType Automatic

Start-Service -Name $ServiceName

Write-Host ""
Write-Host "==> CertHound agent installed and running."
Write-Host "    Check status:  Get-Service $ServiceName"
Write-Host "    View logs:     Get-EventLog -LogName Application -Source $ServiceName -Newest 50"
Write-Host "    Stop agent:    Stop-Service $ServiceName"
