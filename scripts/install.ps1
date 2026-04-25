# CertHound Agent Installer - Windows
# Requires: PowerShell 5.1+, run as Administrator
#
# Managed install (posts to CertHound dashboard):
#   iwr https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.ps1 -OutFile install.ps1 -UseBasicParsing
#   .\install.ps1 -Key ch_xxx -Endpoint https://api.certhound.dev/ingest
#
# Standalone install (local scan only, no dashboard):
#   iwr https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.ps1 -OutFile install.ps1 -UseBasicParsing
#   .\install.ps1

param(
    [string]$Key = "",
    [string]$Endpoint = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Ensure TLS 1.2 — fresh Windows Server defaults to older protocols
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ReleasesUrl  = "https://github.com/deadbolthq/certhound-agent/releases/latest/download"
$InstallDir   = "C:\Program Files\CertHound"
$BinaryPath   = "$InstallDir\certhound-agent.exe"
$ServiceName  = "CertHoundAgent"
$DisplayName  = "CertHound Agent"
$BinaryName   = "certhound-agent-windows-amd64.exe"

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

if (($Key -and -not $Endpoint) -or (-not $Key -and $Endpoint)) {
    Write-Error "Error: -Key and -Endpoint must be provided together. For standalone mode, omit both."
    exit 1
}

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if (-not $Key) {
    Write-Host "==> Standalone mode: agent will scan locally and not report to any endpoint."
    Write-Host "    To connect to the CertHound dashboard, re-run with -Key and -Endpoint."
}

# ---------------------------------------------------------------------------
# Download binary + checksums and verify before installing
# ---------------------------------------------------------------------------

Write-Host "==> Installing CertHound agent (windows/amd64)"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$BinaryUrl   = "$ReleasesUrl/$BinaryName"
$ChecksumUrl = "$ReleasesUrl/checksums.txt"
$TmpBinary   = [System.IO.Path]::GetTempFileName() + ".exe"
$TmpChecksums = [System.IO.Path]::GetTempFileName()

try {
    Write-Host "==> Downloading binary from $BinaryUrl"
    Invoke-WebRequest -Uri $BinaryUrl -OutFile $TmpBinary -UseBasicParsing

    Write-Host "==> Downloading checksums from $ChecksumUrl"
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $TmpChecksums -UseBasicParsing

    Write-Host "==> Verifying SHA-256 checksum..."
    $checksumLines = Get-Content $TmpChecksums
    $expectedLine  = $checksumLines | Where-Object { $_ -match "\b$([regex]::Escape($BinaryName))$" }
    if (-not $expectedLine) {
        Write-Error "No checksum entry found for '$BinaryName' in checksums.txt"
        exit 1
    }
    $expectedHash = ($expectedLine -split '\s+')[0].ToLower()

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($TmpBinary)
    try {
        $hashBytes = $sha256.ComputeHash($stream)
    } finally {
        $stream.Close()
        $sha256.Dispose()
    }
    $actualHash = [BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()

    if ($expectedHash -ne $actualHash) {
        Write-Error "Checksum mismatch!`n  Expected: $expectedHash`n  Got:      $actualHash"
        exit 1
    }
    Write-Host "==> Checksum verified OK ($actualHash)"

    # Stop and remove existing service before replacing the binary — the running
    # service holds a file lock on the exe and Copy-Item will fail if it's up.
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "==> Stopping existing service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Exclude the install directory from Windows Defender before copying —
    # Go binaries that do network I/O and self-update often trigger false positives.
    Write-Host "==> Adding Windows Defender exclusion for $InstallDir..."
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue

    # Install binary
    Copy-Item -Path $TmpBinary -Destination $BinaryPath -Force
    Write-Host "==> Binary installed to $BinaryPath"

} finally {
    Remove-Item -Path $TmpBinary   -ErrorAction SilentlyContinue
    Remove-Item -Path $TmpChecksums -ErrorAction SilentlyContinue
}

# Add install directory to system PATH if not already present
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    Write-Host "==> Adding $InstallDir to system PATH"
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    $env:Path = "$env:Path;$InstallDir"
}

# ---------------------------------------------------------------------------
# Provision (writes key + config) — only in managed mode
# ---------------------------------------------------------------------------

if ($Key) {
    Write-Host "==> Provisioning agent..."
    & $BinaryPath --provision --key $Key --endpoint $Endpoint
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Provisioning failed."
        exit 1
    }
} else {
    Write-Host "==> Skipping provisioning (standalone mode)."
}

# ---------------------------------------------------------------------------
# Install Windows Service
# ---------------------------------------------------------------------------

Write-Host "==> Creating Windows service..."
New-Service `
    -Name        $ServiceName `
    -DisplayName $DisplayName `
    -Description "CertHound certificate monitoring agent" `
    -BinaryPathName "$BinaryPath --watch" `
    -StartupType Automatic | Out-Null

Write-Host "==> Starting service..."
Start-Service -Name $ServiceName

$svc = Get-Service -Name $ServiceName
Write-Host ""
Write-Host "==> CertHound agent installed and running. (Status: $($svc.Status))"
Write-Host "    Check status:  Get-Service $ServiceName"
Write-Host "    View logs:     Get-Content 'C:\ProgramData\CertHound\logs\*.log' -Tail 20"
Write-Host "    Stop agent:    Stop-Service $ServiceName"
if (-not $Key) {
    Write-Host ""
    Write-Host "    Running in standalone mode. To connect to the dashboard later:"
    Write-Host "    certhound-agent --provision --key ch_xxx --endpoint https://api.certhound.dev/ingest"
    Write-Host "    Restart-Service $ServiceName"
}
