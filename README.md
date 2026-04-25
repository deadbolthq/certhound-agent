# CertHound Agent

**SSL/TLS certificate inventory and auto-renewal for your servers.**

A small, single-binary Go agent that finds every certificate on a host — on disk and inside the Windows certificate store — reports their status, and (optionally) renews them via Let's Encrypt before they expire. Cross-platform, no runtime dependencies, no daemon to install besides the agent itself.

Use it standalone for local cert scanning, or pair it with the [CertHound dashboard](https://app.certhound.dev) for centralized monitoring across your fleet.

```
                                 ┌──────────────────────┐
        Filesystem ──────┐       │                      │
                         │       │   CertHound Agent    │
        Windows Store ───┼──────►│   (this repo)        │──── HTTPS ───┐
                         │       │                      │              │
        Live endpoints ──┘       └──────────────────────┘              │
                                            │                          ▼
                                            │              ┌──────────────────────┐
                                            └─ ACME ──────►│  Let's Encrypt       │
                                                           └──────────────────────┘
                                                                       │
                                                           ┌──────────────────────┐
                                                           │  CertHound Dashboard │
                                                           │  app.certhound.dev   │
                                                           │  (optional, managed) │
                                                           └──────────────────────┘
```

## Features

- **Cross-platform** — Linux (amd64/arm64), macOS, Windows (amd64). Single static binary.
- **Filesystem scanning** — recursively walks configured directories for PEM/CRT/DER certificates.
- **Windows certificate store** — enumerates Current User and Local Machine stores (MY, ROOT, CA, TrustedPeople, TrustedPublisher).
- **ACME auto-renewal** — issues and renews Let's Encrypt certificates via HTTP-01 webroot challenge.
- **Windows cert-store import** — renewed certs can be imported directly into `LocalMachine\MY` or `CurrentUser\MY` via CryptoAPI; no PEM-on-disk required.
- **Watch mode** — daily full scans, hourly heartbeats, and immediate scans triggered by `fsnotify` cert-file changes.
- **Auto-update** — agent self-updates from GitHub Releases with SHA-256 checksum verification and automatic rollback on failure.
- **Detailed extraction** — SHA-256 fingerprints, SANs (DNS, IP, URI, email), key/extended key usage, OCSP/CRL/AIA URLs, signature algorithm, key bits, NotBefore/NotAfter.

## Install

### Linux / macOS

```bash
curl -sSL https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.sh | \
  sudo bash -s -- --key ch_yourkey --endpoint https://api.certhound.dev/ingest
```

For standalone (local-only, no dashboard) install, omit `--key` and `--endpoint`:

```bash
curl -sSL https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.sh | sudo bash
```

### Windows

The recommended path is the [GUI installer](https://github.com/deadbolthq/certhound-agent/releases/latest/download/certhound-installer-windows-amd64.exe) — download, run as Administrator, paste your key.

For PowerShell (run as Administrator):

```powershell
iwr https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.ps1 -OutFile install.ps1 -UseBasicParsing
.\install.ps1 -Key "ch_yourkey" -Endpoint "https://api.certhound.dev/ingest"
```

For standalone (no dashboard), drop the `-Key` and `-Endpoint` arguments.

### From source

```bash
git clone https://github.com/deadbolthq/certhound-agent.git
cd certhound-agent
go build -o certhound-agent ./cmd/agent
```

## Usage

```bash
# One-shot scan, table output to console
certhound-agent

# Scan specific directories
certhound-agent /etc/letsencrypt/live /etc/ssl/certs

# JSON to stdout (for piping into jq, etc.)
certhound-agent --json /etc/ssl/certs

# Continuous watch mode reporting to a dashboard
certhound-agent --watch --endpoint https://api.certhound.dev/ingest

# Custom config file
certhound-agent --config /etc/certhound/config.json --watch

# Override expiry threshold to flag certs within 14 days of expiry
certhound-agent --threshold 14
```

## Configuration

The agent loads config from (in priority order):

1. `--config` flag
2. Auto-discovered file at `/etc/certhound/config.json` (Linux/macOS) or `C:\ProgramData\CertHound\config.json` (Windows)
3. Built-in defaults

CLI flags (`--endpoint`, `--threshold`) override config file values.

### Example: scan-only

```json
{
  "ScanPaths": ["/etc/letsencrypt/live", "/etc/ssl/certs"],
  "ScanIntervalSeconds": 86400,
  "HeartbeatIntervalSeconds": 3600,
  "ExpiringThresholdDays": 30,
  "AWSEndpoint": "https://api.certhound.dev/ingest",
  "TLSVerify": true,
  "AutoUpdate": true
}
```

### Example: with ACME auto-renewal (Linux, file output)

```json
{
  "ScanPaths": ["/etc/letsencrypt/live"],
  "AWSEndpoint": "https://api.certhound.dev/ingest",
  "Renewal": {
    "Enabled": true,
    "ACMEEmail": "you@example.com",
    "ACMEDirectoryURL": "https://acme-v02.api.letsencrypt.org/directory",
    "ChallengeType": "http-01",
    "RenewalThresholdDays": 30,
    "AccountKeyPath": "/etc/certhound/acme-account.key",
    "Certs": [
      {
        "Domains": ["example.com", "www.example.com"],
        "WebrootPath": "/var/www/html",
        "CertOutputPath": "/etc/ssl/certs/example.com.crt",
        "KeyOutputPath": "/etc/ssl/private/example.com.key",
        "PostRenewalCommand": "systemctl reload nginx"
      }
    ]
  }
}
```

### Example: with ACME auto-renewal (Windows, cert-store import)

```json
{
  "ScanPathsWindows": ["C:\\ProgramData\\CertHound\\certs"],
  "AWSEndpoint": "https://api.certhound.dev/ingest",
  "Renewal": {
    "Enabled": true,
    "ACMEEmail": "you@example.com",
    "ACMEDirectoryURL": "https://acme-v02.api.letsencrypt.org/directory",
    "ChallengeType": "http-01",
    "RenewalThresholdDays": 30,
    "AccountKeyPath": "C:\\ProgramData\\CertHound\\acme-account.key",
    "Certs": [
      {
        "Domains": ["example.com"],
        "WebrootPath": "C:\\inetpub\\wwwroot",
        "WindowsCertStore": "LocalMachine\\MY"
      }
    ]
  }
}
```

> **Windows + IIS gotcha:** IIS won't serve extensionless files by default, which breaks the ACME HTTP-01 challenge response. Drop a `web.config` in `C:\inetpub\wwwroot\.well-known\acme-challenge\` mapping `.` (no extension) to `text/plain`. See [docs/windows-iis-acme.md](docs/windows-iis-acme.md) for the exact config.

`Certs` entries can set `CertOutputPath`+`KeyOutputPath` (file output), `WindowsCertStore` (store import), or both. At least one is required.

API keys are never read from the config JSON. They're resolved from:

1. `CERTHOUND_API_KEY` environment variable
2. `--api-key-file` flag
3. Platform-specific default key file:
   - Linux/macOS: `/etc/certhound/api.key`
   - Windows: `C:\ProgramData\CertHound\api.key`

## Watch mode

When running with `--watch`, the agent does three things on overlapping schedules:

| Mode | Default interval | Action |
|------|------------------|--------|
| Heartbeat | Hourly | Lightweight check-in (no cert data) |
| Full scan | Daily | Complete certificate inventory + auto-renewal of due certs |
| File watcher | On change | Immediate scan when cert files are created, modified, or deleted |

## Service installation

The Windows installer registers a `CertHoundAgent` service automatically. On Linux, the install script writes a systemd unit:

```bash
systemctl status certhound-agent
journalctl -u certhound-agent -f
```

## Auto-update

Agent checks GitHub Releases on startup and every 24 hours. Updates are:

- **Verified** — SHA-256 checksums fetched from the release; mismatched binaries are refused.
- **Backed up** — current binary saved as `.bak` before replacement; rolled back on validation failure.
- **Privileged** — only runs when the agent has root (Linux) or Administrator (Windows).

Disable with `"AutoUpdate": false`.

## How does this compare to ...

- **Certbot / acme.sh / lego** — those are renewal-only CLI tools. CertHound Agent does renewal *plus* host-wide cert inventory, *plus* (optionally) reports to a dashboard so you see all your servers in one place. If you only need renewal on one server, certbot is fine; CertHound is for the next step.
- **cert-manager** — Kubernetes-native, won't help you on a bare Windows Server or a non-K8s Linux box. CertHound is the fleet equivalent for traditional infrastructure.
- **win-acme** — Windows-only, GUI-driven. CertHound covers the same Windows territory (HTTP-01 + cert-store import) plus Linux/macOS plus a central dashboard.

## Development

```bash
make build          # Build for current platform
make build-all      # Cross-compile linux/{amd64,arm64} + windows/amd64
make test           # Run tests

# Inject version at build time
go build -ldflags "-X main.version=v1.2.3" -o certhound-agent ./cmd/agent
```

## Project layout

```
cmd/agent/          # main entrypoint + Windows service handler
cmd/installer/      # Native Windows GUI installer
internal/config/    # JSON config + API key resolution
internal/scanner/   # Cert scanning (filesystem + Windows store)
internal/renewal/   # ACME client + Windows cert-store import
internal/payload/   # API payload construction
internal/sender/    # HTTP client with retry + auth
internal/updater/   # Self-update with checksum verification
internal/identity/  # Persistent agent UUID
scripts/            # install.sh / install.ps1
.github/workflows/  # CI + release pipelines
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Contributing

Bug reports and PRs welcome — please see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for the security disclosure process.

The dashboard backend (`certhound-backend`) and frontend (`certhound-frontend`) are not currently open source. If that's a dealbreaker for you, the agent works fine standalone — point it at your own ingest endpoint or skip the endpoint entirely for local-only scanning.
