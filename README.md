# CertHound Agent

A cross-platform Go agent that scans X.509 certificates from the filesystem and Windows certificate stores, then reports their status to the CertHound API. Designed for continuous monitoring with configurable scan intervals, heartbeat check-ins, and file-change detection.

## Features

- Scans directories for PEM/CRT certificates on Linux, macOS, and Windows
- Enumerates Windows certificate stores (Current User and Local Machine: MY, ROOT, CA, TrustedPeople, TrustedPublisher)
- Flags certificates that are expired or expiring within a configurable threshold
- Sends structured JSON payloads to a remote API endpoint with retry logic
- **Watch mode**: continuous operation with daily scans, hourly heartbeats, and file-change triggered scans via fsnotify
- Computes SHA-256 fingerprints, extracts SANs, key usage, OCSP/CRL URLs, and more

## Quick Start

**Prerequisites:** Go 1.25+

```bash
git clone https://github.com/deadbolthq/certhound-agent.git
cd certhound-agent
go build -o certhound-agent ./cmd/agent
```

## Usage

```bash
# One-shot scan (prints to log, no endpoint)
certhound-agent

# Scan specific directories
certhound-agent /etc/letsencrypt/live /etc/ssl/certs

# Send results to CertHound API
certhound-agent --endpoint https://api.certhound.dev/v1/ingest

# Continuous mode: heartbeat hourly, full scan daily, immediate scan on cert file changes
certhound-agent --endpoint https://api.certhound.dev/v1/ingest --watch

# Custom config file
certhound-agent --config /etc/certhound/config.json --watch

# Override expiry threshold
certhound-agent --threshold 14
```

## Configuration

The agent loads configuration from (in priority order):

1. `--config` flag
2. Auto-discovered file: `/etc/certhound/config.json`, `C:\ProgramData\CertHound\config.json`, `configs/config.json`, or `config.json`
3. Built-in defaults

CLI flags (`--endpoint`, `--threshold`) override config file values.

Example `config.json`:

```json
{
  "ScanPaths": ["/etc/ssl/certs", "/etc/letsencrypt/live"],
  "ScanPathsWindows": ["C:\\ProgramData\\ssl\\certs"],
  "ScanIntervalSeconds": 86400,
  "HeartbeatIntervalSeconds": 3600,
  "ExpiringThresholdDays": 30,
  "AWSEndpoint": "https://api.certhound.dev/v1/ingest",
  "APIKey": "",
  "TLSVerify": true,
  "MaxRetries": 3,
  "PayloadVersion": "1.0",
  "OrgID": ""
}
```

**Note:** Do not commit config files containing API keys. The default `.gitignore` protects `config.json` in the repo root; `configs/config.json` is tracked as a development example only.

## Watch Mode

When running with `--watch`, the agent operates in three modes simultaneously:

| Mode | Interval | What it does |
|------|----------|-------------|
| **Heartbeat** | Hourly (configurable) | Lightweight check-in with no cert data |
| **Full scan** | Daily (configurable) | Complete certificate inventory |
| **File watcher** | On change | Immediate scan when cert files are created, modified, or deleted |

## Payload Types

The agent sends two types of payloads:

**Scan payload** (`payload_type: "scan"`) — full certificate inventory with host metadata, scan duration, and all certificate details.

**Heartbeat payload** (`payload_type: "heartbeat"`) — lightweight check-in with agent identity, host info, and config hash. No certificate data.

Both include a unique `payload_id` (UUID), `agent_id`, `config_hash`, and `org_id` for backend routing.

## Building

```bash
make build              # Build for current platform
make build-all          # Cross-compile for Linux (amd64/arm64) and Windows (amd64)
make test               # Run all tests
```

Version is injected at build time:

```bash
go build -ldflags "-X main.version=1.0.0" -o certhound-agent ./cmd/agent
```

## License

Copyright 2025 DeadboltHQ. Licensed under the [Apache License 2.0](LICENSE).
