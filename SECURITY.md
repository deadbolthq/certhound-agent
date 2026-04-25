# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in CertHound Agent, **please don't open a public GitHub issue.**

Instead, email **security@certhound.dev** with:

- A description of the issue and the impact you observed
- Steps to reproduce (or a proof-of-concept)
- Affected version(s) — `certhound-agent --version` if you have it installed
- Your name + handle if you'd like credit in the disclosure

We aim to acknowledge reports within **2 business days** and provide a remediation plan within **7 days** for confirmed issues.

## Scope

In scope:

- The agent binary itself (this repository)
- The install scripts (`scripts/install.sh`, `scripts/install.ps1`)
- The Windows GUI installer (`cmd/installer/`)
- The auto-update flow (signed-checksum verification)
- API key handling and storage on disk

Out of scope (different repos, different reports):

- The CertHound dashboard at `app.certhound.dev` — please email separately and note "dashboard" in the subject
- Vulnerabilities in third-party dependencies that we ship — we'll triage and forward upstream

## What's covered

The agent runs with elevated privileges on the host (root on Linux, SYSTEM on Windows) so it can read the certificate store and write renewed certs. Vulnerabilities of particular interest:

- **Local privilege escalation** via the agent
- **Remote code execution** via the API endpoint, ingest payloads, or auto-update
- **Authentication bypass** in the ingest API
- **TLS verification bypass** that would let a MITM impersonate the dashboard
- **Path traversal** in cert scanning or renewal output paths
- **Credential leaks** — API keys ending up in logs, stack traces, or transmitted in cleartext

## Hardening already in place

- Auto-update verifies SHA-256 checksums against the release manifest before replacing the binary; mismatches abort and roll back.
- TLS verification is on by default for all outbound calls; `TLSVerify: false` exists for self-hosted ingest with self-signed certs but is documented as a trust-the-network mode.
- API keys never appear in config JSON; resolved from env var or per-platform key file with `0600` (root-only / SYSTEM-only) permissions.
- Agent ID is a per-host UUID stored in `/etc/certhound/agent-id` (Linux) or `C:\ProgramData\CertHound\agent-id` (Windows); not derived from anything sensitive.

## Disclosure

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). After a fix is shipped, we'll publish an advisory on the GitHub Security tab and credit the reporter (unless they ask to remain anonymous).
