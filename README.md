CertHound

CertHound is a cross-platform utility for scanning X.509 certificates on the filesystem and (on Windows) the current user's certificate store. It outputs a JSON-friendly representation of certificates, including details such as subject, issuer, expiration dates, DNS names, IP addresses, and key paths. Certificates nearing expiration are flagged automatically.

---

Features

- Scans directories for PEM/CRT certificates on Linux, macOS, and Windows.
- Optionally scans the Windows "MY" certificate store.
- Filters out self-signed root CA certificates.
- Flags certificates that expire within 30 days.
- Outputs JSON for easy integration with other tools or dashboards.
- Cross-platform support with stub implementations for non-Windows systems.

---

Installation

Prerequisites:

- Go 1.21+ installed on your system.
- Git (for cloning the repository).

Clone the repository:

git clone https://github.com/deadbolthq/certhound-agent.git
cd certhound-agent

---

Usage

Run the agent:

go run ./cmd/agent

By default, it scans /etc/ssl/certs on Linux/macOS.

Override the certificate directory:

go run ./cmd/agent /path/to/certs

Output:

The agent prints JSON with the following structure for each certificate:

{
  "subject": "CN=example.com, O=Example Corp",
  "issuer": "CN=Example CA, O=Certificate Authority",
  "not_before": "2025-08-01T00:00:00Z",
  "not_after": "2026-08-01T00:00:00Z",
  "dns_names": ["example.com", "www.example.com"],
  "ip_addresses": ["192.168.1.1"],
  "cert_path": "/etc/ssl/certs/example.crt",
  "key_path": "/etc/ssl/private/example.key",
  "expiring_soon": false
}

---

Cross-Platform Notes

- On Windows, the agent scans both the filesystem and the current user's "MY" certificate store.
- On non-Windows platforms, the Windows certificate store scan is stubbed and returns no results.

---

Contributing

Contributions, bug reports, and feature requests are welcome. Please fork the repository and submit a pull request.

---

Attribution

Some portions of this project were assisted by large language models (LLMs), including:

- ChatGPT: https://chat.openai.com/
- GitHub Copilot: https://github.com/features/copilot
- Claude Code: https://claude.ai/code

These tools helped generate boilerplate code, documentation, and comments.

---

License

This project is licensed under for personal use only. See the LICENSE file for details.
