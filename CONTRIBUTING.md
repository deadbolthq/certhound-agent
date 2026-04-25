# Contributing

Thanks for your interest in contributing. Issues and PRs are both welcome.

## Reporting a bug

Open a [GitHub issue](https://github.com/deadbolthq/certhound-agent/issues/new) with:

- What you expected vs. what happened
- Steps to reproduce — the smallest config + command that triggers it
- Agent version (`certhound-agent --version` or check the log)
- OS + version (`uname -a` on Linux/macOS, `[System.Environment]::OSVersion` on Windows)
- Relevant log output from `/var/log/certhound/` (Linux) or `C:\ProgramData\CertHound\logs\` (Windows)

For security issues, see [SECURITY.md](SECURITY.md) — please don't open a public issue.

## Submitting a PR

1. Fork the repo and create a feature branch.
2. Make your change. Add or update tests if you're touching `internal/` package code.
3. Run `make test` and `go vet ./...` before pushing.
4. Open a PR with a description of *why* the change matters, not just *what* it does.

We don't have a strict commit-message convention, but conventional one-liners (`feat:`, `fix:`, `docs:`) help. Squash-on-merge is the default — feel free to make WIP commits during development.

## Building and testing

```bash
make build              # Current platform
make build-all          # Cross-compile linux/{amd64,arm64} + windows/amd64
make test               # All tests
go vet ./...            # Static analysis
```

The Windows-specific code lives behind `//go:build windows` tags in `internal/scanner/scan_win.go` and `internal/renewal/store_windows.go`. Cross-build with `GOOS=windows GOARCH=amd64 go build ./...` to validate before pushing — CI will catch breakage but local catches it faster.

## Code style

Run `gofmt -w .` (or let your editor do it) before committing. We don't have a more opinionated linter beyond `go vet` right now.

For comments: explain *why* something is non-obvious, not *what* a name already conveys. We don't enforce a docstring style.

## Areas we'd love help with

If you're looking for a place to start, the [polish backlog](https://github.com/deadbolthq/certhound-agent/issues?q=is%3Aissue+is%3Aopen+label%3Apolish) issues are good first contributions:

- Auto-drop the IIS extensionless-MIME `web.config` on Windows so HTTP-01 just works out of the box
- DNS-01 challenge support (currently HTTP-01 only)
- macOS Keychain enumeration in the scanner (currently filesystem-only on macOS)
- Better log output on Windows (em-dash mojibake under default OEM codepage)
- Internationalized cert-store names on non-English Windows installs

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same license as the project.
