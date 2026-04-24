package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/identity"
	"github.com/deadbolthq/certhound-agent/internal/logger"
	"github.com/deadbolthq/certhound-agent/internal/payload"
	"github.com/deadbolthq/certhound-agent/internal/renewal"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
	"github.com/deadbolthq/certhound-agent/internal/sender"
	"github.com/deadbolthq/certhound-agent/internal/updater"
	"github.com/fsnotify/fsnotify"
)

// heartbeatResponse is what the backend returns in the body of a successful
// heartbeat POST. PendingRenewals is a list of primary domains the dashboard
// has asked the agent to renew now — e.g. the user clicked "Renew Now".
type heartbeatResponse struct {
	PendingRenewals []string `json:"pending_renewals"`
}

// version is injected at build time via: -ldflags "-X main.version=v1.2.3"
// The tag includes the "v" prefix, so format strings should use %s not v%s.
var version = "dev"

func main() {
	var (
		configPath = flag.String("config", "", "Path to config file (optional; flags take precedence)")
		endpoint   = flag.String("endpoint", "", "CertHound API endpoint to POST results to")
		apiKeyFile = flag.String("api-key-file", "", "Path to file containing the API key")
		watchMode  = flag.Bool("watch", false, "Run continuously on the configured scan interval")
		jsonOutput = flag.Bool("json", false, "Print scan results as JSON to stdout")
		threshold  = flag.Int("threshold", 0, "Days before expiry to flag as expiring (overrides config)")
		provision  = flag.Bool("provision", false, "Write API key and config to disk, then exit. Requires --key and --endpoint.")
		key        = flag.String("key", "", "API key to write during --provision (not used at runtime)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CertHound Agent %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Scans for X.509 certificates on this host and reports their status.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  certhound-agent [flags] [path ...]\n\n")
		fmt.Fprintf(os.Stderr, "Note: all flags must appear before path arguments.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --endpoint https://api.certhound.dev/ingest --watch\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --watch --threshold 30\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --json /etc/ssl/certs\n")
	}
	flag.Parse()
	extraPaths := flag.Args()

	// Go's flag package stops parsing at the first non-flag argument, so flags
	// placed after a path silently become scan paths. Catch this early.
	for _, arg := range extraPaths {
		if strings.HasPrefix(arg, "-") {
			fmt.Fprintf(os.Stderr, "Error: %q looks like a flag but was found after a path argument.\n", arg)
			fmt.Fprintf(os.Stderr, "All flags must come before path arguments.\n")
			fmt.Fprintf(os.Stderr, "Example: certhound-agent --watch --endpoint <url> /path/to/certs\n")
			os.Exit(1)
		}
	}

	// --provision: write key + config to disk, then exit.
	// The install script calls this once after placing the binary.
	if *provision {
		if *key == "" || *endpoint == "" {
			fmt.Fprintln(os.Stderr, "Error: --provision requires both --key and --endpoint")
			fmt.Fprintln(os.Stderr, "Example: certhound-agent --provision --key ch_xxx --endpoint https://api.example.com/ingest")
			os.Exit(1)
		}
		fmt.Printf("Provisioning CertHound agent %s...\n", version)
		if err := config.Provision(*key, *endpoint); err != nil {
			fmt.Fprintf(os.Stderr, "Provisioning failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Done. Start the agent with: certhound-agent --watch")
		os.Exit(0)
	}

	// Load config: --config flag > auto-discovered file > built-in defaults
	// Any config-load outcome is stashed here and surfaced after the logger is
	// initialized — previously a failed auto-discovery would silently fall
	// through to defaults, making it impossible to see why a user-edited
	// config was being ignored.
	cfg := config.DefaultConfig()
	var configLoadedFrom string
	var configLoadErrorPath string
	var configLoadError error
	if *configPath != "" {
		loaded, err := config.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config %q: %v\n", *configPath, err)
			os.Exit(1)
		}
		cfg = loaded
		configLoadedFrom = *configPath
	} else {
		candidates := []string{
			"/etc/certhound/config.json",
			`C:\ProgramData\CertHound\config.json`,
			"configs/config.json",
			"config.json",
		}
		for _, try := range candidates {
			if _, err := os.Stat(try); err != nil {
				continue
			}
			loaded, err := config.LoadConfig(try)
			if err != nil {
				// A file is present but unreadable/invalid — remember it so
				// we can warn the user instead of silently using defaults.
				configLoadErrorPath = try
				configLoadError = err
				continue
			}
			cfg = loaded
			configLoadedFrom = try
			break
		}
	}

	// Flags override config
	if *endpoint != "" {
		cfg.AWSEndpoint = *endpoint
	}
	if *threshold > 0 {
		cfg.ExpiringThresholdDays = *threshold
	}
	if len(extraPaths) > 0 {
		cfg.ScanPaths = extraPaths
		cfg.ScanPathsWindows = extraPaths
	}

	agentID := identity.GetOrCreate()

	log := logger.NewLogger(cfg.LogPath, cfg.LogLevel, cfg.Verbose)
	log.Infof("CertHound agent %s starting on %s/%s (id: %s)", version, runtime.GOOS, runtime.GOARCH, agentID)
	defer log.Close()

	// Surface config-load outcome now that the logger exists. A rejected
	// auto-discovered config used to fall through to defaults silently,
	// which made it impossible to tell why a user's edits weren't taking
	// effect — the operator would see an agent that "started fine" but
	// scanned the wrong paths and never ran renewal.
	if configLoadError != nil {
		log.Errorf("Config file at %s could not be loaded and was ignored: %v", configLoadErrorPath, configLoadError)
		log.Errorf("Falling back to built-in defaults. Fix the config file and restart.")
	}
	if configLoadedFrom != "" {
		log.Infof("Config loaded from: %s", configLoadedFrom)
	} else {
		log.Infof("No config file found — using built-in defaults")
	}

	// Sender is only needed when an endpoint is configured
	var senderClient *sender.Sender
	if cfg.AWSEndpoint != "" {
		apiKey, err := config.ResolveAPIKey(*apiKeyFile)
		if err != nil {
			log.Errorf("Endpoint configured but no API key available.")
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			os.Exit(1)
		}
		cfg.APIKey = apiKey
		senderClient = sender.NewSender(cfg.AWSEndpoint, cfg.APIKey, cfg.TLSVerify, cfg.MaxRetries)
		log.Infof("Sender initialized for endpoint: %s", cfg.AWSEndpoint)
	}

	// Renewal client is only initialized when opted in via config.
	// Failing to init is not fatal — the agent still scans and reports;
	// the dashboard will just show renewal as unavailable on this host.
	var renewalClient *renewal.Client
	if cfg.Renewal.Enabled {
		rc, err := renewal.NewClient(cfg.Renewal)
		if err != nil {
			log.Errorf("Renewal enabled in config but client failed to initialize: %v", err)
		} else {
			renewalClient = rc
			log.Infof("ACME renewal client ready (account: %s, directory: %s)", cfg.Renewal.ACMEEmail, cfg.Renewal.ACMEDirectoryURL)
		}
	}

	// watchLoop runs the continuous scan/heartbeat loop until ctx is cancelled.
	// Extracted so it can be called from either CLI mode or the Windows service handler.
	watchLoop := func(ctx context.Context) {
		changeTrigger := make(chan struct{}, 1)
		startFileWatcher(ctx, cfg, log, changeTrigger)

		runScan(ctx, cfg, log, senderClient, renewalClient, agentID, *jsonOutput)

		// Check for updates on startup
		if cfg.AutoUpdate {
			checkForUpdate(ctx, cfg, log)
		}

		heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval())
		scanTicker := time.NewTicker(cfg.ScanInterval())
		updateTicker := time.NewTicker(24 * time.Hour)
		defer heartbeatTicker.Stop()
		defer scanTicker.Stop()
		defer updateTicker.Stop()

		log.Infof("Watch mode active — heartbeat every %s, full scan every %s",
			cfg.HeartbeatInterval(), cfg.ScanInterval())

		for {
			select {
			case <-ctx.Done():
				log.Infof("CertHound agent stopped.")
				return
			case <-heartbeatTicker.C:
				sendHeartbeat(ctx, cfg, log, senderClient, renewalClient, agentID, version)
			case <-scanTicker.C:
				runScan(ctx, cfg, log, senderClient, renewalClient, agentID, *jsonOutput)
			case <-updateTicker.C:
				if cfg.AutoUpdate {
					checkForUpdate(ctx, cfg, log)
				}
			case <-changeTrigger:
				log.Infof("File change detected — running triggered scan")
				runScan(ctx, cfg, log, senderClient, renewalClient, agentID, *jsonOutput)
			}
		}
	}

	if *watchMode || isWindowsService() {
		if isWindowsService() {
			// Running as a Windows service — delegate to the SCM handler
			// which manages the context lifecycle (cancel on stop/shutdown).
			log.Infof("Running as Windows service")
			runAsService(watchLoop)
		} else {
			// Running from the CLI with --watch
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigs
				log.Infof("Shutdown signal received, stopping agent...")
				cancel()
			}()
			watchLoop(ctx)
		}
	} else {
		runScan(context.Background(), cfg, log, senderClient, renewalClient, agentID, *jsonOutput)
	}
}

// startFileWatcher watches the configured scan paths and sends to changeTrigger
// when any file in those directories is created, written, or removed.
// Drops the event if a trigger is already pending (buffered channel of 1).
func startFileWatcher(ctx context.Context, cfg *config.Config, log *logger.Logger, changeTrigger chan<- struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warnf("Could not start file watcher: %v", err)
		return
	}

	paths := cfg.ScanPaths
	if runtime.GOOS == "windows" {
		paths = cfg.ScanPathsWindows
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			if err := watcher.Add(p); err != nil {
				log.Warnf("File watcher could not watch %s: %v", p, err)
			} else {
				log.Infof("File watcher monitoring: %s", p)
			}
		}
	}

	// certExts are the file extensions that indicate a certificate file changed.
	certExts := map[string]bool{
		".pem": true, ".crt": true, ".cer": true, ".der": true,
		".p12": true, ".pfx": true, ".key": true, ".csr": true,
	}

	go func() {
		defer watcher.Close()
		var debounce *time.Timer
		for {
			select {
			case <-ctx.Done():
				if debounce != nil {
					debounce.Stop()
				}
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Remove) {
					ext := strings.ToLower(filepath.Ext(event.Name))
					if !certExts[ext] {
						continue
					}
					log.Debugf("File watcher event: %s %s", event.Op, event.Name)
					// Debounce: wait 10 seconds after the last cert-related event
					// before triggering a scan. This collapses bursts into one scan.
					if debounce != nil {
						debounce.Stop()
					}
					debounce = time.AfterFunc(10*time.Second, func() {
						select {
						case changeTrigger <- struct{}{}:
						default:
						}
					})
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Warnf("File watcher error: %v", err)
			}
		}
	}()
}

// sendHeartbeat builds and sends a lightweight heartbeat payload. When the
// backend replies with pending_renewals (the dashboard's Renew Now button),
// the named domains are renewed inline before the function returns.
func sendHeartbeat(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, renewalClient *renewal.Client, agentID string, version string) {
	if senderClient == nil {
		log.Debugf("Heartbeat skipped — no endpoint configured")
		return
	}
	pl := payload.NewHeartbeatPayload(cfg, version, agentID)
	body, err := senderClient.SendAndRead(ctx, pl)
	if err != nil {
		log.Errorf("Error sending heartbeat: %v", err)
		return
	}
	log.Infof("Heartbeat sent to %s", cfg.AWSEndpoint)
	handlePendingRenewals(ctx, cfg, log, senderClient, renewalClient, agentID, body)
}

// handlePendingRenewals parses the response body from ingest for any commands
// the backend piggybacked onto the ACK (notably "Renew Now" clicks from the
// dashboard) and runs them inline. Called from both the heartbeat and full-scan
// paths so a queued command is picked up at the earliest possible check-in.
func handlePendingRenewals(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, renewalClient *renewal.Client, agentID string, body []byte) {
	if len(body) == 0 {
		return
	}
	var resp heartbeatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Debugf("Ingest response not JSON (this is fine on older backends): %v", err)
		return
	}
	if len(resp.PendingRenewals) == 0 {
		return
	}
	if renewalClient == nil {
		log.Warnf("Backend requested renewal for %v but renewal is not enabled on this agent", resp.PendingRenewals)
		return
	}
	log.Infof("Backend requested renewal for %d domain(s): %v", len(resp.PendingRenewals), resp.PendingRenewals)
	runRenewalsByDomain(ctx, cfg, log, senderClient, renewalClient, agentID, resp.PendingRenewals)
}

// runRenewalsByDomain runs renewal for each domain the backend asked for
// (by primary domain name) and ships results back.
func runRenewalsByDomain(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, renewalClient *renewal.Client, agentID string, domains []string) {
	var results []renewal.Result
	for _, domain := range domains {
		entry := renewal.FindByDomain(cfg.Renewal, domain)
		if entry == nil {
			log.Warnf("Backend requested renewal for %q but no matching entry in agent config — skipping", domain)
			results = append(results, renewal.Result{
				Domain:     domain,
				Domains:    []string{domain},
				Success:    false,
				Error:      "no matching entry in agent config",
				FinishedAt: time.Now().UTC(),
			})
			continue
		}
		log.Infof("Renewing %v (manual trigger)", entry.Domains)
		r := renewalClient.Renew(*entry)
		logRenewalResult(log, r)
		results = append(results, r)
	}
	sendRenewalResults(ctx, cfg, log, senderClient, agentID, results)
}

func logRenewalResult(log *logger.Logger, r renewal.Result) {
	if r.Success {
		if r.Error != "" {
			log.Warnf("Renewal of %s succeeded with warning: %s (new expiry: %s)", r.Domain, r.Error, r.NotAfter.Format(time.RFC3339))
		} else {
			log.Infof("Renewal of %s succeeded (new expiry: %s)", r.Domain, r.NotAfter.Format(time.RFC3339))
		}
	} else {
		log.Errorf("Renewal of %s failed: %s", r.Domain, r.Error)
	}
}

func sendRenewalResults(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, agentID string, results []renewal.Result) {
	if senderClient == nil || len(results) == 0 {
		return
	}
	pl := payload.NewRenewalPayload(results, cfg, version, agentID)
	if err := senderClient.SendRenewal(ctx, pl); err != nil {
		log.Errorf("Error sending renewal results: %v", err)
	} else {
		log.Infof("Renewal results (%d) sent to %s", len(results), cfg.AWSEndpoint)
	}
}

func checkForUpdate(ctx context.Context, cfg *config.Config, log *logger.Logger) {
	log.Infof("Checking for updates...")
	res := updater.CheckAndUpdate(ctx, version, cfg.UpdateCheckURL)
	if res.Error != nil {
		log.Warnf("Update check failed: %v", res.Error)
		return
	}
	if !res.Updated {
		log.Infof("Agent is up to date (%s)", version)
		return
	}
	log.Infof("Updated from %s to %s — restart required", res.CurrentVersion, res.NewVersion)
	// The service manager (Windows SCM or systemd) will restart us automatically.
	os.Exit(0)
}

func runScan(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, renewalClient *renewal.Client, agentID string, jsonOutput bool) {
	log.Infof("Starting certificate scan...")
	scanStart := time.Now()

	// Collect certs from filesystem paths
	paths := cfg.ScanPaths
	if runtime.GOOS == "windows" {
		paths = cfg.ScanPathsWindows
	}

	var allCerts []scanner.CertInfo
	var scanErrors []string
	for _, path := range paths {
		certs, err := scanner.ScanCertFiles(path, cfg)
		if err != nil {
			if os.IsNotExist(errors.Unwrap(err)) {
				log.Warnf("Scan path not found, skipping: %s", path)
			} else {
				log.Errorf("Error scanning %s: %v", path, err)
				scanErrors = append(scanErrors, fmt.Sprintf("scan %s: %v", path, err))
			}
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	// Windows cert store is scanned once, not per-path
	if runtime.GOOS == "windows" {
		winCerts, err := scanner.ScanWindowsCertStore(cfg)
		if err != nil {
			log.Warnf("Windows cert store scan error: %v", err)
			scanErrors = append(scanErrors, fmt.Sprintf("windows_store: %v", err))
		} else {
			allCerts = append(allCerts, winCerts...)
		}
	}

	log.Infof("Found %d certificate(s)", len(allCerts))

	// Print JSON to stdout if requested
	if jsonOutput {
		data, err := scanner.CertificatesToJSON(allCerts)
		if err != nil {
			log.Errorf("Error marshaling results as JSON: %v", err)
		} else {
			fmt.Println(string(data))
		}
	}

	// Send to endpoint if configured. We use SendAndRead so the backend can
	// piggyback pending commands (e.g. "Renew Now" clicks) onto the scan ACK
	// — otherwise a user clicking Renew Now has to wait up to one heartbeat
	// interval before the agent picks up the command.
	if senderClient != nil {
		pl := payload.NewPayload(allCerts, cfg, version, agentID, scanStart, scanErrors)
		body, err := senderClient.SendAndRead(ctx, pl)
		if err != nil {
			log.Errorf("Error sending payload: %v", err)
		} else {
			log.Infof("Payload sent to %s", cfg.AWSEndpoint)
			handlePendingRenewals(ctx, cfg, log, senderClient, renewalClient, agentID, body)
		}
	}

	// Auto-renew any certs that are within the renewal window. Done after the
	// scan so we have fresh NotAfter data to decide from. Renewal results are
	// sent to the backend as a separate payload.
	if renewalClient != nil {
		due := renewal.FindDue(allCerts, cfg.Renewal, time.Now())
		if len(due) > 0 {
			log.Infof("Auto-renewal: %d cert(s) within threshold — renewing now", len(due))
			var results []renewal.Result
			for _, entry := range due {
				log.Infof("Renewing %v", entry.Domains)
				r := renewalClient.Renew(entry)
				logRenewalResult(log, r)
				results = append(results, r)
			}
			sendRenewalResults(ctx, cfg, log, senderClient, agentID, results)
		}
	}

	log.Infof("Scan complete.")
}
