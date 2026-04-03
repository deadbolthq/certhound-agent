package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/identity"
	"github.com/deadbolthq/certhound-agent/internal/logger"
	"github.com/deadbolthq/certhound-agent/internal/payload"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
	"github.com/deadbolthq/certhound-agent/internal/sender"
	"github.com/fsnotify/fsnotify"
)

// version is injected at build time via: -ldflags "-X main.version=x.y.z"
var version = "dev"

func main() {
	var (
		configPath = flag.String("config", "", "Path to config file (optional; flags take precedence)")
		endpoint   = flag.String("endpoint", "", "CertHound API endpoint to POST results to")
		watchMode  = flag.Bool("watch", false, "Run continuously on the configured scan interval")
		threshold  = flag.Int("threshold", 0, "Days before expiry to flag as expiring (overrides config)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CertHound Agent v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "Scans for X.509 certificates on this host and reports their status.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  certhound-agent [flags] [path ...]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --endpoint https://api.certhound.dev/v1/ingest --watch\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --watch --threshold 30\n")
	}
	flag.Parse()
	extraPaths := flag.Args()

	// Load config: --config flag > auto-discovered file > built-in defaults
	cfg := config.DefaultConfig()
	if *configPath != "" {
		loaded, err := config.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config %q: %v\n", *configPath, err)
			os.Exit(1)
		}
		cfg = loaded
	} else {
		candidates := []string{
			"/etc/certhound/config.json",
			`C:\ProgramData\CertHound\config.json`,
			"configs/config.json",
			"config.json",
		}
		for _, try := range candidates {
			if _, err := os.Stat(try); err == nil {
				if loaded, err := config.LoadConfig(try); err == nil {
					cfg = loaded
					break
				}
			}
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
	log.Infof("CertHound agent v%s starting on %s/%s (id: %s)", version, runtime.GOOS, runtime.GOARCH, agentID)
	defer log.Close()

	// Sender is only needed when an endpoint is configured
	var senderClient *sender.Sender
	if cfg.AWSEndpoint != "" {
		senderClient = sender.NewSender(cfg.AWSEndpoint, cfg.APIKey, cfg.TLSVerify, cfg.MaxRetries)
		log.Infof("Sender initialized for endpoint: %s", cfg.AWSEndpoint)
	}

	if *watchMode {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			log.Infof("Shutdown signal received, stopping agent...")
			cancel()
		}()

		// changeTrigger is buffered so the file watcher never blocks.
		// A value sent here causes an immediate scan outside the daily schedule.
		changeTrigger := make(chan struct{}, 1)

		// Start filesystem watcher on scan paths
		startFileWatcher(ctx, cfg, log, changeTrigger)

		// Initial scan on startup
		runScan(ctx, cfg, log, senderClient, agentID)

		heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval())
		scanTicker := time.NewTicker(cfg.ScanInterval())
		defer heartbeatTicker.Stop()
		defer scanTicker.Stop()

		log.Infof("Watch mode active — heartbeat every %s, full scan every %s",
			cfg.HeartbeatInterval(), cfg.ScanInterval())

		for {
			select {
			case <-ctx.Done():
				log.Infof("CertHound agent stopped.")
				return
			case <-heartbeatTicker.C:
				sendHeartbeat(ctx, cfg, log, senderClient, agentID)
			case <-scanTicker.C:
				runScan(ctx, cfg, log, senderClient, agentID)
			case <-changeTrigger:
				log.Infof("File change detected — running triggered scan")
				runScan(ctx, cfg, log, senderClient, agentID)
			}
		}
	} else {
		runScan(context.Background(), cfg, log, senderClient, agentID)
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

	go func() {
		defer watcher.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Remove) {
					log.Debugf("File watcher event: %s %s", event.Op, event.Name)
					// Non-blocking send: if a trigger is already pending, skip this one
					select {
					case changeTrigger <- struct{}{}:
					default:
					}
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

// sendHeartbeat builds and sends a lightweight heartbeat payload.
func sendHeartbeat(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, agentID string) {
	if senderClient == nil {
		log.Debugf("Heartbeat skipped — no endpoint configured")
		return
	}
	pl := payload.NewHeartbeatPayload(cfg, version, agentID)
	if err := senderClient.Send(ctx, pl); err != nil {
		log.Errorf("Error sending heartbeat: %v", err)
	} else {
		log.Infof("Heartbeat sent to %s", cfg.AWSEndpoint)
	}
}

func runScan(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, agentID string) {
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
			log.Errorf("Error scanning %s: %v", path, err)
			scanErrors = append(scanErrors, fmt.Sprintf("scan %s: %v", path, err))
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

	// Send to endpoint if configured
	if senderClient != nil {
		pl := payload.NewPayload(allCerts, cfg, version, agentID, scanStart, scanErrors)
		if err := senderClient.Send(ctx, pl); err != nil {
			log.Errorf("Error sending payload: %v", err)
		} else {
			log.Infof("Payload sent to %s", cfg.AWSEndpoint)
		}
	}

	log.Infof("Scan complete.")
}
