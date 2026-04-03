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
	"github.com/deadbolthq/certhound-agent/internal/logger"
	"github.com/deadbolthq/certhound-agent/internal/payload"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
	"github.com/deadbolthq/certhound-agent/internal/sender"
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
		for _, try := range []string{"configs/config.json", "config.json"} {
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

	log := logger.NewLogger(cfg.LogPath, cfg.LogLevel, cfg.Verbose)
	log.Infof("CertHound agent v%s starting on %s/%s", version, runtime.GOOS, runtime.GOARCH)
	defer log.Close()

	// Sender is only needed when an endpoint is configured
	var senderClient *sender.Sender
	if cfg.AWSEndpoint != "" {
		senderClient = sender.NewSender(cfg.AWSEndpoint, cfg.TLSVerify, cfg.MaxRetries)
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

		runScan(ctx, cfg, log, senderClient)

		ticker := time.NewTicker(cfg.ScanInterval())
		defer ticker.Stop()
		log.Infof("Watching — interval: %s", cfg.ScanInterval())

		for {
			select {
			case <-ctx.Done():
				log.Infof("CertHound agent stopped.")
				return
			case <-ticker.C:
				runScan(ctx, cfg, log, senderClient)
			}
		}
	} else {
		runScan(context.Background(), cfg, log, senderClient)
	}
}

func runScan(ctx context.Context, cfg *config.Config, log *logger.Logger, senderClient *sender.Sender) {
	log.Infof("Starting certificate scan...")

	// Collect certs from filesystem paths
	paths := cfg.ScanPaths
	if runtime.GOOS == "windows" {
		paths = cfg.ScanPathsWindows
	}

	var allCerts []scanner.CertInfo
	for _, path := range paths {
		certs, err := scanner.ScanCertFiles(path, cfg)
		if err != nil {
			log.Errorf("Error scanning %s: %v", path, err)
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	// Windows cert store is scanned once, not per-path
	if runtime.GOOS == "windows" {
		winCerts, err := scanner.ScanWindowsCertStore(cfg)
		if err != nil {
			log.Warnf("Windows cert store scan error: %v", err)
		} else {
			allCerts = append(allCerts, winCerts...)
		}
	}

	log.Infof("Found %d certificate(s)", len(allCerts))

	// Send to endpoint if configured
	if senderClient != nil {
		pl := payload.NewPayload(allCerts, cfg, version)
		if err := senderClient.Send(ctx, pl); err != nil {
			log.Errorf("Error sending payload: %v", err)
		} else {
			log.Infof("Payload sent to %s", cfg.AWSEndpoint)
		}
	}

	log.Infof("Scan complete.")
}
