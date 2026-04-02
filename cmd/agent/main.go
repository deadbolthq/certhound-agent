package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/logger"
	"github.com/deadbolthq/certhound-agent/internal/payload"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
	"github.com/deadbolthq/certhound-agent/internal/sender"
)

const agentVersion = "0.1.0"

func main() {
	var (
		configPath = flag.String("config", "", "Path to config file (optional; flags take precedence)")
		jsonOut    = flag.Bool("json", false, "Output JSON to stdout instead of a table")
		endpoint   = flag.String("endpoint", "", "CertHound API endpoint to POST results to")
		watchMode  = flag.Bool("watch", false, "Run continuously on the configured scan interval")
		threshold  = flag.Int("threshold", 0, "Days before expiry to flag as expiring (overrides config)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CertHound Agent v%s\n\n", agentVersion)
		fmt.Fprintf(os.Stderr, "Scans for X.509 certificates on this host and reports their status.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  certhound-agent [flags] [path ...]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent /etc/nginx/ssl /home/deploy/certs\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --json\n")
		fmt.Fprintf(os.Stderr, "  certhound-agent --endpoint https://api.certhound.dev/v1/ingest\n")
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

	// Logger is only needed in watch mode or when sending to an endpoint
	var log *logger.Logger
	if *watchMode || cfg.AWSEndpoint != "" {
		log = logger.NewLogger(cfg.LogPath, cfg.LogLevel, cfg.Verbose)
		log.Infof("CertHound agent v%s starting on %s/%s", agentVersion, runtime.GOOS, runtime.GOARCH)
	}

	// Sender is only needed when an endpoint is configured
	var senderClient *sender.Sender
	if cfg.AWSEndpoint != "" {
		senderClient = sender.NewSender(cfg.AWSEndpoint, cfg.TLSVerify, cfg.MaxRetries)
		if log != nil {
			log.Infof("Sender initialized for endpoint: %s", cfg.AWSEndpoint)
		}
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

		runScan(cfg, log, senderClient, *jsonOut)

		ticker := time.NewTicker(cfg.ScanInterval())
		defer ticker.Stop()
		log.Infof("Watching — interval: %s (Ctrl+C to stop)", cfg.ScanInterval())

		for {
			select {
			case <-ctx.Done():
				log.Infof("CertHound agent stopped.")
				return
			case <-ticker.C:
				runScan(cfg, log, senderClient, *jsonOut)
			}
		}
	} else {
		runScan(cfg, log, senderClient, *jsonOut)
	}
}

func runScan(cfg *config.Config, log *logger.Logger, senderClient *sender.Sender, jsonOut bool) {
	if log != nil {
		log.Infof("Starting certificate scan...")
	}

	// Collect certs from filesystem paths
	paths := cfg.ScanPaths
	if runtime.GOOS == "windows" {
		paths = cfg.ScanPathsWindows
	}

	var allCerts []scanner.CertInfo
	for _, path := range paths {
		certs, err := scanner.ScanCertFiles(path, cfg)
		if err != nil {
			if log != nil {
				log.Errorf("Error scanning %s: %v", path, err)
			}
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	// Windows cert store is scanned once, not per-path
	if runtime.GOOS == "windows" {
		winCerts, err := scanner.ScanWindowsCertStore(cfg)
		if err != nil {
			if log != nil {
				log.Warnf("Windows cert store scan error: %v", err)
			}
		} else {
			allCerts = append(allCerts, winCerts...)
		}
	}

	if log != nil {
		log.Infof("Found %d certificate(s)", len(allCerts))
	}

	// Output
	if jsonOut {
		pl := payload.NewPayload(allCerts, cfg, agentVersion)
		data, err := json.MarshalIndent(pl, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshalling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
	} else {
		printTable(allCerts, cfg.ExpiringThresholdDays)
	}

	// Send to endpoint if configured
	if senderClient != nil {
		pl := payload.NewPayload(allCerts, cfg, agentVersion)
		if err := senderClient.Send(pl); err != nil {
			if log != nil {
				log.Errorf("Error sending payload: %v", err)
			} else {
				fmt.Fprintf(os.Stderr, "error sending payload: %v\n", err)
			}
		} else if log != nil {
			log.Infof("Payload sent to %s", cfg.AWSEndpoint)
		}
	}

	if log != nil {
		log.Infof("Scan complete.")
	}
}

func printTable(certs []scanner.CertInfo, thresholdDays int) {
	host, _ := os.Hostname()
	now := time.Now()
	fmt.Printf("CertHound Agent v%s — %s — %d certificate(s) found\n\n", agentVersion, host, len(certs))

	if len(certs) == 0 {
		fmt.Println("No certificates found in the configured scan paths.")
		return
	}

	type row struct {
		subject, expiry, days, status, path string
		color                               string
	}

	rows := make([]row, 0, len(certs))
	maxSubject := len("SUBJECT")
	maxPath := len("PATH")

	for _, c := range certs {
		expiry, err := time.Parse(time.RFC3339, c.NotAfter)

		var days int
		var daysStr, status, color string
		if err == nil {
			days = int(expiry.Sub(now).Hours() / 24)
			daysStr = fmt.Sprintf("%d", days)
			switch {
			case days < 0:
				status, color = "EXPIRED", logger.ColorRed
			case days < 14:
				status, color = "CRITICAL", logger.ColorRed
			case days < thresholdDays:
				status, color = "WARNING", logger.ColorYellow
			default:
				status, color = "OK", logger.ColorGreen
			}
		} else {
			daysStr, status, color = "?", "UNKNOWN", ""
		}

		subject := extractCN(c.Subject)
		path := c.CertPath
		if len(path) > 48 {
			path = "..." + path[len(path)-45:]
		}

		if len(subject) > maxSubject {
			maxSubject = len(subject)
		}
		if len(path) > maxPath {
			maxPath = len(path)
		}

		expiryStr := ""
		if err == nil {
			expiryStr = expiry.Format("2006-01-02")
		}
		rows = append(rows, row{subject, expiryStr, daysStr, status, path, color})
	}

	subjectFmt := fmt.Sprintf("%%-%ds", maxSubject)
	pathFmt := fmt.Sprintf("%%-%ds", maxPath)
	colFmt := subjectFmt + "  %-10s  %5s  %-8s  " + pathFmt + "\n"

	header := fmt.Sprintf(colFmt, "SUBJECT", "EXPIRY", "DAYS", "STATUS", "PATH")
	sep := fmt.Sprintf(colFmt,
		strings.Repeat("-", maxSubject),
		"----------", "-----", "--------",
		strings.Repeat("-", maxPath),
	)
	fmt.Print(header)
	fmt.Print(sep)

	for _, r := range rows {
		line := fmt.Sprintf(colFmt, r.subject, r.expiry, r.days, r.status, r.path)
		fmt.Print(r.color + line + logger.ColorReset)
	}
}

// extractCN pulls the CN value from a Subject DN string.
func extractCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "CN="); ok {
			if len(after) > 42 {
				return after[:39] + "..."
			}
			return after
		}
	}
	if len(subject) > 42 {
		return subject[:39] + "..."
	}
	return subject
}
