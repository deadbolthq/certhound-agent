package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/keelw/certsync-agent/internal/config"
	"github.com/keelw/certsync-agent/internal/logger"
	"github.com/keelw/certsync-agent/internal/payload"
	"github.com/keelw/certsync-agent/internal/scanner"
	"github.com/keelw/certsync-agent/internal/sender"
)

const agentVersion = "0.1.0"

func main() {
	// 1️⃣ Load config
	cfg, err := config.LoadConfig("../../configs/config.json")
	if err != nil {
		fmt.Printf("[ERROR] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 2️⃣ Initialize logger
	log := logger.NewLogger(cfg.LogPath, cfg.LogLevel, cfg.Verbose)
	log.Infof("CertSync agent v%s starting on %s/%s", agentVersion, runtime.GOOS, runtime.GOARCH)
	log.Infof("Log level: %s | Verbose: %v", cfg.LogLevel, cfg.Verbose)

	// 3️⃣ Setup AWS sender (TLS, retries)
	senderClient := sender.NewSender(cfg.AWSEndpoint, cfg.TLSVerify, cfg.MaxRetries)
	log.Infof("Sender initialized for endpoint: %s", cfg.AWSEndpoint)

	// 4️⃣ Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	log.Infof("Press Ctrl+C to stop the agent.")

	go func() {
		<-sigs
		log.Infof("Shutdown signal received, stopping agent...")
		cancel()
	}()

	// Run initial scan immediately
	runScan(cfg, log, senderClient)

	// 5️⃣ Main agent loop
	ticker := time.NewTicker(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
	defer ticker.Stop()
	log.Infof("Starting scan loop with interval: %s", time.Duration(cfg.ScanIntervalSeconds)*time.Second)

	for {
		select {
		case <-ctx.Done():
			log.Infof("CertSync agent stopped.")
			return
		case <-ticker.C:
			runScan(cfg, log, senderClient)
		}
	}
}

// runScan performs a single scan and handles logging + sending
func runScan(cfg *config.Config, log *logger.Logger, senderClient *sender.Sender) {
	log.Infof("Starting certificate scan...")

	var allCerts []scanner.CertInfo

	// Determine OS-specific scan paths
	paths := cfg.ScanPaths
	if runtime.GOOS == "windows" {
		paths = cfg.ScanPathsWindows
	}

	// Loop over all configured scan paths
	for _, path := range paths {
		certs, err := scanner.ScanAllCertificates(path, cfg)
		if err != nil {
			log.Errorf("Error scanning %s: %v", path, err)
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	log.Infof("Found %d certificates", len(allCerts))

	// Build payload
	hostPayload := payload.NewPayload(allCerts, cfg, agentVersion)

	// Print JSON payload to console (for debugging)
	pretty, err := json.MarshalIndent(hostPayload, "", "  ")
	if err != nil {
		log.Errorf("Error marshalling payload: %v", err)
	} else {
		fmt.Println("=== Payload ===")
		fmt.Println(string(pretty))
	}

	// Log to JSON file locally (plain, no colors)
	if err := logger.WriteJSON(hostPayload, cfg.LogPath); err != nil {
		log.Errorf("Error writing JSON log: %v", err)
	}

	// Send to AWS (comment if not configured yet)
	if senderClient != nil {
		err := senderClient.Send(hostPayload)
		if err != nil {
			log.Errorf("Error sending payload to AWS: %v", err)
		} else {
			log.Infof("Payload successfully sent to %s", cfg.AWSEndpoint)
		}
	}

	log.Infof("Scan completed.")
}
