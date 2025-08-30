package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
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
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// 2️⃣ Initialize logger
	log := logger.NewLogger(cfg.LogPath)
	log.Infof("CertSync agent v%s starting...", agentVersion)

	// 3️⃣ Setup AWS sender (TLS, retries)
	senderClient := sender.NewSender(cfg.AWSEndpoint, cfg.TLSVerify, cfg.MaxRetries)
	log.Infof("Sender initialized for endpoint: %s", cfg.AWSEndpoint)

	// 4️⃣ Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	log.Infof("Press Ctrl+C to stop the agent.") //dev code

	go func() {
		<-sigs
		log.Infof("Shutdown signal received, stopping agent...")
		cancel()
	}()

	// Run initial scan immediately
	runScan(cfg, log, senderClient)

	// 5️⃣ Main agent loop
	ticker := time.NewTicker(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
	log.Infof("Starting scan loop with interval: %s", time.Duration(cfg.ScanIntervalSeconds)*time.Second)
	defer ticker.Stop()

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

	// Loop over all configured scan paths
	for _, path := range cfg.ScanPaths {
		certs, err := scanner.ScanAllCertificates(path)
		if err != nil {
			log.Errorf("Error scanning %s: %v", path, err)
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	log.Infof("Found %d certificates", len(allCerts))

	// Build payload
	hostPayload := payload.NewPayload(allCerts, agentVersion)

	// Print JSON payload to console (for debugging)
	pretty, err := json.MarshalIndent(hostPayload, "", "  ")
	if err != nil {
		log.Errorf("Error marshalling payload: %v", err)
	} else {
		fmt.Println("=== Payload ===")
		fmt.Println(string(pretty))
	}

	// Log to JSON file locally
	if err := logger.WriteJSON(hostPayload, cfg.LogPath); err != nil {
		log.Errorf("Error writing log: %v", err)
	}

	// Send to AWS (comment if not configured yet)
	// err = senderClient.Send(hostPayload)
	// if err != nil {
	//     log.Errorf("Error sending to AWS: %v", err)
	// }

	log.Infof("Scan completed.")
}
