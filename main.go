package main

import (
	"fmt"
	"os"

	"github.com/keelw/certcync-agent/scanner"
)

func main() {
	var dir string

	// Default path (Linux example)
	if len(os.Args) > 1 {
		dir = os.Args[1]
	} else {
		dir = "/etc/ssl/certs"
	}

	fmt.Println("Scanning directory:", dir)

	certs, err := scanner.ScanCertFiles(dir)
	if err != nil {
		fmt.Println("Error scanning certificates:", err)
		return
	}

	fmt.Printf("Found %d certificates\n\n", len(certs))
	scanner.PrintCertInfo(certs)
}
