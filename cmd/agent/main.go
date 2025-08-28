/*
Main package for the CertCync Agent.

This executable scans certificates from a specified directory (defaulting to /etc/ssl/certs)
and prints them as JSON to standard output. On Windows, it can also scan the system
certificate store.

Author: Will Keel
Date: 2025-08-27
*/

package main

import (
	"fmt" // Provides Println for output
	"os"  // Provides access to command-line arguments

	// Import the local scanner package for certificate scanning and JSON conversion
	"github.com/keelw/certsync-agent/internal/scanner"
)

/*
main is the entry point for the executable.

Behavior:
 1. Determines the directory to scan. Defaults to "/etc/ssl/certs" but can be overridden
    with the first command-line argument.
 2. Calls ScanAllCertificates from the scanner package to scan the directory (and
    Windows store if applicable).
 3. Converts the resulting certificates to pretty-printed JSON.
 4. Prints the JSON to standard output.
 5. Handles errors gracefully by printing them and exiting early.
*/
func main() {
	// Default directory for scanning certificates
	dir := "/etc/ssl/certs"

	// Override directory if a command-line argument is provided
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	// Scan all certificates in the directory (and Windows store on Windows)
	certs, err := scanner.ScanAllCertificates(dir)
	if err != nil {
		fmt.Println("Error scanning certificates:", err)
		return
	}

	// Convert the slice of CertInfo to JSON
	jsonData, err := scanner.CertificatesToJSON(certs)
	if err != nil {
		fmt.Println("Error converting to JSON:", err)
		return
	}

	// Print the JSON representation of certificates
	fmt.Println(string(jsonData))
}
