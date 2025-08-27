package main

import (
	"fmt"
	"os"

	"github.com/keelw/certcync-agent/scanner"
)

func main() {
	dir := "/etc/ssl/certs"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	certs, err := scanner.ScanAllCertificates(dir)
	if err != nil {
		fmt.Println("Error scanning certificates:", err)
		return
	}

	jsonData, err := scanner.CertificatesToJSON(certs)
	if err != nil {
		fmt.Println("Error converting to JSON:", err)
		return
	}

	fmt.Println(string(jsonData))
}
