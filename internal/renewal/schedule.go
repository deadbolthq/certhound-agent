package renewal

import (
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
)

// FindDue returns the RenewalEntries whose primary cert is within the renewal
// window (or missing from the scan entirely). A missing cert triggers a renewal
// so a brand-new configured domain gets issued on first run without the user
// having to bootstrap one manually.
func FindDue(certs []scanner.CertInfo, cfg config.Renewal, now time.Time) []config.RenewalEntry {
	threshold := cfg.RenewalThresholdDays
	if threshold <= 0 {
		threshold = 30
	}
	var due []config.RenewalEntry
	for _, entry := range cfg.Certs {
		if len(entry.Domains) == 0 {
			continue
		}
		cert := findCertByDomain(certs, entry.Domains[0])
		if cert == nil {
			due = append(due, entry)
			continue
		}
		if cert.DaysUntilExpiry <= threshold {
			due = append(due, entry)
		}
	}
	return due
}

// FindByDomain returns the configured RenewalEntry whose primary domain matches,
// or nil if none do. Used when the backend tells the agent to renew a specific domain.
func FindByDomain(cfg config.Renewal, domain string) *config.RenewalEntry {
	for i := range cfg.Certs {
		if cfg.Certs[i].MatchesDomain(domain) {
			return &cfg.Certs[i]
		}
	}
	return nil
}

func findCertByDomain(certs []scanner.CertInfo, domain string) *scanner.CertInfo {
	for i := range certs {
		for _, name := range certs[i].DNSNames {
			if name == domain {
				return &certs[i]
			}
		}
	}
	return nil
}
