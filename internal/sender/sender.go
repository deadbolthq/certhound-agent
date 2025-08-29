package sender

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/keelw/certsync-agent/internal/payload"
)

type Sender struct {
	endpoint   string
	httpClient *http.Client
	maxRetries int
}

// NewSender initializes a sender with TLS verification and retries
func NewSender(endpoint string, tlsVerify bool, maxRetries int) *Sender {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	return &Sender{
		endpoint:   endpoint,
		httpClient: client,
		maxRetries: maxRetries,
	}
}

// Send sends the payload to the configured endpoint with retries
func (s *Sender) Send(pl *payload.Payload) error {
	data, err := json.Marshal(pl)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var lastErr error
	for i := 0; i <= s.maxRetries; i++ {
		req, err := http.NewRequest("POST", s.endpoint, bytes.NewBuffer(data))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second * 2) // backoff
			continue
		}

		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		} else {
			lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
			time.Sleep(time.Second * 2)
		}
	}

	return fmt.Errorf("failed to send payload after %d retries: %w", s.maxRetries, lastErr)
}
