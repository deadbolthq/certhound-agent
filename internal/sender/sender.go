package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/payload"
)

type Sender struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
	maxRetries int
}

// NewSender initializes a sender with TLS verification and retries
func NewSender(endpoint string, apiKey string, tlsVerify bool, maxRetries int) *Sender {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerify},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	return &Sender{
		endpoint:   endpoint,
		apiKey:     apiKey,
		httpClient: client,
		maxRetries: maxRetries,
	}
}

// Send sends the payload to the configured endpoint with exponential backoff retries.
// The context is honoured during waits — cancelling it aborts immediately.
func (s *Sender) Send(ctx context.Context, pl *payload.Payload) error {
	data, err := json.Marshal(pl)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	backoff := time.Second
	var lastErr error
	for i := 0; i <= s.maxRetries; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewBuffer(data))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
			if s.apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+s.apiKey)
			}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
		}

		if i < s.maxRetries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}

	return fmt.Errorf("failed to send payload after %d retries: %w", s.maxRetries, lastErr)
}
