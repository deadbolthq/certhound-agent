package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	_, err = s.sendBytes(ctx, data)
	return err
}

// SendAndRead is like Send but returns the response body on the successful
// (2xx) attempt. Used by the heartbeat path so the backend can piggyback
// commands (e.g. "renew domain X") onto the heartbeat ACK.
func (s *Sender) SendAndRead(ctx context.Context, pl *payload.Payload) ([]byte, error) {
	data, err := json.Marshal(pl)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return s.sendBytes(ctx, data)
}

// SendRenewal posts a renewal-result payload. Separate from Send because the
// envelope type differs and we'd rather the compiler catch a mismatch than
// accept an any.
func (s *Sender) SendRenewal(ctx context.Context, pl *payload.RenewalPayload) error {
	data, err := json.Marshal(pl)
	if err != nil {
		return fmt.Errorf("failed to marshal renewal payload: %w", err)
	}
	_, err = s.sendBytes(ctx, data)
	return err
}

func (s *Sender) sendBytes(ctx context.Context, data []byte) ([]byte, error) {
	backoff := time.Second
	var lastErr error
	for i := 0; i <= s.maxRetries; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewBuffer(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if s.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+s.apiKey)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if readErr != nil {
					return nil, fmt.Errorf("reading response body: %w", readErr)
				}
				return body, nil
			}
			lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
		}

		if i < s.maxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}

	return nil, fmt.Errorf("failed to send payload after %d retries: %w", s.maxRetries, lastErr)
}
