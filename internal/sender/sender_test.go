package sender

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/payload"
)

func testPayload() *payload.Payload {
	cfg := &config.Config{AgentName: "test", PayloadVersion: "1.0"}
	return payload.NewPayload(nil, cfg, "dev", "test-agent-id")
}

func TestSend_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSender(srv.URL, "", true, 0)
	if err := s.Send(context.Background(), testPayload()); err != nil {
		t.Errorf("Send: unexpected error: %v", err)
	}
}

func TestSend_ServerError_Retries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewSender(srv.URL, "", true, 2)
	err := s.Send(context.Background(), testPayload())
	if err == nil {
		t.Error("expected error after exhausted retries")
	}
	// 1 initial attempt + 2 retries = 3 total calls
	if calls.Load() != 3 {
		t.Errorf("expected 3 calls (1+2 retries), got %d", calls.Load())
	}
}

func TestSend_ContextCancellation(t *testing.T) {
	// Server always returns 500 so the sender will try to wait between retries.
	// We cancel the context immediately to verify it aborts.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())

	s := NewSender(srv.URL, "", true, 5)
	// Cancel after a short delay so the first attempt completes but the backoff wait is interrupted.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := s.Send(ctx, testPayload())
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error after context cancellation")
	}
	// Without context cancellation 5 retries with 1s+ backoff would take >5s.
	// With cancellation it should complete well under 1s.
	if elapsed > 2*time.Second {
		t.Errorf("Send did not respect context cancellation: took %v", elapsed)
	}
}

func TestSend_APIKeyHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSender(srv.URL, "my-secret-key", true, 0)
	if err := s.Send(context.Background(), testPayload()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAuth != "Bearer my-secret-key" {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer my-secret-key")
	}
}

func TestSend_NoAPIKeyHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSender(srv.URL, "", true, 0)
	if err := s.Send(context.Background(), testPayload()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header should be absent when no API key set, got %q", gotAuth)
	}
}

func TestSend_BadEndpoint(t *testing.T) {
	s := NewSender("http://127.0.0.1:1", "", true, 0)
	err := s.Send(context.Background(), testPayload())
	if err == nil {
		t.Error("expected error for unreachable endpoint")
	}
}
