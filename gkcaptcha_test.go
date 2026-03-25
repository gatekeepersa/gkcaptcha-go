package gkcaptcha_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gkcaptcha "github.com/gatekeepersa/gkcaptcha-go"
)

// helper: build a client pointing at the given URL with valid credentials.
func newTestClient(t *testing.T, apiURL string, extra ...func(*gkcaptcha.Config)) *gkcaptcha.GkCaptchaClient {
	t.Helper()
	cfg := gkcaptcha.Config{
		SecretKey:  "sk_test_secret",
		SiteKey:    "pk_test_site",
		APIURL:     apiURL,
		MaxRetries: 1,
	}
	for _, fn := range extra {
		fn(&cfg)
	}
	client, err := gkcaptcha.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// 1. TestVerifyTokenSuccess -- server returns success JSON.
func TestVerifyTokenSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"success":true,"score":0.15,"timestamp":1700000000}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	result, err := client.VerifyToken(context.Background(), "test-token", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true")
	}
	if result.Score != 0.15 {
		t.Errorf("expected Score=0.15, got %v", result.Score)
	}
}

// 2. TestVerifyTokenFailure -- server returns failure JSON.
func TestVerifyTokenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"success":false,"error":"Token expired","reasonCode":"token_expired"}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	result, err := client.VerifyToken(context.Background(), "expired-token", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false")
	}
	if result.ReasonCode != "token_expired" {
		t.Errorf("expected reasonCode=token_expired, got %q", result.ReasonCode)
	}
}

// 3. TestFailOpenDefaultOnNetworkError -- unreachable server, FailClosed:false (default).
func TestFailOpenDefaultOnNetworkError(t *testing.T) {
	// Listen on a port, then immediately close the listener so connections are refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	client := newTestClient(t, "http://"+addr)
	result, err := client.VerifyToken(context.Background(), "any-token", nil)
	if err != nil {
		t.Fatalf("expected nil error with fail-open, got: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true for fail-open")
	}
	if !result.FailOpen {
		t.Error("expected FailOpen=true")
	}
}

// 4. TestFailClosedReturnsErrorOnNetworkError -- unreachable server, FailClosed:true.
func TestFailClosedReturnsErrorOnNetworkError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	client := newTestClient(t, "http://"+addr, func(c *gkcaptcha.Config) {
		c.FailClosed = true
	})
	result, err := client.VerifyToken(context.Background(), "any-token", nil)
	if err == nil {
		t.Fatal("expected error with fail-closed, got nil")
	}
	if result != nil {
		t.Error("expected nil result with fail-closed error")
	}
	gkErr, ok := err.(*gkcaptcha.GkCaptchaError)
	if !ok {
		t.Fatalf("expected *GkCaptchaError, got %T", err)
	}
	if gkErr.Code != "NETWORK_ERROR" {
		t.Errorf("expected Code=NETWORK_ERROR, got %q", gkErr.Code)
	}
}

// 5. TestRetriesOnNetworkError -- server fails first request (503), succeeds on second.
func TestRetriesOnNetworkError(t *testing.T) {
	var requestCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		if n == 1 {
			// First request: abruptly close to simulate network failure.
			// Hijack the connection to force a connection reset.
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		// Second request: success.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"success":true,"score":0.10}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, func(c *gkcaptcha.Config) {
		c.MaxRetries = 1
		c.RetryDelay = 0 // no sleep in tests
	})
	result, err := client.VerifyToken(context.Background(), "retry-token", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected Success=true after retry")
	}
	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("expected 2 requests, got %d", atomic.LoadInt32(&requestCount))
	}
}

// 6. TestReadsEnvVars -- credentials from environment variables.
func TestReadsEnvVars(t *testing.T) {
	t.Setenv("GKCAPTCHA_SECRET_KEY", "sk_env_secret")
	t.Setenv("GKCAPTCHA_SITE_KEY", "pk_env_site")

	_, err := gkcaptcha.NewClient(gkcaptcha.Config{})
	if err != nil {
		t.Fatalf("expected NewClient to succeed with env vars, got: %v", err)
	}
}

// 7. TestReturnsErrorOnMissingSecretKey -- no SecretKey provided.
func TestReturnsErrorOnMissingSecretKey(t *testing.T) {
	// Clear env to ensure no fallback.
	t.Setenv("GKCAPTCHA_SECRET_KEY", "")
	t.Setenv("GKCAPTCHA_SITE_KEY", "")

	_, err := gkcaptcha.NewClient(gkcaptcha.Config{SiteKey: "pk_live_test"})
	if err == nil {
		t.Fatal("expected error for missing SecretKey, got nil")
	}
	gkErr, ok := err.(*gkcaptcha.GkCaptchaError)
	if !ok {
		t.Fatalf("expected *GkCaptchaError, got %T", err)
	}
	if gkErr.Code != "INVALID_CONFIG" {
		t.Errorf("expected Code=INVALID_CONFIG, got %q", gkErr.Code)
	}
}

// 8. TestPassesClientIPAndUserAgent -- verify clientIP and userAgent sent in request body.
func TestPassesClientIPAndUserAgent(t *testing.T) {
	var capturedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	opts := &gkcaptcha.VerifyOptions{
		ClientIP:  "1.2.3.4",
		UserAgent: "Mozilla/5.0 TestBrowser",
	}
	_, err := client.VerifyToken(context.Background(), "ip-ua-token", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}

	if body["clientIP"] != "1.2.3.4" {
		t.Errorf("expected clientIP=1.2.3.4, got %v", body["clientIP"])
	}
	if body["userAgent"] != "Mozilla/5.0 TestBrowser" {
		t.Errorf("expected userAgent=Mozilla/5.0 TestBrowser, got %v", body["userAgent"])
	}
}

// 9. TestContextCancellationAbortsRequest -- cancel ctx before request completes.
func TestContextCancellationAbortsRequest(t *testing.T) {
	// Server hangs indefinitely.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())

	client := newTestClient(t, srv.URL, func(c *gkcaptcha.Config) {
		c.FailClosed = true // ensure we see the error rather than fail-open
	})

	// Cancel immediately.
	cancel()

	_, err := client.VerifyToken(ctx, "cancel-token", nil)
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}

	gkErr, ok := err.(*gkcaptcha.GkCaptchaError)
	if !ok {
		t.Fatalf("expected *GkCaptchaError, got %T: %v", err, err)
	}
	if gkErr.Code != "CANCELED" {
		t.Errorf("expected Code=CANCELED, got %q", gkErr.Code)
	}
}

// 10. TestFailClosedWithConfig -- construct via Config{FailClosed:true}, simulate network failure.
func TestFailClosedWithConfig(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := gkcaptcha.Config{
		SecretKey:  "sk_test",
		SiteKey:    "pk_test",
		APIURL:     "http://" + addr,
		FailClosed: true,
		MaxRetries: 0, // no retries to keep test fast
	}
	client, err := gkcaptcha.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.VerifyToken(context.Background(), "fc-token", nil)
	if err == nil {
		t.Fatal("expected error with FailClosed=true and network failure")
	}
	if result != nil {
		t.Error("expected nil result on fail-closed error")
	}

	gkErr, ok := err.(*gkcaptcha.GkCaptchaError)
	if !ok {
		t.Fatalf("expected *GkCaptchaError, got %T", err)
	}
	if gkErr.Code != "NETWORK_ERROR" {
		t.Errorf("expected Code=NETWORK_ERROR, got %q", gkErr.Code)
	}
	if !strings.Contains(gkErr.Error(), "NETWORK_ERROR") {
		t.Errorf("error string should contain NETWORK_ERROR: %q", gkErr.Error())
	}
}
