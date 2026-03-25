// Package gkcaptcha provides a Go client for the gkCAPTCHA verification API.
//
// Zero external dependencies — uses only the Go standard library.
//
// Quick start:
//
//	client, err := gkcaptcha.NewClient(gkcaptcha.Config{
//	    SecretKey: os.Getenv("GKCAPTCHA_SECRET_KEY"),
//	    SiteKey:   os.Getenv("GKCAPTCHA_SITE_KEY"),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	result, err := client.VerifyToken(ctx, token, nil)
//	if err != nil {
//	    // Network/config error — see result.FailOpen for fail-open behavior
//	    log.Println("verification error:", err)
//	}
//	if !result.Success {
//	    // Verification failed — reject the request
//	}
package gkcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	defaultAPIURL     = "https://gkcaptcha.gatekeeper.sa"
	defaultTimeout    = 5 * time.Second
	defaultMaxRetries = 1
	defaultRetryDelay = 1 * time.Second
)

// Config holds configuration for the gkCAPTCHA client.
type Config struct {
	// SecretKey is the secret key from your gkCAPTCHA dashboard.
	// Falls back to GKCAPTCHA_SECRET_KEY environment variable if empty.
	SecretKey string

	// SiteKey is the public site key from your gkCAPTCHA dashboard.
	// Falls back to GKCAPTCHA_SITE_KEY environment variable if empty.
	SiteKey string

	// APIURL is the base URL of the gkCAPTCHA API. Defaults to "https://gkcaptcha.gatekeeper.sa".
	APIURL string

	// Timeout is the HTTP request timeout. Defaults to 5 seconds.
	Timeout time.Duration

	// MaxRetries is the number of retries on network errors. Defaults to 1.
	MaxRetries int

	// RetryDelay is the duration to wait between retries. Defaults to 1 second.
	RetryDelay time.Duration

	// HTTPClient is an optional custom HTTP client. If nil, a default client
	// with the configured Timeout is created.
	HTTPClient *http.Client

	// FailClosed controls behavior on network errors.
	//
	// false (default, fail-open): On network error, VerifyToken returns
	// &VerifyTokenResponse{Success: true, FailOpen: true}, nil — the request
	// is allowed through. This is the industry-standard behavior for CAPTCHAs.
	//
	// true (fail-closed): On network error, VerifyToken returns
	// nil, *GkCaptchaError{Code: "NETWORK_ERROR"} — the request is blocked.
	FailClosed bool
}

// GkCaptchaClient is the gkCAPTCHA verification client.
type GkCaptchaClient struct {
	config Config
	http   *http.Client
}

// NewClient creates a new gkCAPTCHA client with the given config.
//
// SecretKey and SiteKey may be provided via Config fields or via the
// GKCAPTCHA_SECRET_KEY and GKCAPTCHA_SITE_KEY environment variables.
//
// Returns *GkCaptchaError{Code: "INVALID_CONFIG"} if SecretKey or SiteKey
// are still empty after checking environment variables.
func NewClient(cfg Config) (*GkCaptchaClient, error) {
	// Fall back to environment variables.
	if cfg.SecretKey == "" {
		cfg.SecretKey = os.Getenv("GKCAPTCHA_SECRET_KEY")
	}
	if cfg.SiteKey == "" {
		cfg.SiteKey = os.Getenv("GKCAPTCHA_SITE_KEY")
	}

	// Validate required fields.
	if cfg.SecretKey == "" {
		return nil, &GkCaptchaError{
			Code:    "INVALID_CONFIG",
			Message: "SecretKey is required (or set GKCAPTCHA_SECRET_KEY environment variable)",
		}
	}
	if cfg.SiteKey == "" {
		return nil, &GkCaptchaError{
			Code:    "INVALID_CONFIG",
			Message: "SiteKey is required (or set GKCAPTCHA_SITE_KEY environment variable)",
		}
	}

	// Apply defaults.
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = defaultRetryDelay
	}

	// Create HTTP client if not provided.
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}

	return &GkCaptchaClient{
		config: cfg,
		http:   httpClient,
	}, nil
}

// VerifyToken verifies a CAPTCHA token against the gkCAPTCHA API.
//
// opts may be nil. When provided, ClientIP and UserAgent are forwarded to the
// API for binding verification.
//
// On success: returns *VerifyTokenResponse with Success=true, err=nil.
// On verification failure: returns *VerifyTokenResponse with Success=false, err=nil.
// On network error (after retries):
//   - FailClosed=false (default): returns &VerifyTokenResponse{Success:true, FailOpen:true}, nil
//   - FailClosed=true: returns nil, *GkCaptchaError{Code:"NETWORK_ERROR"}
//
// On context cancellation: returns nil, *GkCaptchaError{Code:"CANCELED"}.
func (c *GkCaptchaClient) VerifyToken(ctx context.Context, token string, opts *VerifyOptions) (*VerifyTokenResponse, error) {
	req := VerifyTokenRequest{
		SiteKey: c.config.SiteKey,
		Secret:  c.config.SecretKey,
		Token:   token,
	}
	if opts != nil {
		req.ClientIP = opts.ClientIP
		req.UserAgent = opts.UserAgent
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, &GkCaptchaError{
			Code:    "INVALID_CONFIG",
			Message: "failed to marshal request",
			Cause:   err,
		}
	}

	endpoint := c.config.APIURL + "/api/v1/token/verify"

	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		// Check context before each attempt.
		if ctx.Err() != nil {
			return nil, &GkCaptchaError{
				Code:    "CANCELED",
				Message: "request context canceled or timed out",
				Cause:   ctx.Err(),
			}
		}

		if attempt > 0 {
			// Wait between retries, but respect context cancellation.
			select {
			case <-ctx.Done():
				return nil, &GkCaptchaError{
					Code:    "CANCELED",
					Message: "request context canceled during retry backoff",
					Cause:   ctx.Err(),
				}
			case <-time.After(c.config.RetryDelay):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, &GkCaptchaError{
				Code:    "INVALID_CONFIG",
				Message: fmt.Sprintf("failed to create HTTP request: %v", err),
				Cause:   err,
			}
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(httpReq)
		if err != nil {
			// Check for context cancellation first.
			if ctx.Err() != nil {
				return nil, &GkCaptchaError{
					Code:    "CANCELED",
					Message: "request context canceled or timed out",
					Cause:   ctx.Err(),
				}
			}

			// Check if this is a network error (retryable).
			if isNetworkError(err) {
				lastErr = err
				continue
			}

			// Non-retryable error.
			lastErr = err
			break
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		var result VerifyTokenResponse
		if decodeErr := json.Unmarshal(respBody, &result); decodeErr != nil {
			return nil, &GkCaptchaError{
				Code:    "INVALID_CONFIG",
				Message: "failed to decode API response",
				Cause:   decodeErr,
			}
		}

		return &result, nil
	}

	// All attempts exhausted — apply fail-open/closed policy.
	if !c.config.FailClosed {
		return &VerifyTokenResponse{Success: true, FailOpen: true}, nil
	}
	return nil, &GkCaptchaError{
		Code:    "NETWORK_ERROR",
		Message: "gkCAPTCHA API unreachable after retries",
		Cause:   lastErr,
	}
}

// isNetworkError reports whether err represents a retryable network error.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return true
		}
		var netErr *net.OpError
		if errors.As(urlErr.Err, &netErr) {
			return true
		}
		// Connection refused, DNS failure, etc.
		return true
	}
	// Check for net.OpError directly.
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	return false
}

