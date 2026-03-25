//go:build integration

package gkcaptcha_test

import (
	"context"
	"os"
	"testing"

	gkcaptcha "github.com/gatekeepersa/gkcaptcha-go"
)

// TestLiveAPIReachable verifies that the production gkCAPTCHA API is reachable
// and returns a well-formed response. It sends a dummy token and asserts that:
//
//  1. No network/TLS error occurred (API is reachable)
//  2. The response is parseable (correct JSON structure)
//  3. success=false (dummy token must fail verification)
//  4. FailOpen=false (actual API responded, not a fallback)
//
// Run with: GKCAPTCHA_LIVE_TEST=1 go test -tags=integration -v -run TestLiveAPI ./...
func TestLiveAPIReachable(t *testing.T) {
	if os.Getenv("GKCAPTCHA_LIVE_TEST") == "" {
		t.Skip("set GKCAPTCHA_LIVE_TEST=1 to run live tests")
	}
	secretKey := os.Getenv("GKCAPTCHA_SECRET_KEY")
	siteKey := os.Getenv("GKCAPTCHA_SITE_KEY")
	if secretKey == "" || siteKey == "" {
		t.Fatal("GKCAPTCHA_SECRET_KEY and GKCAPTCHA_SITE_KEY must be set for live tests")
	}

	client, err := gkcaptcha.NewClient(gkcaptcha.Config{
		SecretKey:  secretKey,
		SiteKey:    siteKey,
		FailClosed: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.VerifyToken(context.Background(), "smoke-test-dummy-token", nil)
	if err != nil {
		t.Fatalf("VerifyToken network error (API unreachable): %v", err)
	}
	if result.Success {
		t.Error("expected success=false for dummy token")
	}
	if result.FailOpen {
		t.Error("expected actual API response, not fail-open fallback")
	}
	t.Logf("Live API response: success=%v, error=%q, reasonCode=%q", result.Success, result.Error, result.ReasonCode)
}
