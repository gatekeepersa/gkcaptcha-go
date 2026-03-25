package gkcaptcha

import "fmt"

// GkCaptchaError is returned for configuration errors (INVALID_CONFIG),
// network errors when FailClosed is true (NETWORK_ERROR),
// and timeout errors (TIMEOUT).
// Verification failures (success=false from API) are NOT errors -- check result.Success instead.
type GkCaptchaError struct {
	Code    string
	Message string
	Cause   error
}

func (e *GkCaptchaError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("gkcaptcha: %s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("gkcaptcha: %s: %s", e.Code, e.Message)
}

func (e *GkCaptchaError) Unwrap() error {
	return e.Cause
}
