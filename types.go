package gkcaptcha

// VerifyTokenRequest is the JSON body sent to POST /api/token/verify.
type VerifyTokenRequest struct {
	SiteKey   string `json:"siteKey"`
	Secret    string `json:"secret"`
	Token     string `json:"token"`
	ClientIP  string `json:"clientIP,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
}

// VerifyTokenResponse is the parsed response from POST /api/token/verify.
type VerifyTokenResponse struct {
	Success    bool    `json:"success"`
	Score      float64 `json:"score,omitempty"`
	Timestamp  int64   `json:"timestamp,omitempty"`
	Error      string  `json:"error,omitempty"`
	ReasonCode string  `json:"reasonCode,omitempty"`
	// FailOpen is true when the response was synthesized due to a network error
	// and FailClosed is false. Callers may check this field to log or monitor.
	FailOpen bool `json:"failOpen,omitempty"`
}

// VerifyOptions are optional per-request parameters.
type VerifyOptions struct {
	ClientIP  string
	UserAgent string
}

// ReasonCode constants mirror the Go backend reason codes.
type ReasonCode string

const (
	ReasonMissingToken    ReasonCode = "missing_token"
	ReasonInvalidSiteKey  ReasonCode = "invalid_site_key"
	ReasonInvalidSecret   ReasonCode = "invalid_secret"
	ReasonSiteDisabled    ReasonCode = "site_disabled"
	ReasonInvalidSig      ReasonCode = "invalid_signature"
	ReasonTokenExpired    ReasonCode = "token_expired"
	ReasonSiteKeyMismatch ReasonCode = "site_key_mismatch"
	ReasonTokenUsed       ReasonCode = "token_already_used"
	ReasonBindingMismatch ReasonCode = "binding_mismatch"
	ReasonInternal        ReasonCode = "internal_error"
)
