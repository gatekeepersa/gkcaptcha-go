# gkcaptcha-go

Official Go SDK for [gkCAPTCHA](https://gatekeeper.sa) — zero external dependencies, stdlib only.

## Installation

```bash
go get github.com/gatekeepersa/gkcaptcha-go
```

## Quick Start

```go
import gkcaptcha "github.com/gatekeepersa/gkcaptcha-go"

client, err := gkcaptcha.NewClient(gkcaptcha.Config{
    SecretKey: os.Getenv("GKCAPTCHA_SECRET_KEY"),
    SiteKey:   os.Getenv("GKCAPTCHA_SITE_KEY"),
})
if err != nil {
    log.Fatal(err)
}

result, err := client.VerifyToken(ctx, captchaToken, nil)
if err != nil || !result.Success {
    http.Error(w, "CAPTCHA verification failed", http.StatusForbidden)
    return
}
```

## Configuration

```go
client, err := gkcaptcha.NewClient(gkcaptcha.Config{
    SecretKey:  os.Getenv("GKCAPTCHA_SECRET_KEY"), // required
    SiteKey:    os.Getenv("GKCAPTCHA_SITE_KEY"),   // required
    APIURL:     "https://gkcaptcha.gatekeeper.sa",    // default
    Timeout:    5 * time.Second,                     // default
    MaxRetries: 1,                                   // default
    RetryDelay: 1 * time.Second,                     // default
    FailClosed: false,                               // default: fail-open
})
```

**SecretKey** and **SiteKey** can also be provided via environment variables:

```bash
export GKCAPTCHA_SECRET_KEY="sk_live_..."
export GKCAPTCHA_SITE_KEY="pk_live_..."
```

`NewClient(gkcaptcha.Config{})` will read them automatically.

## Fail-Open vs Fail-Closed

By default (fail-open), if the gkCAPTCHA API is unreachable after retries, `VerifyToken` returns
`&VerifyTokenResponse{Success: true, FailOpen: true}` with a `nil` error — the request is allowed through.
This is the industry-standard behavior for CAPTCHAs, protecting legitimate users during API outages.

```go
// Default: fail-open (recommended)
client, _ := gkcaptcha.NewClient(gkcaptcha.Config{
    SecretKey: "sk_live_...",
    SiteKey:   "pk_live_...",
    // FailClosed: false (default)
})

result, err := client.VerifyToken(ctx, token, nil)
if err != nil {
    // Should not happen with fail-open (err is always nil)
    log.Println("unexpected error:", err)
}
if result.FailOpen {
    // Network was unavailable — request was allowed through
    log.Println("warning: gkcaptcha unreachable, fail-open applied")
}
```

```go
// Fail-closed: block on network error (high-security environments)
client, _ := gkcaptcha.NewClient(gkcaptcha.Config{
    SecretKey:  "sk_live_...",
    SiteKey:    "pk_live_...",
    FailClosed: true,
})

result, err := client.VerifyToken(ctx, token, nil)
if err != nil {
    var gkErr *gkcaptcha.GkCaptchaError
    if errors.As(err, &gkErr) && gkErr.Code == "NETWORK_ERROR" {
        http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
        return
    }
}
```

## Context Cancellation and Timeout

All methods accept `context.Context`. Set a per-request timeout via context:

```go
ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
defer cancel()

result, err := client.VerifyToken(ctx, token, nil)
if err != nil {
    var gkErr *gkcaptcha.GkCaptchaError
    if errors.As(err, &gkErr) && gkErr.Code == "CANCELED" {
        http.Error(w, "Verification timed out", http.StatusGatewayTimeout)
        return
    }
}
```

## Passing Client IP and User Agent

For accurate binding verification, pass the client's IP and user-agent:

```go
result, err := client.VerifyToken(ctx, token, &gkcaptcha.VerifyOptions{
    ClientIP:  r.RemoteAddr,
    UserAgent: r.UserAgent(),
})
```

## Error Handling

`VerifyToken` returns an error only for configuration or network issues, never for verification failures.
Check `result.Success` to determine if the CAPTCHA passed.

```go
result, err := client.VerifyToken(ctx, token, nil)
if err != nil {
    // Network/config error — log and handle
    var gkErr *gkcaptcha.GkCaptchaError
    if errors.As(err, &gkErr) {
        log.Printf("gkcaptcha error [%s]: %v", gkErr.Code, err)
    }
    return
}

if !result.Success {
    // Verification failed — reject the request
    log.Printf("captcha failed: %s (score: %.2f)", result.ReasonCode, result.Score)
    http.Error(w, "CAPTCHA required", http.StatusForbidden)
    return
}

// result.Success == true — proceed
```

### Error Codes

| Code             | Cause                                                              |
|------------------|--------------------------------------------------------------------|
| `INVALID_CONFIG` | Missing SecretKey or SiteKey, or malformed API URL                 |
| `NETWORK_ERROR`  | API unreachable after retries (only when `FailClosed: true`)       |
| `CANCELED`       | Request context was canceled or timed out before response received |

### ReasonCode Constants

When `result.Success == false`, `result.ReasonCode` explains why:

| Constant                  | Value                  | Meaning                                  |
|---------------------------|------------------------|------------------------------------------|
| `ReasonMissingToken`      | `missing_token`        | No token provided in request             |
| `ReasonInvalidSiteKey`    | `invalid_site_key`     | Site key not found or invalid            |
| `ReasonInvalidSecret`     | `invalid_secret`       | Secret key does not match site           |
| `ReasonSiteDisabled`      | `site_disabled`        | Site has been disabled in dashboard      |
| `ReasonInvalidSig`        | `invalid_signature`    | Token signature verification failed      |
| `ReasonTokenExpired`      | `token_expired`        | Token has exceeded its TTL               |
| `ReasonSiteKeyMismatch`   | `site_key_mismatch`    | Token was issued for a different site    |
| `ReasonTokenUsed`         | `token_already_used`   | Token has already been redeemed          |
| `ReasonBindingMismatch`   | `binding_mismatch`     | Token IP/UA does not match current user  |
| `ReasonInternal`          | `internal_error`       | Server-side error                        |

## Gin Middleware (copy-paste, not included in package)

Gin middleware is not shipped as part of this package (no framework dependencies).
Copy-paste this snippet into your application:

```go
// Gin middleware example (copy-paste, not included in package)
func GkCaptchaMiddleware(client *gkcaptcha.GkCaptchaClient) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("X-Captcha-Token")
        if token == "" {
            token = c.PostForm("captchaToken")
        }
        if token == "" {
            c.AbortWithStatusJSON(403, gin.H{"success": false, "error": "CAPTCHA token required"})
            return
        }
        result, err := client.VerifyToken(c.Request.Context(), token, &gkcaptcha.VerifyOptions{
            ClientIP:  c.ClientIP(),
            UserAgent: c.Request.UserAgent(),
        })
        if err != nil || !result.Success {
            c.AbortWithStatusJSON(403, gin.H{"success": false, "error": "CAPTCHA verification failed"})
            return
        }
        c.Next()
    }
}
```

Register in your router:

```go
captchaClient, _ := gkcaptcha.NewClient(gkcaptcha.Config{
    SecretKey: os.Getenv("GKCAPTCHA_SECRET_KEY"),
    SiteKey:   os.Getenv("GKCAPTCHA_SITE_KEY"),
})

r := gin.Default()
r.POST("/checkout", GkCaptchaMiddleware(captchaClient), checkoutHandler)
```

## Verification

```bash
go vet ./...
go test ./... -v
```

## License

MIT
