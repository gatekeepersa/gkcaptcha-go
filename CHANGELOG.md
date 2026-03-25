# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-24

### Added
- Initial alpha release
- Token verification client with configurable timeout and retry
- Fail-open (default) and fail-closed modes
- Environment variable support (`GKCAPTCHA_SECRET_KEY`, `GKCAPTCHA_SITE_KEY`, `GKCAPTCHA_API_URL`)
- Zero external dependencies (stdlib only)
