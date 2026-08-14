# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-08-14

### Features

- api: Probe backend health via grpchealth
- doctor: Add nk doctor diagnostics command
- api: Fetch service account by token id
- ssh: Verify certs are signed by the current CA key

### Bug Fixes

- install: Drop stale sslcacert pin for fedora
- tpm: Auto-recover when machine identity changed

### Security

- ssh: Reject control characters in generated config

### Refactoring

- cert: Extract x509 ca matching to internal/cert
- cli: Move command tree from main into internal/cli
- logging: Replace stdout/stderr prints with slog
- api: Drop GetAPI accessor in favor of APIURL field
- api: Dedupe login state refresh via syncUser

### Testing

- ssh: Isolate config dir in test helpers
- ssh: Fuzz certificate verification
- state: Cover identity helper methods
- api: Cover auth middleware

### Documentation

- Add package repo and hosting info to readme
- Simplify and shorten comments across packages

### Miscellaneous

- build: Add fuzz task
- Update docs
- Update comment
- docs: Tidy doc comments
- lint: Drop sloglint no-global rules

## [0.1.0] - 2026-08-08

### Features

- installer: Prefer distro packages with github fallback

### Bug Fixes

- release-tagger: Normalize v prefix before comparison

### Miscellaneous

- Cleanup changelog


