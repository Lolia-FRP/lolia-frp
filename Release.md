## Improvements

* Building frp from source now requires Go 1.26.10 or later, fixing GO-2026-6809 (CVE-2026-111943): crypto/x509 now distrusts compromised intermediate certificates.

## Fixes

* Replaced the test-only `gorilla/websocket` dependency with `golang.org/x/net/websocket`, removing the dependency affected by GO-2026-6278 (its v1.5.3 release is a revert to v1.5.0 and still uses `math/rand` for WebSocket mask keys).
