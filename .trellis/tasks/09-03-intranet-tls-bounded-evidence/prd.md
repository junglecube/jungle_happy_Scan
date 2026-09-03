# Intranet TLS and bounded scan evidence

## Goal

Make HTTPS targets using private or self-signed certificates scannable by default in intranet deployments, and make the existing V2 Full scan API return compact but reviewable finding evidence without requiring downstream code changes.

## Background

- The shipped and in-code defaults currently enable certificate verification (`config/config.json:17`, `internal/config/config.go:168`). Both normalized and raw HTTP/1 transports derive `InsecureSkipVerify` from that setting (`internal/transport/transport.go:59`, `internal/transport/transport.go:283`).
- `jungle_happy_scan` waits for a terminal task and writes one JSON response; it is not a progressive response protocol (`internal/api/server.go:741`, `internal/api/server.go:814`, `internal/api/server.go:1169`).
- V2 Lite removes `evidence.request` and `evidence.response` (`internal/api/server.go:863`). V2 Full keeps them, but the response body is currently a whitespace-collapsed 4,000-character window and the request body is cut at 4,000 characters (`internal/plugin/plugin.go:234`, `internal/httpraw/request.go:291`).
- The existing `response_truncated` value only reflects transport capture truncation, so it can be false even when the evidence body was clipped (`internal/plugin/plugin.go:204`, `internal/plugin/plugin.go:235`).

## Requirements

- **R1 — Intranet TLS default:** Change the shipped and in-code default to `verify_tls=false`. Keep the existing administrator-controlled strict verification option. Never retry a failed strict request by silently disabling verification.
- **R2 — Protocol compatibility:** Preserve the current synchronous terminal JSON response. Do not add or require SSE, NDJSON, polling, or staged responses.
- **R3 — API compatibility:** Keep V2 Lite behavior unchanged. Use the existing V2 Full endpoint for bounded request and response evidence so downstream systems only need to change the called endpoint from Lite to Full.
- **R4 — Response evidence view:** Preserve the response status line and every response header value. Return at most 30 body lines centered on the first available evidence marker: 15 lines before, the matching line, and 14 lines after.
- **R5 — Markerless evidence:** If no usable marker exists or the marker is absent from the body, return the first 15 and last 15 body lines when clipping is needed.
- **R6 — Size bound:** Bound selected text body context to 64 KiB. For minified or otherwise overlong lines, select a UTF-8-safe character window around the marker; without a marker, select bounded head and tail portions.
- **R7 — Request evidence view:** Preserve the complete request line and headers. For an oversized request body, center the same 30-line/64-KiB evidence view on the changed or injected field; use the markerless head/tail rule when no changed location is available.
- **R8 — Binary evidence:** Do not coerce binary bodies into text. Return response status and headers plus a readable descriptor containing content type, captured length, original length when known, captured-content SHA-256, and capture completeness.
- **R9 — Explicit clipping semantics:** Keep legacy `response_truncated` useful to unchanged callers by setting it when either capture truncation or evidence clipping occurred. Add optional structured metadata that separately reports capture truncation, evidence clipping, selection strategy, and available line/byte boundaries. Provide equivalent request clipping metadata.
- **R10 — Scope boundary:** Modify only `jungle_happy_Scan` product code and its documentation/tests. No code changes are required in `jungle_happy_scan_batch_api` or `CyberStrikeAI`; their deployment configuration may switch from V2 Lite to V2 Full.

## Acceptance Criteria

- **AC1 (R1):** With default configuration, normalized and raw HTTP/1 scans reach an HTTPS test server using an untrusted certificate. With `verify_tls=true`, the same target fails certificate verification. No automatic fallback changes the selected policy.
- **AC2 (R2, R3):** V1/V2 synchronous scan endpoints still return one terminal JSON document, and V2 Lite still omits the evidence `request` and `response` fields.
- **AC3 (R4):** A textual response with a marker beyond the old 4,000-character boundary returns all headers and exactly the available portion of the 15-before/marker/14-after line window.
- **AC4 (R5):** A markerless textual response over 30 lines returns the first 15 and last 15 lines with an omission indicator and markerless selection metadata.
- **AC5 (R6):** A minified response larger than 64 KiB produces a valid UTF-8 evidence body no larger than 64 KiB, centered on the marker when present.
- **AC6 (R7):** A mutated request whose changed field occurs beyond the old 4,000-character boundary keeps all request headers and includes the changed field in its bounded body evidence.
- **AC7 (R8):** Binary response evidence contains no forced binary text and reports content type, captured/original lengths, SHA-256, and completeness.
- **AC8 (R9):** Tests distinguish capture truncation from evidence clipping. Legacy `response_truncated` is true for either condition, while the new metadata identifies the actual cause.
- **AC9 (R10):** Existing V2 clients can ignore all new fields. Calling V2 Full instead of V2 Lite is sufficient to receive the new evidence view.

## Out of Scope

- Byte-exact network capture, HTTP/2 frame capture, or preservation of wire-level header ordering and casing.
- Returning complete response bodies or retaining every unsuccessful probe exchange.
- New streaming/progressive scan endpoints.
- Changes to batch-adapter or CyberStrikeAI source code.
- Per-request TLS policy overrides or custom enterprise CA configuration.
