# Synchronous Authentication Preflight Contract

This contract governs the authentication preflight used by the synchronous
`jungle_happy_scan` and `jungle_happy_scan_lite` interfaces.

## 1. Scope / Trigger

- Trigger: any change to the synchronous scan response, the shared
  authentication-denial predicate, or the preflight-to-baseline handoff.
- In scope: `/api/v1/jungle_happy_scan`, `/api/v1/jungle_happy_scan_lite`,
  `/api/v2/jungle_happy_scan`, `/api/v2/jungle_happy_scan_lite`, and the V1
  root-path compatibility aliases.
- Out of scope: asynchronous `/api/v1/scan` and `/api/v1/scans`, manual
  `/api/v1/connectivity`, replay, and V3 WEB proxy scanning.

## 2. Signatures

- `diff.AuthDenied(response model.Response, cfg config.Config) diff.AuthDeniedResult`
  returns the shared denial decision and stable diagnostic rule identifier.
- `diff.LikelyAuthDenied(response model.Response, cfg config.Config) bool`
  remains the boolean compatibility wrapper for plugins.
- `(*engine.Manager).CheckConnectivity(ctx context.Context, input model.ScanInput) (engine.ConnectivityResult, error)`
  sends the unmodified original request and records the transport/auth verdict
  for synchronous callers.

## 3. Contracts

`ConnectivityResult` carries these internal fields:

- `NetworkOK`: true only after the original request receives an HTTP response.
- `AuthValid`: pointer to true/false after a response is classified; nil when
  transport or request setup fails before classification.
- `Reason`: `auth_denied` for a denial, or the existing human-readable
  connectivity error for transport failure.
- `MatchedRule`: `status_code[401]`, `status_code[403]`, or
  `denied_pattern[index]`; it must never contain response content.

The synchronous `connectivity` response is additive:

- `ok`: the complete synchronous preflight gate passed.
- `network_ok`: the original request reached the target and received a
  response.
- `auth_valid`: true/false only when a response was classified; omit it for a
  transport failure.
- `reason`: empty on success, `auth_denied` for a denied response, and
  `transport_error` for a transport failure.
- `matched_rule`: present only when an authentication denial was matched.
- `error`: human-readable diagnostic on failure; it must not include the raw
  request or response body.

The original request retains all credentials and client TLS configuration for
the preflight. A successful preflight response is reused as the first scan
baseline, so a state-changing original request is not sent twice. The
unauthorized plugin later clones the request before removing or invalidating
session identifiers.

## 4. Validation & Error Matrix

| Condition | `network_ok` | `auth_valid` | Synchronous action |
| --- | ---: | ---: | --- |
| Request/TLS/transport failure | `false` | omitted | Return terminal failed JSON; create no task |
| HTTP 401 or 403 | `true` | `false` | Return terminal failed JSON; create no task |
| Any response matching `denied_patterns` in status line or body | `true` | `false` | Return terminal failed JSON; create no task |
| Any response not matching denial semantics | `true` | `true` | Create the existing task and reuse preflight as baseline |
| Invalid configured denial regex | unchanged existing behavior | unchanged existing behavior | Do not invent a new error path in preflight |

`401` and `403` are always denied without configuration. A `200` response is
not automatically accepted when its body matches a configured denial pattern.
`success_patterns` is not a required positive allow-list for this gate.

## 5. Good / Base / Bad Cases

- Good: an original request returns `200` with an ordinary business page and
  no denial pattern; the synchronous scan runs and `auth_valid=true`.
- Base: an original request returns `200` with `{"message":"登录失败"}` and
  `denied_patterns` contains `登录失败`; the response is reachable but the
  scan is stopped with `reason=auth_denied`.
- Bad: a request returns `401` or `403`, or the transport fails, and the
  handler creates a task, sends plugin probes, or reports a successful gate.

## 6. Tests Required

- Unit-test `AuthDenied` for 401, 403, body/status-line patterns, rule index,
  and the unchanged `LikelyAuthDenied` wrapper.
- API-test V1, V2, Full, Lite, and root aliases for `200 + denied_patterns`,
  401, and 403; assert terminal failure, empty findings, no task ID, and no
  plugin requests beyond the single preflight request.
- API-test a clean response for `auth_valid=true` and one original request
  reused as baseline for a non-idempotent request.
- API-test that manual `/api/v1/connectivity` keeps its network-only response
  contract and async `/api/v1/scan` remains available for the same denied body.
- Run `go test ./...`, targeted race tests for API/engine/transport/WEB scan,
  `go vet ./...`, and `node --check` for changed JavaScript.

## 7. Wrong vs Correct

### Wrong

```go
task, _ := manager.Create(input)
// The task's baseline may already be a login-failure response.
```

### Correct

```go
preflight, err := manager.CheckConnectivity(ctx, input)
if err != nil || (preflight.AuthValid != nil && !*preflight.AuthValid) {
	// Return terminal failure and do not create a scan task.
}
task, _ := manager.CreateWithPreflight(input, preflight)
```
