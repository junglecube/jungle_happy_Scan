# Implementation plan

## Checklist

1. Add focused tests for the evidence selector: marker line windows, markerless head/tail, CRLF/LF input, fewer than 30 lines, repeated markers, long UTF-8 lines, 64-KiB bounding, and binary classification.
2. Implement the shared evidence-context selector without changing the whitespace-collapsing behavior of `diff.Excerpt` used by summaries.
3. Update response evidence construction to preserve headers, use line-aware context, produce binary descriptors, and populate compatibility/completeness metadata.
4. Update request evidence formatting to preserve headers and center bounded context on the changed body span; keep redaction after selection.
5. Change the in-code and shipped TLS defaults to `verify_tls=false`, preserving explicit strict configuration and both transport modes.
6. Update V2 schema, `docs/API.md`, relevant architecture/capability documentation, and the Full/Lite wording to describe evidence views rather than complete raw messages.
7. Add API and transport regressions proving the acceptance criteria and unchanged Lite/terminal-response behavior.
8. Run focused formatting, tests, and static checks; inspect the final diff for unrelated files and generated documentation consistency.

## Validation

Use low-impact, package-scoped commands:

```bash
gofmt -w <changed-go-files>
go test ./internal/httpraw ./internal/plugin ./internal/transport ./internal/api
go vet ./internal/httpraw ./internal/plugin ./internal/transport ./internal/api
```

Before starting Go validation, check that no duplicate `go test` or `go build` process is running. Add `nice -n 10 env GOMAXPROCS=2` and `-p=1` if the environment shows resource pressure.

## Risk and rollback points

- The legacy `response_truncated` semantic broadens; protect it with explicit tests and new cause-specific metadata.
- Line selection must be UTF-8 safe and must not allocate proportional copies beyond the already captured response body.
- Redaction must remain effective for both line- and byte-window paths.
- Request change detection may be ambiguous for heavily transformed bodies; fall back to deterministic head/tail selection rather than guessing.
- Keep TLS default changes in a separate logical commit hunk so they can be reverted independently if deployment policy changes.

## Pre-start review

- Confirm PRD acceptance criteria still match the approved grilling decisions.
- Confirm only scanner product code is in scope.
- Confirm no staged/streaming response work or downstream repository edits have entered the plan.
- Confirm `implement.jsonl` and `check.jsonl` contain real spec/research context before `task.py start`.
