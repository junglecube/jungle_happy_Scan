# Technical design

## Boundaries

The change stays inside the scanner. Configuration owns the TLS default, the evidence builder owns response selection and compatibility metadata, and the raw-request formatter owns request selection. The synchronous API and V2 conversion layer remain structurally unchanged.

```text
HTTP transport response / mutated request
  → capture state
  → evidence context selector
  → redaction
  → model.Evidence compatibility fields + optional metadata
  → existing V2 Full terminal JSON
```

V2 Lite continues clearing `request` and `response` after evidence construction.

## TLS behavior

Change both the in-code default and shipped `config/config.json` value to `verify_tls=false`. Preserve the existing UI/configuration field and transport mapping; explicit `verify_tls=true` continues to set `InsecureSkipVerify=false`. Do not introduce certificate-error fallback logic.

Existing installations that already persist `verify_tls=true` keep their explicit value. The default change applies to fresh/default configuration rather than overwriting administrator choices.

## Evidence context selection

Introduce one reusable, deterministic text-context selector rather than extending `diff.Excerpt`, because `diff.Excerpt` intentionally collapses whitespace for compact matching summaries.

The selector accepts decoded text, an optional marker, a 30-line limit, and a 64-KiB byte limit, and returns selected text plus metadata:

- `strategy`: `marker_lines`, `head_tail_lines`, `marker_bytes`, `head_tail_bytes`, `complete`, or `binary`;
- whether evidence clipping occurred;
- total and selected line boundaries when meaningful;
- retained and available byte counts.

For marker-based text, locate the first case-insensitive marker occurrence without normalizing whitespace. Select 15 preceding lines, the matching line, and 14 following lines. If the selected lines exceed 64 KiB, take a UTF-8-safe byte window centered on the marker. If no marker is usable, select 15 head and 15 tail lines; oversized single-line content uses bounded head and tail byte segments. Insert an explicit omission notice between non-contiguous regions.

## Response evidence

`evidence.response` remains a reconstructed application-level HTTP response so unchanged consumers continue to display it: reconstructed status line, all response header values using the existing stable ordering and redaction rules, a blank line, then selected textual body or a binary descriptor.

Text selection uses the existing semantic marker obtained from evidence metrics. Binary classification should reuse an existing response-body/content-type helper if available; otherwise it must combine media-type classification with UTF-8 validity and NUL/control-byte checks. The binary descriptor reports the content type, captured bytes, `RawBytes` when known, SHA-256 of captured bytes, and whether transport capture was complete.

## Request evidence

Keep the request line and all headers. Locate the changed body area by comparing the original scan request body with the evidence request body and deriving the first meaningful changed span. Feed that span to the same selector. When the evidence request is the original request or the changed span cannot be identified, use the markerless rule.

Selection occurs before redaction so a redacted secret cannot prevent location of the evidence, but only redacted selected text may leave the evidence builder.

## Compatibility metadata

Extend `model.Evidence` with optional metadata while retaining existing fields. The exact Go representation may use a nested context struct, but the JSON contract must expose these concepts:

- request: context strategy and evidence-clipped state;
- response: context strategy, evidence-clipped state, capture-truncated state, captured bytes, original/raw bytes when known, and captured SHA-256 for binary content;
- legacy `response_truncated`: logical OR of response capture truncation and response evidence clipping.

Optional additive fields are compatible with the published V2 MCP schema because evidence objects allow additional properties. Update that schema and API documentation so new clients do not have to infer completeness from the legacy flag.

## Security and resource behavior

- Preserve existing evidence redaction for session headers, cookies, authorization values, and secret-looking body fields.
- Apply the 64-KiB limit to the selected body portion; response headers remain complete as requested.
- Hash captured bytes, not reconstructed or redacted display text, and label the hash accordingly.
- Never label evidence clipping as transport capture loss, even though the legacy summary flag reports either condition.

## Compatibility and rollback

- V2 Lite output and synchronous endpoint behavior remain unchanged.
- V2 Full callers receive different evidence body selection and additive metadata; request/response remain strings.
- Rollback is limited to restoring TLS defaults and the old evidence formatter. No persisted data migration is required.

