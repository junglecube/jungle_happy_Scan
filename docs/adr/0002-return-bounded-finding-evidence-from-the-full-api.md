---
status: accepted
---

# Return bounded finding evidence from the Full API

The V2 Full scan API returns a finding-oriented evidence view rather than an entire response body: the response status and complete headers, plus the evidence marker line and up to 30 body lines before and after it (at most 61 source lines), bounded to 64 KiB. Requests follow the same evidence-first rule, clipping around the changed field when necessary. Explicit plugin markers are preferred; when a response marker is not supplied, the selector derives the changed segment against the representative baseline before using the legacy markerless fallback. Capture truncation and deliberate evidence clipping remain distinct, while callers can move from Lite to Full without adopting a new response protocol.

When neither an explicit marker nor a response-vs-baseline difference can be located, the markerless fallback keeps the first 15 and last 15 lines. Binary bodies are represented by content type, captured length, original length, hash, and completeness instead of forced text conversion.
