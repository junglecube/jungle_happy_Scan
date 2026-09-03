---
status: accepted
---

# Return bounded finding evidence from the Full API

The V2 Full scan API returns a finding-oriented evidence view rather than an entire response body: the response status and complete headers, plus at most 30 body lines around the evidence marker, bounded to 64 KiB. Requests follow the same evidence-first rule, clipping around the changed field when necessary; capture truncation and deliberate evidence clipping remain distinct, while callers can move from Lite to Full without adopting a new response protocol.

When no response marker is available, the view keeps the first 15 and last 15 lines. Binary bodies are represented by content type, captured length, original length, hash, and completeness instead of forced text conversion.
