---
status: accepted
---

# Preserve raw finding evidence

Finding evidence keeps the selected request and response headers, body context,
and response excerpt verbatim. The legacy `redact_evidence` configuration field
remains accepted so existing configuration and callers continue to work, but it
does not alter evidence serialization. Evidence is still bounded by the
capture/context limits from ADR 0002, and deployments must restrict access to
the API and management UI because credentials and business data may be present.
