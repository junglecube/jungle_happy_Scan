---
status: accepted
---

# Default to insecure TLS for intranet scans

Intranet deployments default `verify_tls` to `false` so targets using private or self-signed certificates remain scannable. Strict certificate verification remains available as an administrator-controlled option; the scanner must never silently switch policies after a failed strict connection.
