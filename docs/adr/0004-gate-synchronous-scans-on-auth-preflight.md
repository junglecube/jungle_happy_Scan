---
status: accepted
---

# Gate synchronous scans on authentication preflight

The `jungle_happy_scan` and `jungle_happy_scan_lite` synchronous interfaces perform an authentication preflight with the original credentials before starting formal scanning. A transport failure or a response identified as authentication-denied by the shared `401/403` and configured denial semantics stops the scan and returns the reason; asynchronous, replay, and WEB proxy scan entry points retain their existing behavior. This boundary prevents an already-expired authenticated baseline from being mistaken for a valid baseline while avoiding a second copy of the unauthorized-response rule set.
