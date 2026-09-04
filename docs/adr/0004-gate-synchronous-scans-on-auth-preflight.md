---
status: accepted
---

# Gate synchronous scans on authentication preflight

The `jungle_happy_scan` and `jungle_happy_scan_lite` synchronous interfaces perform an authentication preflight with the original credentials before starting formal scanning. A transport failure or a response identified as authentication-denied by the shared `401/403` and configured denial semantics stops the scan and returns the reason. When the caller supplies a captured upstream response, the preflight still sends the original request and also requires the live response to reach the shared `0.80` similarity threshold; a 200 response with an empty body or empty business result therefore cannot masquerade as a valid authenticated baseline. Asynchronous, replay, and WEB proxy scan entry points retain their existing behavior. This boundary prevents an already-expired authenticated baseline from being mistaken for a valid baseline while avoiding a second copy of the unauthorized-response rule set.
