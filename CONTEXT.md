# Jungle Happy Scan Context

This context defines the language used when scan traffic and evidence cross the scanner API boundary.

## Language

**Scan exchange**:
A paired application-level HTTP request and response from one scan attempt, reflecting the request actually sent and the response actually received by the scanner.
_Avoid_: Raw packet, wire capture

**Canonical scan message**:
The replayable HTTP representation of a scan exchange. It preserves complete application-level request and response content but does not promise header ordering, header casing, transport framing, compression bytes, or the original character encoding.
_Avoid_: Byte-exact raw message, network raw message

**Evidence excerpt**:
A bounded fragment selected to explain why a finding was produced. It is display evidence and is never a substitute for a complete canonical scan message.
_Avoid_: Full response, raw response
Selected request and response values are preserved verbatim; evidence rendering does not perform redaction.

**Evidence response view**:
An application-level response view containing the response status, complete response headers, and bounded body context around the evidence. It supports finding review without claiming to contain the entire response body.
_Avoid_: Full response, raw response
The legacy `redact_evidence` configuration field is retained for compatibility but does not alter this view.

**Message completeness**:
The explicit state describing whether the scanner captured the underlying message completely. It is separate from deliberate evidence-context clipping.
_Avoid_: Inferring completeness from a successful HTTP status or a missing truncation flag

**Capture truncation**:
Loss of message content because the scanner could not retain the complete request or response within its capture boundary.
_Avoid_: Evidence clipping

**Evidence clipping**:
Deliberate selection of a bounded request or response context for finding review after capture.
_Avoid_: Capture truncation
