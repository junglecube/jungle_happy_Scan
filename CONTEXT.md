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

**扫描前鉴权预检**:
在同步扫描接口开始正式漏洞扫描前，使用仍保留原始鉴权信息的请求确认目标响应没有表现出登录或授权失败；预检判定鉴权失效时，不产生正式扫描结果。
_Avoid_: 未授权探测、匿名扫描

**鉴权拒绝响应**:
表示原始请求的登录状态或授权状态不可用的目标响应。它由明确的拒绝状态码或已配置的登录/授权失败特征共同定义，不能仅凭 HTTP 状态码 200 判定为成功。
_Avoid_: 网络不可达、业务失败

**同步扫描接口**:
以一个终态 JSON 响应返回扫描结果的 `jungle_happy_scan` 与 `jungle_happy_scan_lite` 逻辑接口，包括它们的版本和兼容路径别名。
_Avoid_: 异步扫描接口、WEB 代理扫描
