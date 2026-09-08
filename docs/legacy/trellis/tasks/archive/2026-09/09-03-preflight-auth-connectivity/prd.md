# 扫描前鉴权连通性预检

## Goal

当外部调用 `jungle_happy_scan` 或 `jungle_happy_scan_lite` 时，先确认原始请求中的登录状态仍然有效，再开始正式漏洞扫描。这样可以避免原始鉴权信息已经失效，却被当成有效基线，导致未授权场景提前失去判定价值。

## Background and confirmed facts

- 当前同步处理链路已经执行 `Plan`、原始请求连通性检查、`CreateWithPreflight` 和终态结果返回：[internal/api/server.go:763-827]。
- `CheckConnectivity` 发送未修改的原始请求，并复用成功响应作为正式扫描基线：[internal/engine/manager.go:384-417]、[internal/engine/manager.go:496-499]。
- 当前连通性检查只报告网络/HTTP 请求是否完成；`jungle_happy_scan` 尚未因原始响应命中登录失败特征而停止。
- 未授权插件已经通过 `diff.LikelyAuthDenied` 跳过本身已是鉴权拒绝的基线；该判定识别 `401/403` 和全局 `denied_patterns`：[internal/plugin/unauthorized.go:15-20]、[internal/diff/diff.go:339-379]。
- `denied_patterns` 已在持久配置页的“响应语义”区域维护；配置由 `GET/PUT /api/v1/config` 读写：[internal/api/web/index.html:369-386]、[internal/api/web/app.js:123-133]、[internal/api/server.go:509-564]。
- 同步逻辑同时由 V1、V2 和根路径兼容别名承载；普通异步 `/api/v1/scan`、重放接口和 V3 WEB 代理扫描是不同入口：[internal/api/server.go:102-112]。

## Requirements

- **R1 — 入口范围：** 只在 `jungle_happy_scan` 与 `jungle_happy_scan_lite` 两个逻辑同步接口执行鉴权预检；覆盖 V1、V2 和根路径兼容别名。不得改变普通异步扫描、手动 `/api/v1/connectivity`、重放或 V3 WEB 代理扫描的入口行为。
- **R2 — 原始请求：** 预检使用正式扫描前现有的原始请求连通性检查，保留请求中的 Header、Cookie、Query、Form、JSON、Multipart 鉴权信息及客户端 TLS 证书；不得先移除或替换会话信息，也不得为同一同步请求额外重复发送一份原始报文。
- **R3 — 鉴权拒绝语义：** 预检必须复用未授权插件的统一拒绝判定：响应状态为 `401/403`，或响应状态行/Body 命中全局 `denied_patterns`，均判定为鉴权失效。因而 `HTTP 200` 但 Body 含“登录失败”等已配置特征时，必须阻止正式扫描。
- **R4 — 非拒绝响应：** 网络请求成功且未命中鉴权拒绝语义时允许进入正式扫描；不要求命中 `success_patterns`，不凭业务成功码限制接口类型。
- **R5 — 失败短路：** 网络/TLS/报文发送失败，或鉴权预检判定失效时，不创建正式扫描任务、不发送插件请求，并返回终态失败 JSON 与空 Finding 数组。
- **R6 — 诊断结果：** 同步接口的 `connectivity` 结果增加可机器读取的网络状态、鉴权状态、失败原因和命中规则信息；鉴权失败至少能区分内置状态码拒绝和 `denied_patterns` 命中。不得把完整响应 Body 默认塞入该诊断对象。
- **R7 — 配置页面：** 继续使用持久配置页已有的登录/授权失败正则作为唯一业务拒绝规则来源。页面需明确说明该规则同时用于未授权插件和两个同步接口的扫描前鉴权预检；不新增重复的独立规则存储。
- **R8 — 不提供绕过：** 第一版不提供“忽略预检并继续扫描”的选项。
- **R9 — 兼容性：** 除同步接口新增诊断字段和鉴权失败短路结果外，保留现有 V1/V2、Full/Lite 的终态 JSON 结构；未涉及入口的行为和响应保持不变。

## Acceptance Criteria

- **AC1 (R1):** 调用 V1、V2 及根路径的 `jungle_happy_scan` 和 `lite` 时会执行鉴权预检；调用 `/api/v1/scan`、`/api/v1/connectivity`、重放或 WEB 代理扫描时不会触发新的鉴权预检流程。
- **AC2 (R2):** 预检请求仍携带原始鉴权信息和已配置客户端证书；对非幂等请求不会因为新增判定而发送第二次未修改原始请求。
- **AC3 (R3):** 目标返回 `401`、`403`，或返回 `200` 且 Body 命中“登录失败”这类 `denied_patterns` 时，同步接口返回失败、`auth_valid=false`、对应原因和命中规则，不创建任务，不发送正式插件请求。
- **AC4 (R4):** 目标返回未命中拒绝规则的 `200`、业务页面或其他 HTTP 响应时，接口继续执行正式扫描；未命中 `success_patterns` 不会单独阻止扫描。
- **AC5 (R5):** 网络/TLS 失败仍返回原有连通性失败形态；鉴权失效失败同样返回终态 `scan.status="failed"` 和空 `findings`，且不留下可轮询的扫描任务。
- **AC6 (R6):** 成功结果包含 `auth_valid=true`；拒绝结果包含 `auth_valid=false`、`reason` 和可定位的命中规则；传输失败不会伪造鉴权结论。
- **AC7 (R7):** 持久配置页可读取、编辑、保存 `denied_patterns`，帮助文案明确其被两个同步接口预检和未授权插件共同使用；保存后新同步调用立即采用新规则。
- **AC8 (R8):** 鉴权预检失败的 API 响应中不存在继续扫描或强制绕过字段/动作。
- **AC9 (R9):** V1 与 V2、Full 与 Lite 的现有 Finding 转换及 Lite 证据裁剪保持有效；异步和 WEB 相关既有测试不因该功能改变。

## Out of Scope

- 不给普通异步扫描入口增加自动鉴权预检。
- 不给手动 connectivity/replay、爆破重放、V3 WEB 自动扫描或手工资产扫描增加该门禁。
- 不建立独立的未授权规则模型、规则 API、按目标规则档案或第二套拒绝规则。
- 不使用 `success_patterns` 作为同步扫描的强制成功白名单。
- 不新增强制继续扫描、绕过鉴权失效或自动刷新业务登录态的机制。
- 不改变未授权插件移除/替换鉴权信息的正式检测步骤。

## Open Questions

无。产品范围、判定语义、失败策略、配置位置和兼容路径已确认。
