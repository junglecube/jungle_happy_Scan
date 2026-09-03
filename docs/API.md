# HTTP API 使用说明

服务默认地址：`http://0.0.0.0:8888`。API 使用 JSON，不需要 API Key。

V3.5保留V3.4的专用HTTP回连端口：它支持`GET`、`HEAD`和最大64 KiB的`POST`。回调Token可以位于`/api/v1/callback/<token>`、`/callback/<token>`的后续追加路径中，也可以位于Query；只有当前进程已注册的一次性Token才会命中。成功响应包含Token和专属响应标记，供SSRF插件区分“服务端读取回连响应”与普通输入反射。

## V3 WEB 扫描接口

V3 把浏览器手工代理捕获与原有单报文扫描分开命名；下列接口不会改变 V1/V2 的请求或响应结构：

- `POST /api/v3/web-scans`：创建并启动 WEB 扫描任务；
- `GET /api/v3/web-scans`：列出当前进程内的 WEB 扫描任务；
- `GET /api/v3/web-scans/{id}`：读取任务、代理监听、计数和轻量状态摘要；
- `DELETE /api/v3/web-scans/{id}/proxy`：仅关闭代理监听和现有隧道，不取消扫描、不删除接口资产与漏洞结果；
- `DELETE /api/v3/web-scans/{id}`：停止代理、取消排队扫描并删除任务；
- `GET /api/v3/web-scans/{id}/assets`：读取已去重的接口资产；
- `GET /api/v3/web-scans/{id}/assets/{asset_id}`：读取接口请求、响应、状态和 Finding；
- `POST /api/v3/web-scans/{id}/assets/{asset_id}/scan`：手工重新投递该接口。
- `PUT /api/v3/web-scans/{id}/interception`：运行时启停请求/响应拦截；
- `GET /api/v3/web-scans/history/assets`：跨全部保留任务分页查询历史接口摘要；
- `GET /api/v3/web-scans/history/findings`：跨全部保留任务查询轻量漏洞摘要；
- `DELETE /api/v3/web-scans/history/assets`：清空全部历史接口与漏洞，Body必须包含`{"confirm":"CLEAR_ALL_HISTORY_ASSETS"}`，不会停止代理；
- `GET /api/v3/web-scans/{id}/interceptions`：读取待处理项和有界处理历史；
- `GET /api/v3/web-scans/{id}/interceptions/{intercept_id}`：读取完整 Raw 报文；
- `POST /api/v3/web-scans/{id}/interceptions/{intercept_id}/forward`：原样放行；Body 传 `{"raw":"..."}` 时修改后放行；
- `POST /api/v3/web-scans/{id}/interceptions/{intercept_id}/drop`：丢弃请求或响应。
- `GET /api/v3/proxy-ca`：下载当前 HappyScan HTTPS 代理 CA（PEM）。

V3.1曾使用`browser-heartbeat`和`browser-close`管理页面租约。V3.2保留这两个路径作为兼容空操作，但前端不再调用；浏览器刷新、关闭、后台冻结或心跳丢失不会停止代理或删除记录。任务只能通过明确的代理停止、任务删除或进程关闭改变生命周期。

V3.3管理页面使用历史分页接口展示本机恢复目录中的全部接口。页面通过`GET /api/v3/web-scans/history/changes?since={revision}&wait=1`等待最长25秒的全局资产变化通知；人工拦截另使用`GET /api/v3/web-scans/{id}/interceptions?since={revision}&wait=1`，队列变化立即返回且只传输待处理摘要。任务摘要额外返回`asset_revision`、`progress_revision`、`finding_revision`和`interception_revision`，用于局部刷新。`GET /api/v3/web-scans/history/findings`默认返回漏洞分组；传入`group`才返回该组受影响接口摘要。

创建任务的主要字段为：

```json
{
  "name": "CTP 测试站点",
  "target_url": "http://test.example.internal/",
  "scope_hosts": ["test.example.internal"],
  "proxy_listen": "0.0.0.0:8083",
  "scan_mode": "normal",
  "plugins": [],
  "auto_scan": true,
  "filter_static": true,
  "static_extensions": ["avif", "wasm"],
  "intercept_tls": true,
  "client_tls_file": "/opt/jungle_happy_Scan/config/client_tls_files/client.p12",
  "client_tls_password": "only-for-this-create-request",
  "intercept_requests": true,
  "intercept_responses": true,
  "intercept_timeout_seconds": 60,
  "intercept_on_timeout": "drop",
  "max_pending_intercepts": 50
}
```

`target_url`可以填写完整HTTP/HTTPS URL，也可以留空或填写`*`创建全局被动代理。全局作用域强制使用`scan_mode: "passive"`、只允许被动插件，并要求`proxy_listen`使用本机环回地址；它会转发所有Host的浏览器流量、捕获和去重普通HTTP接口，并基于已经经过代理的请求/响应完成被动分析，不发送额外Payload或重复业务请求。全局作用域下`scope_hosts`被规范化为`["*"]`。Normal/Deep仍必须配置明确目标范围。

浏览器应把HTTP代理配置为页面返回的服务器IP和端口。环回监听时，测试范围外HTTP/CONNECT会直接通过但不缓存、不拦截、不建资产、不扫描；非环回监听仍拒绝范围外Host以避免开放代理。任务对单任务资产数量、报文大小、CONNECT连接数和扫描队列设置硬上限。

V3.3的任务详情接口只返回状态、计数和细粒度Revision；接口列表支持`page`、`page_size`（最高100）、`q`和`status`查询参数。`GET /api/v3/web-scans/{id}/findings`返回不含完整Evidence的站点Finding摘要，完整Raw请求、响应和证据仅由单接口详情端点按需返回。任务恢复文件位于安装目录`var/webscan_state`，进程重启后任务以已停止状态恢复。

V3.5 的 `intercept_tls=true` 仅对作用域内 HTTPS 启用中间人解密。先下载 `GET /api/v3/proxy-ca` 返回的 CA 并在浏览器信任它；之后范围内 CONNECT 会签发目标 Host 证书，解密后的 HTTP/1.1 请求进入与普通 HTTP 相同的转发、双向拦截、资产和扫描链路。未启用解密或范围外 CONNECT 继续透明隧道，不保存 TLS 明文。超过 10MB、流式响应、WebSocket 和不可安全编辑的二进制不会进入可编辑路径。

`client_tls_file` 可选择 HappyScan 服务器上的 PEM/PFX/P12 客户端证书，只能与 `intercept_tls=true` 一起使用，并只用于代理到目标站点的上游 mTLS 握手；浏览器仍只需信任代理 CA。`client_tls_password` 只用于本次创建请求的 PFX/P12 解析，不会出现在任务详情、恢复文件、日志或漏洞报告中。

任务热摘要保存在当前进程内，完整接口快照异步保存到本地恢复目录；进程重启后可查看恢复任务，但代理不会自动重新监听。明确删除任务时，内存数据与对应恢复目录一起删除。V3 API 不替代下面的 V2 稳定同步接口。

## V2 稳定同步接口（新调用方推荐）

- `POST /api/v2/jungle_happy_scan`
- `POST /api/v2/jungle_happy_scan_lite`
- `GET /api/v2/plugins`

V2.4 同步接口保留 `http`、`scan_type`、`scheme`、`host`、可选 `client_tls_file` 与 `client_tls_password`；只传 `http` 时仍默认 Normal 与 Auto。V2 返回使用 `api_version: "2.0"`（接口主版本保持兼容）、`rule_pack_version: "2.4.0"` 和当前持久规则内容的 `rule_pack_digest`，并将机器字段与中文展示字段分离：

```json
{
  "api_version": "2.0",
  "rule_pack_version": "2.4.0",
  "rule_pack_digest": "sha256:0123456789abcdef01234567",
  "findings": [{
    "severity": "high",
    "severity_label": "高危",
    "confidence": "certain",
    "confidence_label": "已确认",
    "category": "confirmed",
    "category_label": "确认漏洞",
    "score": 93,
    "correlation_id": "corr_0123456789ab",
    "evidence": [{
      "strength": "L4",
      "request": "GET /api/user?id=1 HTTP/1.1\r\nHost: test.example.local\r\n\r\n",
      "response": "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n...evidence context...",
      "response_status": 200,
      "response_truncated": true,
      "response_capture_truncated": false,
      "response_context_clipped": true,
      "response_context_strategy": "marker_lines"
    }]
  }]
}
```

上述英文均为 V2 API 机器字段，不能翻译后传输：`severity` 的 `info|low|medium|high|critical` 依次展示为**提示/低危/中危/高危/严重**；`confidence` 的 `tentative|firm|certain` 依次展示为**待确认/较确定/已确认**；`category` 的 `confirmed|probable|exposure|informational|unknown` 依次展示为**确认漏洞/疑似漏洞/配置暴露/信息提示/未知**。本文其余说明统一使用中文展示值。`evidence.strength` 为 L1–L5：L1 被动指标、L2 差分启发式、L3 唯一错误/指纹、L4 成对或重复确认、L5 一次性回连或执行级证据。L5 会参与可信分计算，不会再把严格回连证据降为普通疑似。

V2 Full 的 `evidence.request` 和 `evidence.response` 是漏洞证据视图，不承诺返回完整正文：响应保留状态行和全部响应头，正文优先保留关键 marker 上下各 30 行（含命中行最多 61 行），最多 64 KiB；没有显式 marker 时先根据当前响应与代表性基线的实际差异定位，再使用头 15 行和尾 15 行的 markerless 兜底。单行超长正文使用围绕 marker 的 UTF-8 安全字符窗口，二进制正文返回类型、长度、SHA-256 和完整性描述。`response_context_clipped` 表示展示视图被主动裁剪，`response_capture_truncated` 表示扫描器未能完整捕获目标响应；为兼容旧调用方，`response_truncated` 在任一情况发生时均为 `true`。请求具有对应的 `request_context_*` 字段。Lite 版本仍去掉 `request`、`response`，保留摘要、命中窗口、截断标记、指标与证据强度。原 V1 接口继续兼容中文字段。

## 创建扫描

`POST /api/v1/scans`，兼容别名 `POST /api/v1/scan`。

```json
{
  "http": "GET /api/user?id=1 HTTP/1.1\r\nHost: test.example.local\r\nCookie: JSESSIONID=abc\r\n\r\n",
  "scheme": "auto",
  "scan_type": ["unauthorized", "sqli", "sensitive_data"]
}
```

字段：

- `http`：必填，Burp Suite Raw HTTP 报文，最大 5 MB；也接受别名 `http_request`。
- `scheme`：可选，`auto`、`http` 或 `https`。默认 `auto`；固定先尝试 HTTP，连接或协议失败后再尝试 HTTPS，并让本次扫描继续沿用成功协议。
- `scan_type`：必填，插件 ID 数组；也接受别名 `plugins`。`["all"]` 运行全部插件。
- `mode`：仅为 V1 客户端兼容而继续接受 `passive`、`normal`、`standard` 或 `deep`（也接受别名 `scan_mode`），不再改变所选插件的 Payload 或执行逻辑。新调用方应省略此字段。
- `client_tls_file`：可选，扫描器服务器上的 PEM/PFX/P12 绝对路径。PEM 文件必须同时包含客户端证书链和未加密私钥。
- `client_tls_password`：可选，仅用于 PFX/P12；不写入持久配置、日志或漏洞报告。

Web 页面只提交勾选后的插件 ID：Passive、Normal、Deep 是快捷勾选预设，Custom 是手工组合。Normal 选择全部被动插件，以及 XSS、文件读取、文件上传、异常信息泄露、未授权、CORS、SQL 注入、XXE、短信漏洞；Deep 选择全部 52 个插件。时间盲注、OAST、编码绕过、上传执行确认等高成本能力有独立插件 ID，可在 Custom 中直接增减。

响应状态为 `202`：

```json
{"scan_id":"scan_...","status":"queued"}
```

## 扫描前计划

`POST /api/v1/plan` 使用与扫描接口完全相同的请求 JSON，但只解析报文并生成执行计划，不访问目标。响应包括：

- `discovered_points`：发现的可变异输入点数。
- `estimated_requests`、`request_budget`、`estimated_seconds`：预计请求、当前配置预算和估算耗时。
- `complete_within_budget`：当前预算是否足够完整执行适用插件。
- `plugins`：逐插件 `planned`、`partial` 或 `skipped` 状态、适用性原因、预计请求和公平分配预算。

```bash
curl -sS http://127.0.0.1:8888/api/v1/plan \
  -H 'Content-Type: application/json' \
  --data @scan.json
```

## 进度与结果

- `GET /api/v1/scans/{scan_id}`：状态、阶段、百分比、请求数、错误数和耗时。
- `GET /api/v1/scans/{scan_id}/findings`：当前或最终结果。
- `GET /api/v1/scans/{scan_id}/result`：与 findings 相同的兼容结果接口。
- `GET /api/v1/scans/{scan_id}/events`：SSE；事件包括 `snapshot`、`progress`、`finding`、`warning`、`done`。
- `POST /api/v1/scans/{scan_id}/cancel`：取消任务。
- `DELETE /api/v1/scans/{scan_id}`：立即删除内存任务和结果。

任务状态：`queued`、`running`、`completed`、`failed`、`cancelled`。

V2.4 的 `progress` 使用请求级字段：

- `planned_requests`：适用插件计划请求槽位；
- `resolved_requests`：已发送或因证据提前收敛而明确裁掉的槽位；
- `requests_skipped`：提前收敛裁掉的槽位；
- `requests_sent`：传输层实际发送数（还包含基线请求）；
- `percent`：基线阶段占 0%–10%，扫描阶段按 `resolved_requests / planned_requests` 映射到 10%–99%，终态为 100%。

`completed_checks`、`total_checks` 为兼容旧客户端保留，在 V2.4 中分别镜像 `resolved_requests`、`planned_requests`。V2.4 还通过逐插件覆盖率和进度区分 `adaptive_pruned`、`mutation_failed`、`budget_skipped`；它们都能让终态进度完成，但后两类会使插件覆盖状态为部分，不能被理解为“已经测过且无漏洞”。

V1.3 的任务对象还包含：

- `coverage.complete`：适用插件是否全部在预算内完成。
- `coverage.plugins`：每个插件的适用性、跳过原因、插入点、预计请求、分配预算和实际请求。
- `correlations`：同一输入点上的多类独立安全信号关联，包含关联 ID、风险族和对应 Finding ID。

当 `status=completed` 但 `coverage.complete=false` 时，结论只覆盖已执行范围，不能将未执行部分理解为安全。

## 单接口同步扫描（推荐给外部调用方）

`POST /api/v1/jungle_happy_scan`，兼容短路径 `POST /jungle_happy_scan`。

同步接口会先发送一次未修改的原始报文进行连通性检测。Auto 按 HTTP→HTTPS 尝试；成功响应会直接复用为第一个扫描基线，避免状态变更接口被原样重复调用。若两个协议都失败，接口直接返回 `scan.status="failed"`、中文 `scan.error`、空 `findings` 和 `connectivity.ok=false`，不会创建或执行扫描任务。

该接口使用独立、精简且严格的入参；只传 `http` 即可完成 Normal 扫描：

- `http`：必填，完整 Burp Raw HTTP 报文；不再接受 `http_request` 别名。
- `scan_type`：可选数组，省略或传空数组时默认 `normal`。仅传 `["passive"]`、`["normal"]` 或 `["deep"]` 时使用对应预设；否则数组中的每一项都按插件 ID 处理，只运行明确传入的插件。
- `scheme`：可选，`auto`、`http`、`https`，默认 `auto`。
- `host`：可选的域名到 IP 映射对象，例如 `{"test.icbc.com":"122.223.22.22"}`。连接使用指定 IP，但原始 Host Header 和 HTTPS TLS SNI 仍保留域名；不修改系统 hosts，也不执行外部 DNS。该参数不能与显式 HTTP 代理同时使用。
- `client_tls_file`：可选，扫描器服务器上 PEM/PFX/P12 文件的绝对路径。前端上传文件后会返回并使用该路径，服务器保存时保留原文件名。
- `client_tls_password`：可选，PFX/P12 密码；PEM 不使用此字段。密码只存在于当前请求和扫描所需内存中。

不接受 `mode`、`scan_mode`、`plugins` 等额外字段；传入会返回 `400`。该接口在内部创建任务、等待扫描到达终态，然后一次性返回最终状态和漏洞数组，不需要调用方再轮询进度接口。

客户端 TLS 示例：

```json
{
  "http": "GET /secure/query HTTP/1.1\r\nHost: test.icbc.com\r\n\r\n",
  "scheme": "auto",
  "client_tls_file": "/opt/jungle_happy_Scan/config/client_tls_files/client.pfx",
  "client_tls_password": "pfx-password"
}
```

Auto 仍按 HTTP→HTTPS 尝试：HTTP 阶段不会使用证书；切换到 HTTPS 后使用客户端证书，并在后续扫描中沿用成功协议。上传接口为 `POST /api/v1/client-tls-files`，使用 `multipart/form-data`、文件字段名 `file`，只接受 `.pem`、`.pfx`、`.p12` 且最大 2 MiB；返回 `client_tls_file` 绝对路径。

预设最终也会在服务端展开为插件 ID。`normal` 与 `deep` 之间不存在另一层不可见 Payload 强度：同一插件无论通过预设还是显式 ID 选中，行为完全相同。

Normal 预设：

```json
{
  "http": "POST /api/query HTTP/1.1\r\nHost: test.example.local\r\nContent-Type: application/json\r\n\r\n{\"id\":1}"
}
```

上例自动使用 `scan_type=["normal"]` 和 `scheme="auto"`。

指定域名解析：

```json
{
  "http": "GET /api/query?id=1 HTTP/1.1\r\nHost: test.icbc.com\r\n\r\n",
  "host": {"test.icbc.com": "122.223.22.22"}
}
```

只运行指定插件：

```json
{
  "http": "GET /api/query?id=1 HTTP/1.1\r\nHost: test.example.local\r\n\r\n",
  "scan_type": ["sqli", "error_disclosure"],
  "scheme": "auto"
}
```

```bash
curl -sS --max-time 600 http://127.0.0.1:8888/api/v1/jungle_happy_scan \
  -H 'Content-Type: application/json' \
  --data @scan.json
```

```json
{
  "scan": {
    "scan_id": "scan_...",
    "status": "completed",
    "elapsed_ms": 1260,
    "findings_count": 1,
    "progress": {"percent": 100, "requests_sent": 9}
  },
  "connectivity": {
    "ok": true,
    "scheme": "http",
    "auto_fallback": false,
    "elapsed_ms": 12,
    "status_code": 200
  },
  "findings": []
}
```

HTTP 请求正常等待到任务终态时返回 `200`；即使任务状态为 `failed` 或 `cancelled`，也会保留 `scan.error`、告警和已产生的结果，因此调用方必须检查 `scan.status`。没有漏洞时 `findings` 固定为 `[]`。客户端中断同步连接时，扫描器会取消对应任务。

同步扫描可能持续数分钟。经过 Nginx、负载均衡或 SDK 调用时，应将读取超时设置为大于最大扫描时间（例如 Nginx `proxy_read_timeout 600s`）；需要实时进度时仍建议使用异步接口。

### 精简证据同步扫描

`POST /api/v1/jungle_happy_scan_lite`，兼容短路径 `POST /jungle_happy_scan_lite`。

入参与 `jungle_happy_scan` 完全一致，包括只传 `http` 时默认使用 Normal 和 `scheme=auto`。扫描流程、漏洞判定、状态及 Finding 字段也完全一致，唯一差异是返回的每条 `evidence` 不包含 `request` 和 `response`；`summary`、`response_status`、`response_excerpt` 和 `metrics` 仍保留。该精简仅作用于本次接口响应，不修改扫描任务内部保存的完整证据。

```bash
curl -sS --max-time 600 http://127.0.0.1:8888/api/v1/jungle_happy_scan_lite \
  -H 'Content-Type: application/json' \
  --data @scan.json
```

轮询示例：

```bash
curl -sS http://127.0.0.1:8888/api/v1/scans/scan_xxx
curl -sS http://127.0.0.1:8888/api/v1/scans/scan_xxx/result
```

## 辅助接口

程序同时启动两类独立离线回连监听：HTTP 默认 `0.0.0.0:61166`，LDAP/JNDI 默认 `0.0.0.0:61167`。HTTP 端口只处理 `/api/v1/callback/{token}` 和 `/callback/{token}`；LDAP 端口只完成最小匿名 Bind，以便接收包含随机 Token 的搜索 DN，绝不返回目录条目、远程类或序列化对象。两者均不暴露扫描、配置或管理接口。回连基础地址必须配置为目标服务器可访问的扫描器地址。

- `POST /api/v1/parse`：解析报文并返回插入点，不访问目标。
- `POST /api/v1/plan`：生成适用性、请求预算和预计耗时计划，不访问目标。
- `POST /api/v1/connectivity`：只发送一次原始报文，返回实际协议、状态码、耗时、Header、Body 和 Raw Response；网络失败也返回 `200`，此时 `ok=false` 并包含中文诊断。
- `POST /api/v1/replays`：高并发重放/爆破单条 Raw HTTP 报文。支持 `{{int(min-max)}}`、`{{integer(min-max)}}` 和 `{{x(dict)}}` 占位符；整数会保留补零宽度，例如 `{{int(0000-9999)}}`。没有占位符时按 `repeat` 重复原始报文。任务创建后使用下面两个接口轮询摘要和按需读取单条响应详情。
- `GET /api/v1/replays/{replay_id}`：分页读取爆破结果摘要，查询参数 `page`、`page_size`，每页最多 200 条。
- `GET /api/v1/replays/{replay_id}/results/{result_id}`：读取某条爆破结果的 Raw Response；响应内容最多保留 200KB 并带截断标识。
- `POST /api/v1/jungle_happy_scan`：同步完成创建、等待和结果读取的总接口。
- `GET /api/v1/plugins`：插件 ID、风险、默认状态、模式和说明。
- `GET /api/v1/config`：读取管理配置；动态签名 Secret 会显示为 `<redacted>`。
- `PUT /api/v1/config`：完整覆盖并原子保存管理配置；必须提供 `X-Jungle-Config-Password` 请求头，监听地址变更需要重启。
- `GET /api/health`、`GET /health`、`GET /healthz`、`GET /readyz`：健康检查。

创建扫描 curl 示例：

```bash
curl -sS http://127.0.0.1:8888/api/v1/scans \
  -H 'Content-Type: application/json' \
  --data @scan.json
```

高并发爆破 curl 示例：

```bash
curl -sS http://127.0.0.1:8888/api/v1/replays \
  -H 'Content-Type: application/json' \
  -d '{
    "scheme": "auto",
    "concurrency": 10,
    "max_requests": 10000,
    "dictionary": ["alice", "bob"],
    "http": "GET /api/user?pin={{int(0000-0003)}}&user={{x(dict)}} HTTP/1.1\r\nHost: test.example.local\r\n\r\n"
  }'

curl -sS "http://127.0.0.1:8888/api/v1/replays/replay_xxx?page=1&page_size=50"
curl -sS "http://127.0.0.1:8888/api/v1/replays/replay_xxx/results/result_1"
```

## Finding 字段

每个结果包含：

- `plugin_id`、`title`、`severity`、`confidence`
- `affected`、`description`、`remediation`
- `evidence`：保留原文的 Request、完整顺序的 Response（状态行、Header、空行、Body）、响应片段和差分指标；证据上下文不执行脱敏
- `references`、`detected_at`
- `score`：0–100 的统一可信分。
- `category`：`确认漏洞`、`疑似漏洞`、`配置暴露` 或 `信息提示`。
- `correlation_id`：存在同输入点关联发现时返回。

严重性：`提示`、`低危`、`中危`、`高危`、`严重`。置信度：`待确认`、`较确定`、`已确认`。

## 插件规则配置

`GET /api/v1/config` 返回的 `config.plugin_rules` 是插件规则表；`PUT /api/v1/config` 完整保存。示例：

```json
{
  "plugin_rules": {
    "file_read": {
      "parameter_names": ["file", "filepath", "resourceKey"],
      "paths": [],
      "payloads": [
        {
          "name": "自定义配置文件",
          "payload": "/opt/app/config.yml",
          "expected": "(?m)^spring:"
        }
      ],
      "patterns": []
    },
    "sensitive_data": {
      "payloads": [],
      "patterns": [
        {
          "name": "内部客户编号",
          "pattern": "CUST-[0-9]{8}",
          "severity": "medium",
          "confidence": "firm"
        }
      ]
    }
  }
}
```

管理页面会编辑完整配置，直接调用 `PUT` 时也必须提交完整 `Config` 对象，而不是只提交 `plugin_rules`。

保存配置示例。默认兼容密码仍为 `jungle`，共享部署应在启动前通过 `JUNGLE_CONFIG_PASSWORD` 环境变量设置独立密码；该环境变量不会写入配置或版本日志：

```bash
curl -sS http://127.0.0.1:8888/api/v1/config \
  -X PUT \
  -H 'Content-Type: application/json' \
  -H 'X-Jungle-Config-Password: jungle' \
  --data @config.json
```

`dynamic_patterns` 中每个元素是一条完整正则。它只用于响应差分前的归一化，例如将时间戳、requestId、traceId、nonce 等动态内容替换成统一占位符，避免内容每次变化导致误报；不会修改目标响应或最终证据。

`verify_tls` 是持久配置中的全局 HTTPS 证书策略，默认值为 `false`，适合使用内网私有 CA 或自签证书的目标；管理员可以在配置页面或 `PUT /api/v1/config` 中改为 `true` 以启用严格证书校验。严格校验失败不会自动降级为跳过校验。

## V1.3 协议与动态请求配置

- `transport_mode`：`normalized`、`force_http1` 或 `raw_http1`。Raw 模式不支持显式 HTTP 代理。
- `scan_header_names`：允许作为主动扫描插入点的 Header 名。
- `request_transforms`：每次发送前计算动态字段，算法支持 `timestamp`、`uuid`、`regex_replace`、`sha256`、`hmac-sha256`、`base64`；目标支持 `header:名称`、`query:名称`、`json:路径`、`cookie:名称`、`form:名称`、`multipart:名称` 和 `body`。
- `response_extractors`：从 `body` 或 `header:名称`（包括 `header:Set-Cookie`）使用正则捕获组提取值；V2 会在每次响应后更新并写回上述任一目标。Query/JSON 只替换目标值，不重排参数、字段或改写大整数。默认以原子“写入→发送→提取”流水线串行，适配一次性 CSRF/轮换 Token；只有确认目标允许并发复用时，才把全部规则设为 `"parallel_safe": true` 以恢复插件并发。
- `max_queued_scans`：有限任务队列上限。
- `global_max_concurrency`、`global_requests_per_second`：整个扫描器进程的并发与 RPS 上限。
- `per_host_concurrency`：同一目标 Host 的进程级并发上限，防止多任务把压力倍增到同一服务。
- `callback_ldap_listen`、`callback_ldap_base_url`：JNDI 安全回连监听和目标可访问 LDAP 地址；修改监听需重启。
- `callback_max_connections`：LDAP/JNDI Sink 最大并发连接数，默认 128、范围 1–4096；修改后需重启。
- `max_scans_per_minute`：单来源 IP 每分钟可创建的扫描任务数。
- `shared_service_mode`：共享服务安全模式；启用时 `allowed_hosts` 不允许为空。
- `config_write_allowed_cidrs`：允许读取和修改持久配置的管理网段；留空为兼容允许所有来源。

动态请求示例：

```json
{
  "request_transforms": [
    {
      "name": "HMAC 签名",
      "algorithm": "hmac-sha256",
      "source": "body",
      "destination": "header:X-Sign",
      "secret": "replace-me",
      "encoding": "hex"
    }
  ],
  "response_extractors": [
    {
      "name": "刷新 CSRF",
      "source": "header:X-CSRF-Token",
      "pattern": "(.+)",
      "destination": "header:X-CSRF-Token",
      "parallel_safe": false
    }
  ]
}
```

## 请求限制

- API JSON 最大约 6 MB，Raw HTTP 最大 5 MB。
- 单响应读取大小、单任务请求总数、单任务并发、全局并发任务数及 RPS 均由管理页面配置。
- 请求计划器在全局预算不足时为适用插件执行公平分配；实际覆盖情况随任务结果返回。
- JSON 中存在未知字段时返回 `400`。

连通性测试响应示例：

```json
{
  "ok": true,
  "scheme": "http",
  "auto_fallback": true,
  "status_code": 200,
  "elapsed_ms": 36,
  "url": "http://test.example.local/api/user?id=1",
  "headers": {"content-type": "application/json"},
  "body": "{\"code\":\"000000\"}",
  "raw_response": "HTTP/1.1 200 OK\r\n..."
}
```
