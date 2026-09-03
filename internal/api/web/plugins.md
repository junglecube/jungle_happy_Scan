# jungle_happy_Scan V2.4 插件扫描与配置手册

> 本文以 V2.4 当前代码为准，面向测试人员、规则维护人员和二次开发人员。V2.4 只改造 SQL 注入能力，其他插件沿用 V2.3。文中的阈值、请求顺序、适用条件和默认规则均来自实际实现，而不是概念性说明。

## 1. 使用边界

jungle_happy_Scan 的目标是：输入一条 Burp Suite Raw HTTP 请求，在已授权测试环境中对这一个接口及少量同源相邻路径进行扫描。它不是爬虫，不会自动遍历整个网站，也不会从一个接口推导完整业务流程。

扫描器按风险标记插件，并在 V2 内核中分四阶段执行：

- `passive`：只分析原始请求或基线响应，不发送漏洞 Payload。
- `active`：对原请求中的插入点发送变异请求。
- `state-changing`：可能创建或修改测试数据，例如文件上传。
- `adjacent-path`：会在相同 Host 上探测配置的管理或接口描述路径。

实际顺序是：被动响应分析 → 安全主动探测/相邻路径 → OAST 回连确认 → 状态变更独占。前三阶段保留 Go 并发，状态变更插件逐个独占执行。任务级并发/RPS 之外，进程还执行全局并发、单 Host 并发和全局 RPS 限制。

插件结果中的置信度含义：

- **已确认**：存在唯一 canary、稳定重复、强特征或严格差分证据（API 机器值为 `certain`）。
- **较确定**：证据较强，但仍需要结合业务语义复核（API 机器值为 `firm`）。
- **待确认**：提示性结果，通常因为缺少业务授权预期或持久化验证（API 机器值为 `tentative`）。

## 2. 四种前台扫描模式

前台提供四个彩色圆形模式按钮：

- **Passive**：勾选三个被动响应分析插件，不发送漏洞 Payload。
- **Normal**：勾选全部被动插件，以及 XSS、文件读取、文件上传、异常信息泄露、未授权、CORS、SQL 注入、XXE、短信漏洞。
- **Deep**：勾选全部 52 个插件，包括时间差分、编码绕过、OAST 和执行确认扩展插件。
- **Custom**：使用当前手工勾选组合；按钮放在最后，手工增减任何预设后自动进入 Custom。

V2.4 当前实现中，四种模式只是插件选择预设。前端提交最终 `scan_type` 插件 ID 数组；同一个插件不论由 Normal、Deep 还是 Custom 选中，都执行完全相同的请求序列。异步 API 为兼容旧客户端仍接受 `mode`，但它不会改变 Payload 强度。同步总接口继续通过 `scan_type: ["passive"|"normal"|"deep"]` 选择预设，服务端随即展开为插件 ID。

扫描中心将插件按 SQL 与查询注入、文件与 XML、身份权限与会话、代码与表达式执行、服务端请求与跳转、API/框架/协议配置、响应与业务风险分组。桌面端每行显示两个插件卡片，名称、小字说明和风险类型始终可见；窄屏自动切换为单列。该分组只影响展示，不改变插件 ID、预设或 API。

历史配置里的 Payload `mode: "deep"` 会在升级到配置版本 15 时自动迁移到显式扩展插件，例如 SQL 时间规则迁移到 `sqli_timing`、命令回连迁移到 `command_injection_oast`。新配置不要再用 `mode` 控制执行范围；应把规则加到目标插件中。

### 2.1 客户端 TLS 证书

扫描页的 HTTP 报文下方可以上传 `.pem`、`.pfx` 或 `.p12`，最大 2 MiB。服务器保存到配置文件同级的 `client_tls_files/` 目录并保留原文件名，目录权限为 0700、文件权限为 0600；同名上传原子替换旧文件。PEM 必须在同一个文件中包含证书链和未加密私钥；PFX/P12 可在页面输入密码。

证书会同时用于“测试原始报文”和正式扫描。Auto 仍先发 HTTP；如果切换到 HTTPS，TLS 握手自动携带客户端证书，后续基线和 Payload 请求沿用同一证书。PFX 密码不会写入持久配置、磁盘、日志、扫描结果或 Evidence。

外部同步接口可传：

```json
{
  "client_tls_file": "/opt/jungle_happy_Scan/config/client_tls_files/client.pfx",
  "client_tls_password": "password"
}
```

路径必须是扫描器服务器上的绝对路径，不是调用方电脑路径。扩展名必须是 PEM/PFX/P12，文件必须是普通文件且不超过 2 MiB。

## 3. 插入点发现能力

大多数主动插件使用统一插入点发现器。V2.4 支持：

- URL Query 参数，保留同名参数的 occurrence。
- `application/x-www-form-urlencoded` Form 参数。
- JSON 对象、任意层级嵌套字段、根数组、嵌套数组；字符串、数字、布尔和 null 均可变异。
- GraphQL JSON 中 `variables.*` 的嵌套变量。
- XML 文本节点、XML 属性和 CDATA。
- Multipart 普通字段、文件名和文件字段。
- URL 路径中的数字、UUID 和业务标识片段。
- 非会话业务 Cookie。
- `scan_header_names` 指定的 Header。
- 普通 Query/Form/JSON 字符串/Multipart/Cookie/配置 Header 值中包含的 JSON 或 XML；最多递归展开三层，单叶变异后按父级位置逐层写回。
- Base64/Base64URL 编码的 JSON 或 XML；解码后继续递归发现嵌套字段，修改后按原编码写回。

因此 JSON 数组和嵌套 JSON 已被支持。例如：

```json
[
  {
    "user": {
      "accounts": [
        {"id": 1, "name": "A"}
      ]
    }
  }
]
```

会生成类似 `json:[0].user.accounts[0].id` 的插入点。插件仍会依据自己的语义参数白名单决定是否使用该点。

### 3.1 全局扫描排除参数

持久配置 `excluded_parameter_names` 每行填写一个参数 Key，匹配不区分大小写。例如：

```json
{
  "excluded_parameter_names": [
    "content_string",
    "signature_raw"
  ]
}
```

命中后，该参数无论位于 Query、Form、JSON（对象、数组或嵌套对象）、Multipart 文本字段、Cookie，还是 `scan_header_names` 指定的 Header，都不会进入主动 Payload 插入点。若它本身装载 JSON/XML/Base64 文档，扫描器也不会继续展开内部字段。JSON 对象参数按完整路径的任意对象 Key 判断，例如排除 `content_string` 会同时排除 `content_string.id`、`items[0].content_string.value`。

该配置只控制主动参数变异，不会删除原始报文内容，也不会阻止未授权插件识别配置的会话凭据。不要把真实鉴权 Key 加入排除列表来代替会话配置。

### 3.2 会话 Key

`session_identifiers` 只需要配置 Key 名，不需要声明 Header、Cookie、Query、Form 或 JSON 位置。匹配不区分大小写，扫描器会在以下位置递归识别和删除/失效：

- Cookie 子项；
- 普通 Header；
- Query；
- Form；
- JSON 对象与数组中的嵌套字段；
- Multipart 普通字段。

推荐根据系统实际补充：

```json
[
  "cookie",
  "Authorization",
  "token",
  "accessToken",
  "des_sessionId",
  "sessionId",
  "JSESSIONID"
]
```

不要把普通业务字段如 `id`、`user` 配成会话 Key，否则未授权插件会删除业务输入并造成误判。

### 3.2 动态响应归一化正则

`dynamic_patterns` 用于在响应相似度计算前删除每次都会变化的片段，例如时间戳、requestId、traceId、nonce。它不是漏洞检测规则。

推荐每条正则完整匹配“字段名 + 值”，不要只匹配数字或大段正文：

```json
[
  "(?i)\\\"(?:timestamp|requestId|traceId|nonce)\\\"\\s*:\\s*\\\"?[^\\\",}\\s]+",
  "\\b\\d{4}-\\d{2}-\\d{2}[T ][0-9:.+Z-]+"
]
```

过宽会抹掉真实差异，使布尔注入、越权等插件漏报。保存失败通常是 JSON 转义或正则语法错误；反斜杠在 JSON 字符串中必须写成 `\\`。

### 3.3 成功与拒绝特征

- `success_patterns`：识别业务成功，如 `"code":"000000"`、`"success":true`。
- `denied_patterns`：识别未登录、无权限、认证失败。

这些规则直接影响未授权、CSRF、越权、GraphQL 等插件。应添加系统真实返回码或中文提示，同时避免只写过短词语，如 `error`、`fail`。

### 3.4 基线、预算和并发

每个任务需要 `baseline_samples` 个基线，默认 2 个。同步接口的连通性成功响应直接作为第一个基线，因此不会把状态变更原始请求无意义地重复发送。动态归一化后计算基线稳定度：

- 稳定度低于 `0.75`：任务产生警告；
- 部分内容差分插件要求稳定度至少 `0.85`。

V2 按被动分析、安全主动、OAST、状态变更独占四阶段运行。安全阶段在 Go goroutine 中并发，状态变更逐插件串行。任务级和进程级传输共同受：

- `max_concurrency`：单任务并发请求上限；
- `max_active_scans`：同时运行任务数；
- `max_queued_scans`：有限排队任务数；
- `requests_per_second`：单任务请求速率；
- `global_max_concurrency`：整个进程并发上限；
- `per_host_concurrency`：同一目标 Host 的进程级并发上限；
- `global_requests_per_second`：整个进程请求速率；
- `max_requests`：单任务总请求预算；
- `timeout_seconds`：每次请求超时；
- `max_response_bytes`：响应读取上限。

计划器先给适用插件分配最低公平预算，再按插件估算量和优先级分配剩余预算。结果中的 `completed`、`partial`、`failed`、`skipped` 必须结合覆盖率查看；插件异常会明确变成 `failed` 和 `coverage.complete=false`。配置 `response_extractors` 时，每次响应后都会刷新动态值并写入下一个请求。默认采用原子“写入→发送→提取”串行流水线，保证一次性 Token 正确；只有目标明确允许并发复用时，才可将全部提取规则设为 `"parallel_safe": true`，此时发送使用会话值快照恢复插件并发。

V2.3 的总体百分比按请求数计算，而不是按插件数量平均计算：

- `planned_requests`：所有适用插件计划的请求槽位总数；
- `resolved_requests`：已经真实发送，或因插件获得证据/低成本筛选未命中而确定不再发送的槽位数；
- `requests_skipped`：插件提前收敛后明确裁掉的计划请求数；
- `requests_sent`：传输层实际发出的请求数，另外包含基线请求，因此不要求与 `resolved_requests` 完全相等。

扫描阶段占总体进度的 10%–99%。若一个 SQL 参数只执行了 1 次筛选就停止，剩余计划槽位会计入“收敛跳过”，所以进度会继续前进；若插件失败、取消或预算不足，未执行请求不会伪装成已覆盖。任务只有进入最终状态时才显示 100%。

V2.3 不再单独显示“扫描覆盖率”明细框。逐个点亮的插件卡片直接合并展示：

- 插件名称与实时请求覆盖数，例如 `CORS 配置错误 3/3`；
- `运行中`、`完成`、`部分`、`失败`或`跳过`状态；
- 灰色跳过卡片下方的小字会说明不适用原因；

因此 CORS 等插件在进度区域只出现一次，例如 `CORS 配置错误 3/3`，漏洞清单仍保持独立。

动态目标支持 `header:名称`、`query:名称`、`json:路径`、`cookie:名称`、`form:名称`、`multipart:名称` 与 `body`。响应来源支持 `body` 和 `header:名称`，因此 `Set-Cookie` 可写作 `header:Set-Cookie`。Query、Form、JSON 和 Multipart 均只替换目标值：不会重新排序无关参数/字段，也不会把 JSON 超大整数转成浮点。目标前缀写错会在保存配置时直接拒绝，而不是到扫描中静默失败。

## 4. 持久配置规则通用格式

漏洞插件配置包含四类字段：

```json
{
  "parameter_names": ["id", "path"],
  "paths": ["/actuator"],
  "payloads": [
    {
      "name": "规则名",
      "kind": "插件约定类型",
      "group": "配对组",
      "payload": "{{value}}'",
      "expected": "(?i)error",
      "mode": "",
      "mime": "application/octet-stream",
      "header": "X-Test"
    }
  ],
  "patterns": [
    {
      "name": "检测特征名",
      "pattern": "(?is)Exception",
      "severity": "high",
      "confidence": "certain"
    }
  ]
}
```

通用占位符按插件支持情况展开：

- `{{value}}`：原字段值；
- `{{token}}`：每次生成的唯一随机 canary；
- `{{host}}`：原请求 Host；
- `{{callback}}`：离线回连 URL；
- `{{root}}`：XML 根元素名。

配置 JSON 中 `severity` 使用机器值 `info/low/medium/high/critical`，依次对应**提示/低危/中危/高危/严重**；`confidence` 使用 `tentative/firm/certain`，依次对应**待确认/较确定/已确认**。这些配置枚举不能翻译成中文。`mode` 仅为旧配置迁移保留，运行时忽略；新规则放入哪个插件就由哪个插件执行。新增成对规则时，`kind` 和 `group` 必须正确，否则插件无法组成一对。

---

## 5. 插件详解

## 5.1 未授权访问（`unauthorized`）

**适用场景**：基线不是未登录/拒绝响应。原始请求可以包含一个或多个会话 Key，也可以完全没有鉴权字段。

**扫描过程**：

1. 合并前台配置 Key 与报文中自动识别的 `session/token/authorization/accessToken/authKey/ticket/credential` 类字段；不区分 Header、Cookie、Query、Form、JSON、嵌套数组或 multipart。
2. 一次性删除全部识别出的会话 Key，发送匿名请求；不会只删除 Cookie 而保留 `desSessionId` 等其他有效凭据。
3. 将全部会话 Key 同时改为无效值，发送失效会话请求。
4. 两个响应都不能被 `denied_patterns` 或状态码判定为拒绝。
5. 匿名响应与基线相似度至少 `0.90`；无效会话响应至少 `0.85`。

如果完全没有发现鉴权字段，且 `authorization_expected=true`、原始响应又不是鉴权拒绝，插件直接报告“接口未携带鉴权凭据仍可访问”。由于扫描器无法替业务判断公开接口，公共接口应关闭该开关或不要选择未授权插件。

`authorization_expected=true` 表示接口按预期必须登录：结果为高危；当相似度达到 `0.97/0.95` 时为**已确认**。若关闭该开关，结果只作为需要业务确认的提示。

**配置重点**：

- `session_identifiers` 应覆盖真实会话 Key；自动识别用于补漏，但明确配置仍最可靠。
- `denied_patterns` 必须覆盖 CTP/Spring 统一认证失败码。
- `unauthorized.payloads` 中 `kind: "invalid_session"` 的第一条规则决定无效会话值。

示例：

```json
{
  "payloads": [
    {"name": "无效会话", "kind": "invalid_session", "payload": "invalid-jhs-session"}
  ]
}
```

**测试建议**：先用“测试原始报文”确认登录请求正常，再手工从 Burp 删除会话确认系统真实拒绝特征，然后补充 `denied_patterns`。

## 5.2 IDOR 对象级越权（`idor`）

**候选点**：参数语义名匹配 `parameter_names`，且值为不超过 19 位的无符号整数。

对每个值生成 `+1` 和 `-1`；原值为 0 时使用 1 和 2。候选响应必须：

- 状态码小于 400；
- 不是认证拒绝；
- 与基线相似度至少 `0.45`；
- 响应正文至少 40 字节；
- 归一化响应不能与基线完全相同；
- 若响应未明确出现候选 ID，过于相似（`>=0.98`）反而不报告。

响应 JSON/字段中明确出现新 ID 时，置信度由**待确认**提升为**较确定**。此插件只说明“相邻对象可能可读”，必须人工确认对象归属。

配置示例：

```json
{
  "parameter_names": [
    "id", "userId", "accountId", "orderId", "documentId", "recordId"
  ]
}
```

将本系统的业务主键名加入列表；不要加入金额、页码、状态等普通数字字段。

## 5.3 CSRF（`csrf`）

**适用条件**：方法为 POST/PUT/PATCH/DELETE，并且请求含 Cookie。

插件删除 `csrf_header_names` 中存在的 Header，设置恶意 `Origin` 和对应 `Referer` 后发送一次。响应需要被判为业务成功、不是认证拒绝，并且与基线相似度至少 `0.85`。

- 原请求存在 CSRF Header 且移除后仍成功：**中危、较确定**。
- 原请求本来没有 Token：**低危、待确认**，需要确认 SameSite、Origin/Referer 检查和浏览器可提交性。

配置：

```json
{
  "csrf_header_names": [
    "X-CSRF-Token",
    "X-XSRF-Token",
    "CSRF-Token"
  ],
  "plugin_rules": {
    "csrf": {
      "payloads": [
        {"name": "跨站 Origin", "kind": "origin", "payload": "https://jungle-happy-scan.invalid"}
      ]
    }
  }
}
```

Bearer-only API 通常不适用。若 CTP 使用自定义 CSRF Header，必须加入全局列表。

## 5.4 HTTP Method Override 权限绕过（`method_override`）

**适用条件**：原方法为 POST、PUT 或 PATCH；目标方法只测试 PUT、PATCH、DELETE。

每条变体先直接用目标方法请求。只有直接方法得到 405、401、403 或认证拒绝，才继续发送 Override。支持：

- Header：`X-HTTP-Method-Override`、`X-Method-Override`；
- Query：`?_method=DELETE`；
- Form：`_method=DELETE`；
- Multipart 普通字段：`_method=DELETE`。

Override 响应必须 2xx、未拒绝，并出现以下至少一种语义变化：匹配 `expected`、状态变化，或基线稳定且相似度下降。随后重复一次，第二次也要成立，两个 Override 响应相似度至少 `0.90`，才报告**高危、已确认**。

规则示例：

```json
{
  "payloads": [
    {
      "name": "Spring form DELETE",
      "kind": "form_param",
      "group": "_method",
      "payload": "DELETE",
      "expected": "(?is)(deleted|删除成功|\"status\"\\s*:\\s*\"success\")"
    }
  ]
}
```

`kind` 必须为 `header/query_param/form_param/multipart_param`；Header 规则还要填写 `header`。`group` 是参数名，默认 `_method`。

## 5.5 URL 路径归一化权限绕过（`path_normalization`）

**适用条件**：请求含可识别会话，且路径不是 `/`。

插件先删除会话发送正常路径，只有匿名正常路径被拒绝才继续。随后尝试：

- 重复首个 `/`；
- 插入 `/./`；
- 最后路径段增加 `;jhs=1`；
- 添加或移除末尾 `/`。

变体匿名响应必须为 2xx、未拒绝、与已登录基线相似度至少 `0.82`；重复请求也必须成立，且两次变体响应相似度至少 `0.90`。结果为**高危、已确认**。

此插件没有 Payload 配置，依赖 `session_identifiers` 和 `denied_patterns`。适合发现 Spring Security、网关、CTP Filter 与 MVC 路由对规范化路径理解不一致。

## 5.6 HTTP 参数污染/身份优先级混淆（`parameter_confusion`）

插件在 Query、Form、Cookie、Header 中制造同名参数，一个值为原值，一个值为唯一无效标记，并交换先后顺序：

1. 无效值在前、原值在后；
2. 原值在前、无效值在后；
3. 重复第 2 种；
4. 重复第 1 种。

要求：

- 同一顺序的两次响应相似度均至少 `0.92`；
- A 顺序接近基线至少 `0.84`；
- B 顺序接近基线不高于 `0.78`；
- A/B 相似度不高于 `0.68`，或状态码族不同。

普通参数报告**中危、较确定**；若参数名匹配会话 Key，则报告**高危、已确认**。插件固定最多检查 12 个候选，不受前台预设影响。

没有独立 Payload 配置。要提升命中率，应正确配置 `session_identifiers`，并在 `scan_header_names` 中加入网关/框架会读取的自定义 Header。

## 5.7 Mass Assignment 过度字段绑定（`mass_assignment`）

**适用条件**：POST、PUT 或 PATCH。

插件按 Content-Type 自动生成字段：

- JSON 对象：在根或配置的嵌套路径增加字段；
- JSON 根数组：对前 4 个对象元素增加字段；
- JSON 还测试 Query + JSON 混合绑定；
- Form：Form 字段及 Query + Form 混合；
- Multipart：核心插件测试 Multipart 字段；`mass_assignment_extended` 再测试 Query + Multipart；
- 其他请求只由 `mass_assignment_extended` 尝试 Query。

每条规则必须设置：

- `group`：要新增的字段路径，如 `isAdmin`、`user.role`；
- `payload`：合法 JSON 标量文本，如 `true`、`"admin"`、`731`；
- `expected`：响应中确认字段真正生效的正则。

首次和重复请求均需 2xx、匹配 Expected、未拒绝，两次响应相似度至少 `0.88`。两次响应仅回显新增字段时，只报告**低危、待确认**：它只能证明请求 DTO/响应接受该字段，不能证明数据库已经保存，也不能单独证明越权。若响应给出同源资源地址，或规则的 `header` 显式配置一个以 `/` 开头的同源复查路径，插件会再发 GET；复查响应仍匹配 Expected 时才升级为持久化**高危、已确认**。

示例：

```json
{
  "payloads": [
    {
      "name": "CTP 机构字段",
      "group": "organizationId",
      "payload": "\"jhs-org-731\"",
      "expected": "(?is)\"organizationId\"\\s*:\\s*\"jhs-org-731\"",
      "header": "/api/test-users/731"
    },
    {
      "name": "嵌套审批角色",
      "group": "approval.role",
      "payload": "\"admin\"",
      "expected": "(?is)\"role\"\\s*:\\s*\"admin\"",
      "mode": ""
    }
  ]
}
```

`header` 在这个插件中不是请求 Header 名；当它以 `/` 开头时表示管理员确认安全、且能读取刚才资源的同源验证路径。若响应本身会返回同源 Location/资源 URL，可不填。不要填写会读取其他真实用户数据的路径。

应优先配置“客户端不该控制、但响应可验证”的字段。没有可观测 Expected 的字段不会可靠报警。

## 5.8 SQL 注入（`sqli`）

SQLi 面向 PostgreSQL、MySQL、GaussDB、JDBC、MyBatis 和存储过程，不包含 SQL Server Payload，也不尝试导出数据。

扫描前会对插入点做稳定排序：Query、JSON、GraphQL Variables、Form 中的业务参数优先，Multipart、Path 次之，会话 Cookie 和通用 Header 靠后；`id/name/app/query/search/filter/where/date/time/code/account/sort/order/limit/offset/page/size` 等名称提高优先级，Token、Session、签名和 Nonce 降低优先级。排序不跳过任何参数，只让高价值参数更早获得请求预算和结果。

每个参数还会分类为 `numeric`、`date-string`、`string`、`order-by`、`limit-offset` 或 `header-path`。JSON 中只有原始类型确实是 Number 才按数值上下文处理；字符串 `"20260722"` 不会因为只含数字而误用数值 Payload。排序和分页参数仍由专项插件做更精确的语法探测。

### V2.4 准确率内核总览

V2.4 把 SQL 判断拆成四层：

1. 单引号 Gate 只判断“错误恢复分支是否值得展开”；
2. 完整的 A-B-B-A 请求组执行破坏/恢复、真假、正常/错误或控制/延时复核；
3. 数据库错误、响应差分、JSON/JSP 业务结果和时间差作为相互独立的 Oracle；
4. 根据证据强度形成疑似、多路径恢复、条件错误、布尔或时间结论。

Gate 响应不再复用为 A-B-B-A 的第一条证据。确认前先原子预留完整四请求组，预算不足时一条也不发送。Gate 没有触发时，只裁剪单引号错误恢复和条件错误分支；数值、布尔及其他上下文仍可继续，修复了“单引号不报错就完全漏扫”的问题。

Query、Form 和 Multipart 文本值新增 `number/date/bool/uuid/string` 词法类型；JSON 仍保留原生类型和无损大整数。SQL 插入点按位置、参数语义、值类型排序，高价值业务参数优先获得预算。`application/*+json` 和缺失/错误 Content-Type 但正文是合法 JSON 的请求也可以发现插入点；XML 属性变异会转义 `&"`、`<`、`>`，避免扫描器自身破坏 XML。

所有 SQL 家族插件在安全主动阶段进入同一条独占 Oracle Lane，不与其他主动插件交错。某插件因证据收敛而提前停止后，未使用预算返回任务共享池，供后续 ORDER BY、LIMIT/OFFSET 或 MyBatis 插件使用。覆盖率明确区分：

- `requests_sent`：实际发送；
- `adaptive_pruned`：证据收敛后跳过；
- `mutation_failed`：无法安全生成请求，状态为部分覆盖；
- `budget_skipped`：完整请求组预算不足，状态为部分覆盖。

### 错误型

`kind: error_break` 与 `error_repair` 按相同 `group` 配对，发送顺序为：

1. break；
2. repair；
3. repair；
4. break。

两次 break 必须出现相同检测特征，且基线从未出现该特征；两次 repair 均不能出现检测特征，与基线相似度均至少 `0.82`。repair 与 break 的相似度差至少 `0.12`，或状态码族发生变化。

如果 Spring/CTP 把数据库异常捕获并改写成普通业务 JSON，break 响应可能没有 SQL/JDBC 关键字。核心插件对此增加严格恢复差分：对 `group` 以 `quote` 开头的配对启用；基线稳定度至少 `0.85`；排除鉴权拒绝、限流和 WAF 拒绝；两次 break 状态码必须一致（允许统一异常处理包装成 500）；两次恢复响应必须非 5xx、与基线状态一致且相似度至少 `0.94`；两次 break 响应自身稳定。明显内容差要求破坏相似度不高于 `0.90` 且恢复差至少 `0.06`；对于很长的 JSP 页面，也接受“两个恢复响应归一化后与基线完全相同、两个破坏响应归一化后彼此完全相同但不等于基线”的细微稳定差异。

默认包含两类恢复配对：

- `{{value}}'` / `{{value}}''`：适合双单引号能够恢复原业务结果的上下文；
- `{{value}}'` / `{{value}}'||''||'`：适合 PostgreSQL/GaussDB 字符串拼接上下文。后一条关闭原字符串、拼接空字符串再重新打开，数据库计算后的业务值仍等于原值。

仅“原始响应与空字符串拼接响应相同”不会单独报警；还必须满足两次破坏、两次恢复的 A-B-B-A 稳定差分，并继续尝试下述常量条件错误确认。扫描器不调用 `user()`、数据库名或业务表，不提取数据。

### 条件错误差分（V2.1）

只有上述单引号破坏/双单引号恢复形成稳定信号后，核心 SQLi 才追加一个 MySQL、PostgreSQL 和 GaussDB 均可使用的条件错误对：

```text
正常：{{value}}' AND (CASE WHEN 1=1 THEN 731 ELSE EXP(720) END)=731-- 
错误：{{value}}' AND (CASE WHEN 1=2 THEN 731 ELSE EXP(720) END)=731-- 
```

发送顺序为正常、错误、错误、正常，即 A-B-B-A。两条 Payload 只有 CASE 谓词不同，不包含数据库名、表名、字段名或数据提取表达式。`EXP(720)` 用于制造只出现在错误分支的数值溢出；正常分支不会执行它。管理员仍可保留 MySQL `IF/EXP` 或 PostgreSQL/GaussDB `CASE/exp` 专属组，但核心扫描每次只选择一个条件组，避免因数据库方言扩充而线性增加请求。判定要求：

- 两次正常分支状态与基线一致、与基线相似度均至少 `0.90`；
- 两次正常分支彼此相似度至少 `0.94`，两次错误分支彼此至少 `0.90`；
- 错误分支发生稳定状态码族变化，或每轮相似度差至少 `0.12`；
- 排除 401、403、406、429 以及登录/授权失败响应；
- 数据库错误特征不能已存在于基线，且两次正常分支都不能出现该特征。

两次错误分支命中同一数据库错误特征时，报告“SQL 条件错误差分注入”，置信度为**已确认**。没有显式错误文本、但两个错误分支稳定为 5xx 时降为**较确定**。若优化器常量折叠导致正常分支也执行 `exp(720)` 并报错，正常分支无法回到基线，因此不会报警。

【持久配置】→【响应语义】中的“数据库报错特征”用于补充目标特征，每行一条 Go RE2 正则，例如：

```text
(?i)syntax error
(?i)ORA-\d{5}
(?is)numeric.{0,40}(?:overflow|out of range)
(?i)SQLSTATE\s*[:\[]?\s*22003
(?is)CTP.{0,120}(?:SQLException|数据库异常)
```

保存时服务端逐条编译；任何无效正则都会拒绝保存并指出 `sqli_error_patterns`。应填写数据库/JDBC/ORM 专属特征，不要填写泛化的 `error`、`message` 或 `500`。本栏与 SQLi 插件 `patterns` 合并参与判定，后者仍可单独配置名称、严重性和置信度。

同一响应可能同时命中 `error`、Spring 包装异常、JDBC 异常和数据库内核错误。V2.4 不采用“配置中最先出现的正则”，而是综合严重性、置信度和数据库/JDBC/MyBatis 专属性选择最高价值的共同证据；通用错误文本不会覆盖更具体的 MySQL、PostgreSQL、GaussDB 或 SQLSTATE 证据。前台简化正则的默认可信度可单独选择，建议保持“较确定”；只有管理员确认规则足够专属时才设为“已确认”。

### 布尔盲注

`boolean_true` 与 `boolean_false` 按 group 配对，顺序为真、假、假、真。仅在基线稳定度至少 `0.85` 时执行。常规阈值会根据基线稳定度自适应；此外支持“真分支完整 Body 精确回基线、假分支两次完整 Body 精确一致且不同”以及同一路径 JSON/JSP 业务结果 Oracle。常规要求包括：

- 两次真响应与基线相似度均至少 `0.88`；
- 两次假响应均不高于 `0.72`；
- 每轮真假差至少 `0.20`；
- 两次真、两次假各自相似度至少 `0.90`；
- 真响应状态码与基线相同。

### 时间盲注（独立插件 `sqli_timing`）

`time_control` 与 `time_delay` 配对，顺序为 control、delay、delay、control。`expected` 填预期秒数。两轮延时差必须同时超过：

- 1200ms；
- 预期延时的 65%；
- 基线抖动的 4 倍；

三者中的最大值。两次 control 和两次 delay 还必须各自稳定。

默认同时包含 MySQL 单引号和双引号字符串闭合时间对。双引号规则用于 `WHERE id="$id"` 一类上下文；如果 MySQL 启用了 `ANSI_QUOTES`，双引号可能按标识符处理，不能保证适用。

### ORDER BY 专项（独立插件 `sqli_order_by`）

仅扫描 `sort/sortBy/sortField/sortColumn/sortKey/order/orderBy/orderField/orderColumn/field/column/direction` 等可配置候选名。V2.4 先按参数名和值分类：

- 值为 `ASC/DESC`，或名称为 `direction/sortOrder/*Direction`：按“排序方向”处理；
- 其他候选：按“排序字段/表达式”处理。

插件不会因为正常的 `ASC/DESC` 顺序变化就报警。字段上下文使用：

```text
正常：IF(731=731,{{value}},EXP(720))
异常：IF(731=732,{{value}},EXP(720))
```

方向上下文保留原方向，并追加第二个受控排序表达式：

```text
正常：{{value}},IF(731=731,1,EXP(720))
异常：{{value}},IF(731=732,1,EXP(720))
```

正常、异常、异常、正常按 A-B-B-A 发送。正常分支必须两次回到基线，异常分支必须两次命中同类数据库错误或稳定 5xx。MySQL 使用 IF/EXP 与 SLEEP；PostgreSQL/GaussDB 使用外层 `CAST(CASE...)` 条件错误对，降低常量折叠造成的误判。ORDER BY 可能按结果行重复计算表达式，因此该插件只属于 Deep/Custom，并受任务超时和请求预算限制。

### LIMIT/OFFSET 专项（独立插件 `sqli_limit`）

仅扫描 `limit/offset/pageSize/pageNo/page/start/startRow/rowStart/rowCount/size` 等可配置候选名。默认使用：

```text
破坏：{{value}}'-- 
恢复：{{value}}-- 
```

按破坏、恢复、恢复、破坏发送。MySQL 使用上述引号/注释组；PostgreSQL/GaussDB 还使用保持分页值不变的 `CAST(CASE...)` 正常分支和稳定报错分支。两次恢复必须高度接近基线，两次破坏必须稳定触发同类数据库错误或统一 5xx。普通分页数量变化不构成证据；该插件不使用堆叠语句，也不修改数据。

### 插件拆分与默认覆盖

V2.4 的核心 `sqli` 对每个插入点先执行一层单引号筛选：

- 发送一次优先级最高的单引号破坏请求；
- 若出现基线中没有的数据库/JDBC/MyBatis 正则、HTTP 状态族变化、长业务响应明显变空，或归一化相似度不高于 `0.88`，才进入确认层；
- 鉴权拒绝、406、429、基线稳定度低于 `0.75` 不作为筛选信号；
- 筛选响应只用于适用性，不进入漏洞证据；确认层会重新原子发送完整 A-B-B-A。

进入确认层后：

- 单引号破坏/双单引号恢复按 break/repair/repair/break 独立发送 4 次；
- 仅在上一组出现稳定恢复信号时，追加条件正常/条件错误/条件错误/条件正常共 4 次；
- 原值可解析为数字时使用数值真假组；`query/search/keyword/filter/name/user/title/content` 等 MyBatis 常见模糊搜索参数使用 `LIKE '%输入%'` 边界适配组；其他参数使用普通字符串真假组，共 4 次；
- 不执行时间延迟。

请求计划会同时计入 1 条 Gate 和所有可能被发送或明确剪枝的请求槽位。Gate 干净时会剪枝单引号恢复及条件错误组，但仍执行一个上下文适配的布尔组；Gate 可疑时再按证据信号展开恢复和最多三种方言的有界条件组。一旦形成可靠证据立即停止当前点。该行为不因 Normal/Custom/Deep 改变。其余能力拆成：

- `sqli_extended`：双引号标识符、双引号字符串布尔、括号/注释、PostgreSQL CAST、额外字符串/数值布尔组；
- `sqli_timing`：PostgreSQL `pg_sleep(0/2)`、GaussDB 独立 `pg_sleep(0/2)` 与 MySQL 单引号/双引号 `SLEEP(0/2)`；
- `sqli_order_by`：只扫描排序候选参数的条件错误和时间配对；
- `sqli_limit`：只扫描分页候选参数的注释恢复/引号破坏配对。

LIKE 包裹组默认使用：

```text
真：{{value}}%' AND '731'='731' AND '%'='
假：{{value}}%' AND '731'='732' AND '%'='
```

当 Mapper 使用 `LIKE CONCAT('%', #{query}, '%')` 或等价字符串拼接时，尾部 `AND '%'='%'` 用于重新闭合框架追加的百分号和引号。仍需真、假、假、真两轮稳定差分，不会仅凭单次内容变化报告。

实际请求数是计划上限而不是强制消耗量：某插入点一旦在当前 SQL 插件内获得可靠证据，就不再继续该插件的后续组。Normal 只勾选核心 `sqli`；Deep 勾选五个 SQL 插件；Custom 可以按需增加任一专项插件。

错误正则覆盖 PSQLException、MySQL JDBC、GaussDB JDBC/内核/openGauss/GS 错误码、MyBatis/Spring 数据访问异常、CallableStatement/存储过程和通用 SQL 语法异常。GaussDB 官方确认支持 `pg_sleep(seconds)`，因此时间检测使用相同安全函数，但保留独立 group 与异常指纹。

新增规则示例：

```json
{
  "name": "CTP 字符串布尔真",
  "kind": "boolean_true",
  "group": "ctp-string-comment",
  "payload": "{{value}}' AND '731'='731'-- "
}
```

必须同时添加相同 group 的 `boolean_false`。V2.4 保存配置时会检查 SQL `kind`、非空 `group`、`{{value}}` 占位符和左右配对数量；同一 group 可以配置多对，按 JSON 数组顺序一一配对，数量不一致会拒绝保存。时间规则必须有同组 control，且 `expected` 必须大于 0、最多 10 秒。不要添加破坏数据的堆叠语句、DROP、UPDATE 或数据提取 Payload。

## 5.9 MyBatis 动态 SQL 片段注入（`mybatis_dynamic_sql`）

该插件只扫描排序列、方向、字段列表、表名和分组等语义参数。默认候选包括 `sort/order/orderBy/column/field/tableName/groupBy/direction/queryColumn`。

向原值追加唯一不存在列 `jhs_invalid_column_731`；表名参数使用 `jhs_invalid_table_731`。V2.4 原子发送两次 canary 请求，不再为恢复步骤重复发送原始 POST。两次变异必须出现相同数据库/ORM 特征，并在响应中明确出现 canary；两条已采集原始基线不能有该特征且与代表性基线相似度至少 `0.86`，两次变异相似度至少 `0.90`。报告中的基线证据带 `reused_baseline:true`。

配置示例：

```json
{
  "parameter_names": [
    "sortField", "sortColumn", "orderByClause", "tableAlias", "selectFields"
  ],
  "payloads": [
    {
      "name": "追加不存在列",
      "kind": "fragment_break",
      "payload": "{{value}},jhs_invalid_column_731",
      "expected": "jhs_invalid_column_731"
    }
  ]
}
```

检测正则必须同时覆盖 canary 和目标系统真实异常包装。例如 CTP 重新包装异常时，应通过测试响应找出稳定类名或错误码后添加 Pattern。

## 5.10 输入诱导异常信息泄露（`error_disclosure`）

该插件不是 SQLi 的替代品。它回答的是：“任意异常输入能否让后端泄露内部实现信息？”

V2.3 的核心 `error_disclosure` 对每个插入点只先尝试单引号。若第一次响应没有出现基线中不存在的 Java、Spring、ORM、SQL、路径或调试特征，该点立即停止，通常只发送 1 次。命中特征后的确认顺序：

1. 变异输入；
2. 恢复原始请求；
3. 重复同一变异。

两次变异必须出现相同特征，所有基线和恢复请求均不能出现该特征。默认检测：

- Java/Spring/MyBatis 异常堆栈；
- Jackson 参数绑定异常；
- SQL、Mapper XML、Prepared/CallableStatement 细节；
- PostgreSQL/MySQL 异常详情；
- 服务端绝对路径。

双引号、反斜杠、超大整数、非法日期和空字节等更广输入由独立的 `error_disclosure_extended` 插件执行，Deep 会勾选，Normal 默认不选。若系统主要是数值、日期或 CTP 自定义类型绑定，建议在 Custom 中同时选择扩展插件，而不是继续放大 Normal 对每个普通参数的请求量。

规则示例：

```json
{
  "payloads": [
    {"name": "CTP 类型边界", "payload": "{{value}}[]", "mode": ""}
  ],
  "patterns": [
    {
      "name": "CTP 内部异常",
      "pattern": "(?is)(com\\.icbc\\.ctp\\.[\\w.$]+Exception|CTP-[A-Z]+-\\d+).{0,500}(?:\\.java:\\d+|Mapper\\.xml)",
      "severity": "high",
      "confidence": "certain"
    }
  ]
}
```

正则应匹配真正敏感的类名、栈行、SQL 或路径，不能只匹配“系统异常”这种统一业务提示。

## 5.11 NoSQL 注入（`nosql_injection`）

JSON 点会把字符串替换为结构化对象；Query/Form 会将 `{"$ne":null}` 转换为 `name[$ne]=` 风格。

默认真假对：

- 真：`{"$ne":null}`；
- 假：`{"$eq":"__jhs_no_match_731__"}`。

使用公共成对注入引擎：真、假、假、真。基线稳定度至少 `0.85`；真响应接近基线至少 `0.86`，假响应不高于 `0.74`，差至少 `0.18`，重复一致性至少 `0.90`。

同一插件还发送 MongoDB `$where` 语法错误，两次相同错误特征才报告。默认 Pattern 也覆盖 Elasticsearch 解析异常；是否执行只取决于是否勾选 `nosql_injection`。

可根据实际文档数据库增加 operator 配对，但不要加入 JavaScript 执行、延时或数据提取表达式。

## 5.12 LDAP 注入（`ldap_injection`）

候选参数名为 user、username、uid、cn、dn、filter、search、query、email、account 等。默认使用：

- 真过滤器：`{{value}}*)(|(objectClass=*))`
- 假过滤器：`{{value}}*)(objectClass=__jhs_no_match_731__)`
- 错误探针：`{{value}})(`

错误探针需连续两次触发 `InvalidSearchFilterException` 等特征；真假差分沿用 NoSQL 的严格四请求阈值。

该插件当前没有前台 `parameter_names`，候选名由代码固定。若自研 CTP 使用特殊命名，可通过二次开发扩展 planner，或优先让字段名中保留 `filter/search/query/account` 等语义。

## 5.13 XPath 注入（`xpath_injection`）

XML 请求或 user、username、xpath、query、search、filter、name 等参数适用。默认：

- 真：`{{value}}' or '731'='731`
- 假：`{{value}}' or '731'='732`
- 错误：`{{value}}'[`

确认机制与 LDAP/NoSQL 相同。Pattern 覆盖 Java XPath、Saxon、未闭合字面量等异常。新增真假规则必须同 group，并确保真条件保持原查询语义、假条件只改变匹配结果。

## 5.14 OS 命令注入（`command_injection`）

只测试 `parameter_names` 或全局 `command_parameter_names` 命中的参数。默认候选除 cmd、command、exec 外，包含 execute、executable、program、process、script、code、expression、groovy、engine、host、ip、path、file、url、target，并显式加入 `backuppath`；字段名后缀匹配仍会识别 `backupPath`、`outputPath` 等名称。

核心 `command_injection` 使用 `kind: output`。分号基础形式为：

```text
{{value}};printf JHS_%s $(({{left}}+{{right}}))
```

扫描器随机生成 `left/right`。请求里只有两个操作数，不存在期望的 `JHS_{{sum}}`。发送顺序为变异、恢复原始、相同变异；两次变异必须出现计算结果，基线和恢复响应不得出现。完整反射 Payload 不会满足条件。插件不读取系统文件。

默认还对相同无害算术 canary 使用 `|`、`||`、`&&`、换行、反引号和 `$()` 六类 Shell 上下文。反引号与 `$()` 属于命令替换，尤其适合 `backuppath` 被拼入双引号命令参数的情况；此时分号可能只是路径字符串，而命令替换仍可能执行。

对于参数名明确属于 `cmd/command/exec/execute/executable/program/process/ProcessBuilder` 的上下文，核心插件还发送不带 Shell 分隔符的直接程序探针：

```text
expr {{left}} + {{right}}
```

该形式用于 Java `Runtime.exec(String)`、`ProcessBuilder` 或“可执行文件 + 参数”入口；期望结果 `{{sum}}` 不直接存在于请求中，仍按变异、恢复、变异三段确认。它不会对 url/path/file 等宽泛候选发送，避免把普通路径解析错误误判为命令执行。

`command_injection_timing` 使用 `delay/control` 成对规则。Shell 规则覆盖分号、管道、逻辑或、逻辑与、换行、反引号和 `$()` 的 `sleep 2/sleep 0` 对照；script/code/expression/groovy/engine 等脚本语义参数还使用 Groovy/ScriptEngine `sleep(2000)/sleep(0)`。当前实现各发送一次；延时至少比控制慢 1700ms，且控制耗时的两倍仍小于延时，报告**严重、较确定**。

`command_injection_oast` 使用 `kind: callback` 的 curl 一次性回连，覆盖分号、管道、逻辑或、逻辑与、换行、反引号和 `$()`。反引号规则会把整个参数替换为：

```text
`curl -fsS --max-time 3 '{{callback}}' >/dev/null`
```

这与 <code>backuppath=&#96;curl http://目标/&#96;</code> 的已知可利用上下文等价。目标服务器只访问随机 URL，不读取文件、不下载内容；扫描器在默认61166回连监听收到唯一Token时报告**严重、已确认**。`callback_base_url`必须是目标服务器可访问的HappyScan地址，不能保留为远程目标不可达的`127.0.0.1`。

若应用只接受特定命令上下文，可增加无害算术输出 canary。`expected` 必须使用 `{{sum}}`，并且展开后的期望结果不能直接出现在 Payload：

```json
{
  "name": "管道算术输出 canary",
  "kind": "output",
  "payload": "{{value}}|printf JHS_%s $(({{left}}+{{right}}))",
  "expected": "JHS_{{sum}}",
  "mode": ""
}
```

不要配置反弹 Shell、文件写入、网络下载或破坏性命令。

## 5.15 服务端模板注入（`ssti`）

对每个插入点、每种模板语法生成两组不同的随机整数乘法。两次响应必须分别出现对应乘积，且乘积不在 Payload 原文和基线中，才报告**严重、已确认**。固定数值偶然出现和原样反射表达式都不会命中。

可为 Thymeleaf、SpEL 或其他已知模板语法增加无副作用算术表达式；`expected` 必须是唯一且不在正常页面中的结果。避免使用类加载、反射或 Runtime 表达式。

## 5.16 XXE（`xxe`）

**适用条件**：Content-Type 含 XML，或 Body 以 `<` 开始；必须能识别根节点和叶子/CDATA 节点。原报文已包含 DOCTYPE 时不二次注入，避免构造无效 XML。

插件对每个 XML 节点分别创建一条变体，只替换当前 occurrence，保留原 XML 声明、其他节点、命名空间、SOAP 包络和 CDATA，不再一次替换全部叶子。

默认规则：

- `inline`：内部实体展开，响应出现唯一 token，**高危、较确定**；
- `file`：`file:///etc/passwd`，响应匹配 root 指纹，**严重、已确认**；
- `callback`：位于 `xxe_extended`，使用 `callback_base_url`，收到唯一回连为**严重、已确认**。
- `xinclude_file`：位于 `xxe_extended`，仅替换一个节点为 XInclude `file:///etc/passwd`，强指纹命中为**严重、已确认**。

示例：

```json
{
  "name": "内部实体",
  "kind": "inline",
  "payload": "<?xml version=\"1.0\"?><!DOCTYPE {{root}} [<!ENTITY jungle_happy_scan \"{{token}}\">]>",
  "expected": "{{token}}"
}
```

`expected` 是正则。主程序默认额外监听 `0.0.0.0:61166`，只开放一次性回连接口。`callback_base_url` 必须填写目标服务器能访问的扫描器地址，例如 `http://10.0.0.20:61166`；不依赖公网服务。

## 5.17 任意文件读取（`file_read`）

只扫描 `parameter_names` 命中的参数。每个 Payload 的 `expected` 是文件内容强指纹正则。首次命中后会用同一 Payload 再请求一次；两次都命中且基线不命中才报告严重/已确认，避免把偶发错误页中的 `localhost`、`Linux` 等普通文字当作文件读取。

核心 `file_read` 默认规则：

- `/etc/passwd`：目录穿越、绝对路径，匹配 root 账号记录；
- `/etc/hosts`：目录穿越、绝对路径，匹配完整 loopback/localhost 行；
- `/proc/version`：目录穿越、绝对路径，匹配 Linux 内核版本行；
- `/etc/os-release`：目录穿越、绝对路径，同时匹配发行版名称与 ID。

`file_read_encoded` 增加 passwd、hosts、proc/version 双重编码穿越、`....//` 非标准路径归一化和 `file:///etc/hosts` 变体。目标服务器统一为 Linux，不包含 Windows `win.ini` 或 Windows 路径规则。

增加应用文件探测时，优先使用无敏感内容且稳定的系统文件，如：

```json
{
  "name": "Linux hosts",
  "payload": "../../../../../../etc/hosts",
  "expected": "(?m)^\\s*127\\.0\\.0\\.1\\s+localhost\\b",
  "mode": ""
}
```

不要把 Expected 写成 `root`、`localhost`、`Linux` 这种过短字符串。新增系统文件时应同时配置该文件独有的行结构，并保留重复确认。

## 5.18 危险文件上传（`file_upload`）

**适用条件**：Multipart 请求中存在文件 Part。

插件按照 `Content-Type` 中的 boundary 解析并重建标准 Multipart Part。普通危险后缀规则只替换文件名和 MIME，原文件内容逐字节保留，从而与 Burp 中“只改扩展名”的手工测试保持一致；只有独立的 `execute_canary` 无害执行确认规则会替换内容。其他文本字段和文件 Part 保持不变。它不接受拼错的 `Content-Disposition`。V2.1 会枚举并分别测试请求中的每一个文件 Part，不再只检查第一个文件字段；报告的 `affected`、`file_field`、`file_index` 和 `original_filename` 可定位实际被接受的字段。

普通规则首先只改标准 `filename` 参数。若原始 `name` 自身也形如文件名（例如 `name="020079103915427_0.jpg"`），且标准探针未形成证据，插件会额外执行一次兼容探针，同时把 `name` 和 `filename` 改为相同危险文件名，用于兼容错误地以 field name 判断扩展名的旧 Servlet。响应应满足以下之一：

- 匹配 `expected`；
- 响应包含文件名；
- 响应新增 `filename/文件名` 字段，并且服务端重命名后的文件仍保留本次测试的危险后缀；
- `execute_canary` 或文件名模板确实发送了随机 token，并且响应包含该 token。

`UploadFileTypeNot`、文件类型不允许/不支持等拒绝特征会覆盖宽泛的 HTTP 200 或成功文本。`expected` 还必须是相对原始基线新增的信号，避免接口原本就返回 `code=200` 导致误报。仅命中宽泛成功正则时为**中危、待确认**；响应明确返回原文件名、相同危险后缀的服务端重命名文件、canary 或同源路径时提升为**高危、较确定**。重命名证据兼容 `filename：“xxx.jspx”`、普通 JSON、被转义后嵌在字符串中的 JSON，以及旧 CTP/Servlet 文本包装；必须在 `filename/new_filename/saved_filename/文件名` 标签附近出现本次测试的精确危险后缀。若旧 Servlet 已保存文件但随后由统一异常包装成 HTTP 500，该强重命名证据仍可成立；401、403、406、429 和明确拒绝文本始终不会报警。若上传响应提供同源相对 `Location` 或 JSON `url/path/location/downloadUrl`，插件会读取该地址；能读到 canary 时为**高危、已确认**。

`file_upload_execution` 使用 `kind: "execute_canary"`：上传仅含随机整数乘法的 JSP。乘积不存在于上传源码；只有访问同源路径后出现正确乘积，且没有返回 `<%=` 源码，才报告**严重、已确认（L5）**。它不执行命令、不读文件、不出网。

规则示例：

```json
{
  "name": "JSP 文件",
  "payload": "jungle-happy-scan-canary.jsp",
  "mime": "application/octet-stream",
  "expected": "(?i)(上传成功|保存成功|\"code\"\\s*:\\s*\"?000000)"
}
```

核心插件默认测试 `.jsp`、`.jspx`、`.php`、`.exe`、`.sh`、`.html` 和 `.py`；`file_upload_execution` 包含双扩展 JSP 和 JSP 无害算术执行确认。可根据目标白名单补充 `.war`、模板文件或其他危险业务扩展名，但不应在文件内容中配置命令、文件读取或网络操作。

本次 V2.1 修复将内部配置结构升级到 19：服务器第一次使用新二进制启动时，会在保留管理员自定义规则的前提下，把缺失的默认 `.jspx` 探针补回持久配置。之后管理员仍可在【持久配置】中自行删除、增加或修改规则。

## 5.19 SSRF（`ssrf`）

只扫描 URL 类 `parameter_names`，且必须设置 `callback_base_url`。默认名称包含 `domain`，因此可匹配 `cmcDomain` 等以后缀命名的字段。每个请求注册唯一 token，Payload 用 `{{callback}}` 生成 URL。

- 收到独立一次性回连：**严重、已确认**，证据等级 L5；
- 目标读取回连响应并把专属响应标记带回原始业务响应：**严重、已确认**，证据等级 L5；
- 未收到回连：不报告。响应仅回显 callback URL、Token 或整个 Payload 不构成 SSRF 证据，也不会被提升为 L5。

配置示例：

```json
{
  "callback_base_url": "http://10.0.0.20:61166",
  "plugin_rules": {
    "ssrf": {
      "parameter_names": ["url", "domain", "webhookUrl", "downloadAddress", "imageUrl"],
      "payloads": [
        {"name": "内网回连", "payload": "{{callback}}"}
      ]
    }
  }
}
```

程序启动时默认同时打开 61166 回连端口，回连路径由扫描器自动生成。V3.4支持GET、HEAD以及最大64 KiB的POST回连，并能从Token后的追加业务路径或Query中识别已注册Token。例如目标将固定路径追加为：

```http
POST /api/v1/callback/<token>/openapi/v1/envs/apps/1 HTTP/1.1
```

仍可正确关联。回连响应还包含一个不出现在注入URL中的专属标记；只有目标真正读取该响应并将标记回显到原始接口响应时，才使用“直接回显”证据确认SSRF。该端口不暴露扫描或配置 API。默认不会探测云元数据、环回端口或真实内网资产。

## 5.20 开放重定向（`open_redirect`）

只扫描 redirect、return、next、continue、target、url、callback 等语义参数。默认注入：

```text
https://jungle-happy-scan.invalid/{{token}}
```

解析响应 `Location`，只有 Host 与 Payload Host 精确一致且保留唯一 token 才报告**中危、已确认**。由于客户端默认不跟随跨站跳转，不会访问外部域名。

对于本系统特殊参数，扩展 `parameter_names`：

```json
{
  "parameter_names": ["redirectUrl", "returnTo", "successPage", "errorPage"]
}
```

不要把任何包含 `url` 的字段都加入，例如内部下载地址可能属于 SSRF 而非重定向。

## 5.21 CRLF/响应头注入（`crlf_injection`）

向每个插入点追加 CRLF 与唯一响应头：

```text
{{value}}\r\nX-Jungle-Happy-Scan-Canary: {{token}}
```

只有响应中真正出现独立的目标 Header，且值包含 token，才报告**高危、已确认**。仅在 Body 回显换行文本不会报警。

规则必须同时设置 `payload` 和 `header`：

```json
{
  "name": "URL 编码 CRLF",
  "payload": "{{value}}%0d%0aX-Jungle-Happy-Scan-Canary:%20{{token}}",
  "header": "X-Jungle-Happy-Scan-Canary",
  "mode": ""
}
```

是否添加编码变体应根据网关解码行为决定；Header 名必须与 Payload 注入的 Header 完全对应。

## 5.22 反射型 XSS（`reflected_xss`）

仅对 GET/POST/PUT/PATCH 执行，两阶段检测：

1. 注入唯一 token，确认它在 HTML/JSP 响应中反射；JSON/XML Content-Type 直接跳过，无 Content-Type 时仅对具有 HTML 文档特征的响应继续。
2. 检查 token 的全部反射位置，过滤 HTML 注释、`style/textarea/title/xmp/noembed/noframes` 等不可执行文本容器。
3. 区分 `html-text`、`tag`、双引号/单引号/无引号属性，以及 JavaScript 单引号、双引号、模板字符串和代码上下文，选择对应 kind 的 Payload。

只有完整 Payload 原样出现在响应，且没有以 HTML 编码形式出现，才报告高危/较确定。V1.4 不启动浏览器验证 JavaScript 执行，因此不会声称已执行脚本。

规则：

```json
{
  "name": "单引号属性上下文",
  "kind": "attribute-single",
  "payload": "{{token}}'><svg/onload=confirm(\"{{token}}\")>"
}
```

可配置的精确 kind 为 `attribute-double`、`attribute-single`、`attribute-unquoted`、`script-single`、`script-double`、`script-template`、`script-code`、`tag` 和 `html-text`。旧的 `attribute`、`script` 规则继续作为同类上下文回退项。只有完整 Payload 原样出现在同一可执行上下文，且没有被 HTML 编码时才报告；增加规则时保持唯一 token，不使用出网脚本。

## 5.23 敏感信息泄露（`sensitive_data`）

被动扫描基线响应的状态行、Header 和 Body 文本。每个 Detection Rule 最多生成一个 Finding，避免同类信息刷屏。

默认检测：

- Java 异常堆栈、SQL 语句、数据库连接串、绝对路径；
- 私钥和 JWT；
- 中国手机号、身份证、银行卡、邮箱、IP；
- Kubernetes kubeconfig、Secret 清单、ServiceAccount 环境/路径；
- Docker Registry 认证、`DOCKER_AUTH_CONFIG`、Docker Socket。
- 微信小程序 `appSecret/app_secret/wx_app_secret/wechat_app_secret`，以及部分系统误拼的 `appSecrect`。

额外有效性校验：

- 身份证：出生日期与 18 位校验码；
- 银行卡：Luhn；
- IP：标准 IP 解析。

证据保留命中上下文原文，不执行脱敏；Java 栈和 SQL 只保留至多 160 字符。

新增 CTP/容器秘密示例：

```json
{
  "name": "Spring 配置密码",
  "pattern": "(?i)(?:spring\\.datasource\\.password|redis\\.password|client-secret)\\s*[=:]\\s*([^\\s,;]+)",
  "severity": "high",
  "confidence": "firm"
}
```

Pattern 有捕获组时证据优先取第一个非空捕获组。请避免把普通 `token` 字样或所有邮箱都当成高危；严重性应结合数据类型。

## 5.24 JWT 弱配置（`jwt_weak`）

被动遍历所有请求 Header。支持纯 JWT 或 `Bearer <JWT>`；只解析 Header 和 Claims，不验证/爆破/伪造签名。

报告条件：

- `alg=none`：**高危、已确认**；
- 缺少 `exp`：**中危、已确认**；
- `exp` 超过当前时间 30 天：**中危、已确认**；
- Claims 含 password、passwd、secret、idcard、bankcard：**中危、已确认**。

该插件没有持久规则。JWT 放在 Cookie、Query 或 JSON 中时，当前插件不会解析，可通过后续版本扩展，或确保网关使用 Authorization Bearer。

## 5.25 安全响应头（`security_headers`）

浏览器页面安全头只对 HTML/JSP 基线响应执行；Content-Type 缺失或为 `application/octet-stream`、`binary/octet-stream`、`unknown/unknown` 时，可以用 HTML 文档开头识别，并明确记录“Content-Type 缺失或歧义，存在 MIME 嗅探风险”。会话 Cookie 属性会对所有响应检查，因此 JSON 登录接口返回的 `Set-Cookie` 也不会漏掉。检查：

- HTML 样式正文是否缺失或使用歧义 `Content-Type`；
- `Content-Security-Policy`；
- 有效的 `X-Frame-Options: DENY/SAMEORIGIN` 或 CSP `frame-ancestors`；
- `X-Content-Type-Options: nosniff`。
- HTTPS 页面上的 `Strict-Transport-Security`。
- 会话类 `Set-Cookie` 的 `HttpOnly`、`SameSite`，以及 HTTPS 下的 `Secure`；`SameSite=None` 但没有 `Secure` 会单独指出。

浏览器安全头缺少或取值无效时生成一条**低危、已确认** Finding；会话 Cookie 属性问题生成**中危、已确认** Finding。明确声明 `text/plain` 的响应不会仅因为正文以 `<html>` 开头而被升级为反射型 XSS，也不会套用 HTML 安全头结论；这避免把文本下载/源码展示接口误报为 XSS。JSON API 不适用。响应模型会原样保留重复 Header 值，尤其不会把多个 `Set-Cookie` 用逗号错误拆分，因此 Cookie 的 `Expires=Wed, ...` 不影响逐条解析。

该插件没有持久规则；若要检查银行自定义安全 Header，需要新增插件逻辑，不应放到敏感信息 Pattern。

## 5.26 CORS 配置错误（`cors`）

逐个设置 Origin：

- 任意外部源；
- `null`；
- 同 Host 后缀：`https://{{host}}.jungle-happy-scan.invalid` 绕过。

判定：

- `Access-Control-Allow-Origin` 精确反射恶意 Origin，同时 `Access-Control-Allow-Credentials: true`：**高危**；普通源为**已确认**，null 源为**较确定**。
- ACAO 为 `*` 且 Body 非空：只报告**提示、待确认**。公开资源这样配置很常见，不再直接判为中危漏洞。

示例：

```json
{
  "payloads": [
    {"name": "恶意源", "payload": "https://evil.example.invalid"},
    {"name": "null 源", "payload": "null"},
    {"name": "后缀绕过", "payload": "https://{{host}}.evil.invalid", "mode": ""}
  ]
}
```

插件检查实际响应 Header，不只根据预检；当前不单独发送 OPTIONS。

## 5.27 Spring Boot Actuator 暴露（`spring_actuator`）

属于同源相邻路径插件。删除会话后探测 `paths`。除服务器根路径外，会从原报文推导最多三级 Servlet/CTP context path，例如 `/ctp/mobile/order` 会同时探测 `/ctp/actuator`。插件始终执行全部配置路径；通过增减 `paths` 控制覆盖和请求量。

- `/actuator`
- `/actuator/env`
- `/actuator/beans`
- `/actuator/configprops`

响应必须 200，并命中端点专属结构。默认路径覆盖 conditions、scheduledtasks、caches、prometheus、httptrace、flyway/liquibase、gateway/routes 和 Jolokia；同时使用专属签名识别 Druid Monitor、H2 Console 和 Spring Boot Admin，不请求 heapdump。

CTP 改写管理根路径时，直接在 `paths` 添加：

```json
{
  "paths": [
    "/manage",
    "/manage/env",
    "/ctp/actuator/beans"
  ]
}
```

路径必须是同源相对路径。扫描器不会使用从响应发现的链接继续爬取。

## 5.28 OpenAPI 暴露（`api_exposure`）

删除会话后以 GET 探测同源 Java 常见路径：

- `/v3/api-docs`、`/v2/api-docs`、`/api-docs`；
- `/v3/api-docs/swagger-config`；
- `/openapi.json`、`/openapi.yaml`；
- `/swagger-resources`、`/swagger-resources/configuration/ui`；
- `/swagger-ui.html`、`/swagger-ui/index.html`；
- `/doc.html`（Knife4j）。

响应 200 且出现 OpenAPI 3、Swagger 2、Swagger UI 或 Knife4j 明确结构才报告低危/已确认。除服务器根路径外，插件还从当前接口推导最多三层 Servlet/CTP Context Path；例如原接口为 `/ctp/mobile/order`，会同时检查 `/ctp/v3/api-docs`、`/ctp/mobile/v3/api-docs` 等同源候选，适配被网关挂载到子路径的 Java 应用。

配置：

```json
{
  "paths": [
    "/v3/api-docs",
    "/v3/api-docs/swagger-config",
    "/v2/api-docs",
    "/swagger-ui/index.html",
    "/swagger-resources",
    "/doc.html"
  ]
}
```

这是信息暴露提示，测试环境中可能是预期行为。V1.4 不再由本插件访问 `/graphql`；GraphQL 的端点、introspection 与批量限制检测完全归入 `graphql_security`。

## 5.29 GraphQL 安全配置（`graphql_security`）

**适用条件**：Target 含 graphql，或 JSON Body 含 `"query"`。路径包括当前 GraphQL Target 和配置 `paths`，自动去重。

每条规则重复发送两次，都必须 HTTP 200、未认证拒绝并匹配明确特征：

- `introspection`：`__schema` 返回；
- `suggestion`：无效字段返回 `did you mean`；
- `batch`：插件实际生成 20 个 `{__typename}` JSON 操作，响应必须是至少 20 项数组；
- `alias_batch`：由 `graphql_alias_abuse` 生成 32 个别名，响应同时含 `jhs1` 和 `jhs32`。

Introspection/建议为**低危**，批量/别名无限制为**中危**，均为**已确认**。

配置示例：

```json
{
  "paths": ["/graphql", "/api/graphql"],
  "payloads": [
    {
      "name": "Schema Introspection",
      "kind": "introspection",
      "payload": "{__schema{queryType{name}}}",
      "expected": "(?is)\"__schema\"\\s*:\\s*\\{"
    }
  ]
}
```

`batch` 和 `alias_batch` 的数量由代码固定，配置中的 Payload 主要用于元数据；其中 alias 规则配置在 `graphql_alias_abuse`。不要用业务 Mutation 测试批处理。

## 5.30 Java 不安全反序列化入口（`java_deserialization`）

候选来源：

- 值以 `rO0AB`、`H4sI`、`!!java/` 开头；
- Base64 解码后以 Java ObjectStream 魔数 `AC ED` 开头；
- 参数名匹配 data、payload、object、serialized、token、state；
- Content-Type 含 `java-serialized` 或 `x-hessian` 时可直接变异 Raw Body。

插件使用畸形、无 gadget 的 ObjectStream/Hessian 数据。相同请求发送两次，两次触发同一 ObjectInputStream、StreamCorrupted、Hessian、Kryo 等异常，且基线没有，报告**高危、已确认**。不会执行命令。

为兼容旧规则，管理员仍可自行配置 `kind: command_canary`，只有两次响应都含展开后的 Expected 才报告**严重、已确认**。项目不内置 gadget；该行为由是否配置/选择插件决定，不再由 mode 决定。

安全的默认规则示例：

```json
{
  "name": "畸形 Java ObjectStream",
  "kind": "error_probe",
  "payload": "rO0ABXNyAANqaHM="
}
```

除非有专门审批和隔离环境，不要配置 command_canary。建议仍以入口确认和 JEP 290 加固验证为主。

## 5.31 Fastjson SafeMode 检测（`json_polymorphic`）

**适用条件**：请求体是 JSON 对象或数组。

V2.3 保留历史插件 ID 以兼容 API 和已有插件选择，但抛弃旧版 Jackson 多态入口、AutoType 可利用性和 RCE 分级。插件只对 `@type` 注入不存在的无害类型：

```text
jungle.happy.scan.SafeModeProbe731
```

支持 JSON 根对象、根数组及可加入字段的嵌套对象路径，不加载真实类、不使用 gadget、不执行命令。判定逻辑：

1. 第一次注入 `@type`。
2. 若响应明确出现 `safeMode not support autoType`，说明 SafeMode 已开启，作为安全结果结束，不生成漏洞 Finding。
3. 若响应同时出现随机类型名和 Fastjson 特征（例如 `autoType is not support`、`com.alibaba.fastjson`、Fastjson `JSONException`、`type not match`、`ClassNotFoundException`），且没有 SafeMode 拒绝，则发送原始请求对照。
4. 原始对照必须恢复到基线且没有该特征，再次发送同一探针。
5. 两次探针必须命中同一规则、包含随机类型名且响应相似度至少 `0.90`，才报告**高危、已确认**“Fastjson 未开启 SafeMode”。

需要特别区分：

- `autoType is not support` 只说明普通 AutoType 策略拒绝，不等于 SafeMode 已开启；按本版本需求仍报告“未开启 SafeMode”。
- `safeMode not support autoType` 才是 SafeMode 的明确开启证据。
- 普通 Jackson `InvalidTypeIdException` 不属于本插件范围，不报告。
- 目标没有返回任何 Fastjson 特征时无法从黑盒响应证明 SafeMode 状态，因此不报告；扫描器不会把任意 JSON 500 或沉默接受误判为“未开启”。

持久规则中：

- `group` 固定为 `@type`；
- `payload` 必须是合法 JSON 值，字符串需包含双引号；
- `expected` 是不存在类型名；
- Pattern “Fastjson SafeMode 已开启”应只匹配明确 SafeMode 文本；
- Pattern “Fastjson SafeMode 未开启特征”应同时关联 Fastjson 特征与随机类型名，避免把通用 JSON 异常当成证据。

配置从旧版本升级到 V2.3 时，该插件的历史 Payload、Pattern（包括管理员自定义旧多态规则）会被新 SafeMode 规则包整体替换，这是本次“抛弃原有一切逻辑”的有意行为。升级后如需扩展厂内 Fastjson 包装异常，请在新规则基础上追加仍与 `SafeModeProbe731` 关联的正则。

## 5.32 短信轰炸/喷洒（`sms_abuse`）

**适用条件**：请求 URL 必须包含持久规则 `sms_abuse.url_keywords` 中的任一关键字，默认是 `send`；同时发现手机号语义参数。管理员可在持久配置中新增 `message` 等厂内路由关键字。这样包含 `phone` 的普通 `update` 接口不会被当作短信接口。命中 URL 条件后不再硬编码限制 HTTP Method；GET Query、POST/PUT/PATCH 的 Form、JSON、嵌套 JSON 等只要发现匹配字段都可执行。默认参数名称包括 `mobile`、`mobileNo`、`mobilePhone`、`phone`、`phoneNumber`、`telephone`、`tel`、`smsPhone`、`receiverMobile`。

### 短信轰炸

插件为原号码生成 30 个相同请求，先创建全部 goroutine，再通过同一个 start channel 同步释放，确保它是高并发批次而不是串行 Payload 循环。实际在途连接仍受 `max_concurrency` 和 `requests_per_second` 的安全上限约束。只有同时满足以下条件才报告：

- 成功响应超过 5 次；
- 从同步释放到批次完成不超过一分钟；
- 成功响应为 2xx 且不是认证拒绝；
- JSON 结构明确包含 `code/status/resultCode/retCode` 为 `0`、`200`、`000000`，或 `success=true`，或消息字段包含“发送成功/下发成功”；也可由 `sms_abuse.patterns` 或全局 `success_patterns` 补充判定。

例如下面的数字型 `code` 会直接计入成功，不依赖持久正则是否覆盖：

```json
{"msg":"发送成功", "code":200}
```

结果名称为“短信接口缺少单号码发送频率限制”。扫描器无法观察运营商或手机，只能证明接口在一分钟内超过 5 次返回“发送成功”。

### 短信喷洒

`kind: spray_number` 的规则生成不同号码，所有变异请求同样通过同步屏障并发发送。只有一分钟内超过 5 个不同号码均返回成功时才报告。

默认使用原号码除最后 4 位之外的前缀，并生成 30 个不同测试尾号。管理员自定义不足 30 条时，扫描器会自动补足为 30 个不同号码：

```json
{
  "parameter_names": ["mobile", "phoneNumber", "receiverMobile"],
  "payloads": [
    {"name": "喷洒号码 1", "kind": "spray_number", "payload": "{{prefix}}7300"},
    {"name": "喷洒号码 2", "kind": "spray_number", "payload": "{{prefix}}7301"},
    {"name": "喷洒号码 30", "kind": "spray_number", "payload": "{{prefix}}7329"}
  ],
  "patterns": [
    {
      "name": "短信发送成功",
      "pattern": "(?is)(短信.{0,20}发送.{0,20}成功|验证码.{0,20}发送.{0,20}成功|\"(?:code|status)\"\\s*:\\s*\"?(?:0|200|000000)\"?)",
      "severity": "高危",
      "confidence": "较确定"
    }
  ]
}
```

测试前应把喷洒号码改为测试环境保留号码，并把成功正则收紧到目标系统真实 success code/message。该插件会真实调用接口，只能在明确授权的测试环境使用。

---

## 5.33 Apache Shiro RememberMe（`shiro`）

### 扫描目的

识别请求/响应中的 `rememberMe` Cookie，并判断是否仍使用 Shiro 历史默认 AES Key。插件严格限制在密码学入口验证，不使用 CommonsCollections 等 gadget，不加载业务类型，不执行命令。

### 请求和判定顺序

1. 无论原请求是否已有 `rememberMe`，都先写入随机无效值 `jhs-invalid-rememberme`；因此登录前接口和未携带 RememberMe 的 Burp 报文也能发现入口。
2. 若相对基线新增 `rememberMe=deleteMe`，以“识别到 Shiro RememberMe”输出提示，不把组件指纹当成 RCE；原请求或基线已出现该 Cookie 时只作为额外被动佐证。
3. 对每条 `payloads` 中 `kind=key` 的 Base64 AES Key，生成随机 IV，将最小 Java ObjectStream `AC ED 00 05 70`（`TC_NULL`）按 AES-CBC/PKCS#7 加密后作为 Cookie。该对象流不包含类描述和 gadget。
4. 随机密文被 deleteMe、而安全 null 对象流不再 deleteMe 时，报告“使用已知密钥”，严重/已确认，证据为 L4 成对密码学确认。

### 持久配置

```json
{
  "payloads": [
    {"name":"Shiro 历史默认 AES Key","kind":"key","payload":"kPH+bIxk5D2deZiIxcaaaA=="}
  ]
}
```

若你们自研框架曾统一下发弱密钥，可在授权范围内增加 Base64 Key。Key 解码后必须是 AES 支持的 16/24/32 字节。不要把生产密钥写入共享配置；该插件的目的应是验证已知默认/弱密钥，而不是收集密钥。

### 误报控制与边界

- 只有 deleteMe 的组件指纹为“提示”，不是漏洞确认。
- 默认密钥结论必须同时存在随机密文对照，避免把应用统一清 Cookie 的逻辑误判。
- 某些定制 Realm 会拒绝反序列化 null；此时可能漏报默认密钥，但不会因此提升错误结论。

## 5.34 Java 表达式注入（`java_expression`）

### 扫描目的

面向 Spring/CTP 常见 SpEL，以及 Groovy/JSR-223 ScriptEngine、Thymeleaf、FreeMarker、Velocity、OGNL 表达式上下文。探针只做整数乘法，不访问 `T(java.lang.Runtime)`、ClassLoader、文件、网络或命令。

### 判定逻辑

每个插入点、每种表达式模板执行两轮。每轮随机生成不同操作数，将 `{{left}}`、`{{right}}` 写入模板；只有两次响应分别出现正确乘积，且乘积不在 Payload 原文和基线中时报告严重/已确认。单纯反射 `${731*73}` 不会命中，因为响应必须包含请求中没有连续出现的计算结果。

### 默认配置

当前规则已拆分：`java_expression` 保存 Spring EL 与裸算术核心模板；裸 `{{left}}*{{right}}` 可覆盖直接 SpEL/Groovy/ScriptEngine `eval` 上下文。`java_expression_extended` 保存 Thymeleaf、OGNL、FreeMarker、Velocity 扩展模板。下例为两处配置合并后的展示，实际应在前台对应插件下维护。

```json
{
  "payloads": [
    {"name":"Spring EL","kind":"spel","payload":"${{{left}}*{{right}}}"},
    {"name":"Spring EL #{ }","kind":"spel","payload":"#{{{left}}*{{right}}}"},
    {"name":"SpEL/Groovy 裸表达式","kind":"raw_expression","payload":"{{left}}*{{right}}"},
    {"name":"Thymeleaf *{ }","kind":"thymeleaf","payload":"*{{{left}}*{{right}}}","mode":""},
    {"name":"Thymeleaf 预处理选择器","kind":"thymeleaf","payload":"__${{{left}}*{{right}}}__::.x","mode":""},
    {"name":"OGNL %{ }","kind":"ognl","payload":"%{{{left}}*{{right}}}","mode":""},
    {"name":"FreeMarker","kind":"freemarker","payload":"${{{left}}*{{right}}}","mode":""},
    {"name":"Velocity","kind":"velocity","payload":"#set($jhs={{left}}*{{right}})$jhs","mode":""}
  ]
}
```

根据 CTP 模板语法可以增加只含算术的包裹形式。必须保留 `{{left}}` 和 `{{right}}`，不要加入 Java 类型访问、方法调用或命令表达式。若页面对数字进行格式化（千分位等），当前严格字符串判定可能漏报，可增加一个专用插件规则前先用测试环境确认实际输出。

## 5.35 JNDI/Log4j 回连注入（`jndi_injection`）

### 扫描目的与安全模型

验证不可信 Header/输入是否触发 JNDI LDAP 查询。主程序额外监听 `callback_ldap_listen`（默认 `0.0.0.0:61167`）。监听器只返回最小匿名 Bind 成功以接收搜索 DN 中的一次性随机 Token，随后断开；它不会返回 LDAP Entry、`javaClassName`、`javaCodeBase`、远程 class、序列化对象或命令。

### 判定逻辑

1. 为每个规则注册十分钟有效的一次性 Token。
2. 将 `{{callback}}` 展开为带 `jhs-jndi-随机值` 的唯一 LDAP URL。
3. 规则填写 `header` 时写入该 Header；不填写 `header` 时遍历当前报文的每个插入点。所有 Token 由一个批量等待器共享 8 秒窗口，不为每个 Payload 创建 Goroutine/定时器，也不串行累加等待时间。
4. 只有 LDAP Sink 从目标连接字节中读到完整 Token 才报告严重/已确认（L5）。HTTP 500、`error`、Payload 反射均不能单独形成结论。
5. Token 首次命中后拒绝重复，过期拒绝，消费后删除。

### 持久配置

```json
{
  "payloads": [
    {"name":"Log4j/JNDI User-Agent","kind":"callback","header":"User-Agent","payload":"${jndi:{{callback}}}"},
    {"name":"Log4j/JNDI X-Api-Version","kind":"callback","header":"X-Api-Version","payload":"${jndi:{{callback}}}"}
  ]
}
```

可以增加实际进入日志链的业务 Header，例如 `X-Request-Id`、`X-Client-Id`；也可以省略 `header` 以扫描参数，但插入点较多时请求数会相应增长。不建议无差别扫描全部 Header，既增加日志噪声也降低效率。前台还需把 `callback_ldap_base_url` 设置为目标服务器能访问的扫描器 IP/域名；NAT、防火墙和容器端口需要放行 TCP 61167。`callback_max_connections` 默认 128，限制 LDAP Sink 同时占用的原始连接，修改后需重启。无出站网络时插件会安全地无结果，而不是根据错误响应猜测漏洞。

## 5.36 Host Header 信任注入（`host_header_injection`）

### 扫描目的

检测 Spring 应用、网关或代理是否直接信任 `X-Forwarded-Host`、`X-Host`、`Forwarded`，进而污染密码重置链接、绝对跳转、表单 Action 或静态资源地址。插件不修改真实连接目标和原始 `Host`，避免把请求发送到 canary 域名。

### 判定逻辑

每条规则生成唯一 `*.invalid` 主机名，发送同一变异两次。只有两次响应都在以下位置产生该主机名，且基线没有时才报告：

- `Location` 为 `https://canary.invalid/...` 或 `//canary.invalid/...`；
- HTML 的 `href`、`action`、`src` 为指向 canary 的绝对 URL。

普通响应正文反射 Header、错误页打印 Header、JSON echo 不作为证据。

### 默认配置

```json
{
  "payloads": [
    {"name":"X-Forwarded-Host","kind":"header","header":"X-Forwarded-Host","payload":"{{host}}"},
    {"name":"X-Host","kind":"header","header":"X-Host","payload":"{{host}}"},
    {"name":"Forwarded host","kind":"header","header":"Forwarded","payload":"host={{host}}","mode":""}
  ]
}
```

若网关采用自定义 Header，可以增加同结构规则。`payload` 必须包含 `{{host}}`；不要把 Host 配成真实外部域名。对于只在异步邮件中生成密码重置链接的系统，单报文同步响应无法自动观察邮件内容，需要人工业务测试。

## 5.37 JWT 签名校验绕过（`jwt_active`）

插件从任意 Header、Cookie、Query、Form 和嵌套 JSON 中识别三段 JWT，不更改 Claims，先将签名替换为随机错误值作为拒绝控制，再构造相同 Claims 的 `alg=none` 无签名令牌并重复两次。只有“错签被拒绝 + none 两次恢复授权基线”才报告严重/已确认。若某个令牌的错签本身也被接受，插件继续检查其他令牌，不根据该启发式差异猜测。

该插件无需 Payload 配置。应将系统真实 JWT 拒绝 code/message 加入 `denied_patterns`，否则统一返回 200 的鉴权框架可能使控制请求无法被识别。插件列为状态修改阶段，因为原始接口可能是 POST/PUT。

## 5.38 反向代理信任头权限绕过（`proxy_trust_bypass`）

适用于带会话且授权基线正常的 Spring/CTP 接口。插件先删除所有会话，确认规范匿名请求被拒绝；再分别测试 `X-Forwarded-For: 127.0.0.1`、`X-Real-IP: 127.0.0.1`、`X-Original-URL` 和 `X-Rewrite-URL`。单一变体必须两次恢复授权基线且彼此稳定，才报告高危/已确认。

配置重点仍是 `session_identifiers` 和 `denied_patterns`。插件只比较匿名拒绝对照与代理头变体，不尝试提供或推断其他用户身份。服务端应只信任由受控反向代理清洗并重写的转发头。

## 5.39 HTTP TRACE 方法开放（`http_trace`）

插件删除会话，把方法改为 `TRACE`，清空 Body，并添加唯一 `X-Jungle-Trace` Header。只有响应 Body 原样出现完整 Header 名与随机值才报告中危/已确认；`Allow: TRACE`、普通 200 或错误页不足以报告。无需配置 Payload。

## 5.40 SQL 注入扩展差分（`sqli_extended`）

该插件承接旧 Deep SQL 规则，但运行逻辑不依赖 mode。默认包含双引号字符串布尔、括号上下文、数值/字符串注释上下文和 PostgreSQL/GaussDB 兼容的 CAST 破坏/恢复组。每组仍按 A-B-B-A 反向顺序确认；错误型要求两次同类 SQL/JDBC/ORM 特征，布尔型要求真响应接近基线、假响应稳定偏离。

配置时把 `error_break/error_repair` 或 `boolean_true/boolean_false` 成对放入 `sqli_extended.payloads`，同组 `group` 必须一致。该插件沿用自己的 `patterns` 副本；在核心 `sqli` 中新增 Pattern 不会自动同步，因此涉及自研 CTP 包装异常时，应同时更新需要使用的 SQL 插件 Pattern。

## 5.41 SQL 时间盲注（`sqli_timing`）

默认包含 PostgreSQL、GaussDB 与 MySQL 的数值、单引号字符串和双引号字符串上下文。`time_control` 和 `time_delay` 必须同组，发送顺序为 control、delay、delay、control。`expected` 是预期秒数；两轮延迟均需超过 1200ms、预期值 65% 和基线抖动四倍中的最大值，控制/延迟各自还要稳定。

只在明确允许产生约两秒延迟的测试环境勾选。增加存储过程时间规则时必须提供零延时控制，不能只配置 `SLEEP(2)`；不要使用锁表、重查询或外部网络延时。

### 5.41.1 SQL ORDER BY 注入（`sqli_order_by`）

候选参数名和 Payload 均可在【持久配置】中修改。条件错误规则使用 `conditional_control/conditional_error` 同组配对，时间规则使用 `time_control/time_delay` 同组配对。检测必须保留 `{{value}}` 作为原排序表达式，避免正常控制分支改变业务排序。不要仅配置 `ASC/DESC` 差异，这只能证明排序功能存在。

### 5.41.2 SQL LIMIT/OFFSET 注入（`sqli_limit`）

候选参数名和 Payload 均可持久配置。默认只执行 MySQL 注释恢复与单引号破坏，不根据 `limit=10/20` 的结果数量差异报警。自定义规则必须按 `error_break/error_repair` 同组配置，并确保 repair 保持原分页值；不要加入 UPDATE、DELETE、堆叠查询或数据提取语句。

## 5.42 XXE 扩展与回连（`xxe_extended`）

承接 `callback` 与 `xinclude_file` 规则。适用性与核心 XXE 相同，仍按 XML occurrence 精确变异。回连只有 61166 独立监听器收到一次性 Token 才成立；响应回显 callback URL 不成立。XInclude 必须两次匹配 `/etc/passwd` 强指纹且基线不匹配。

配置 `callback_base_url` 为目标可访问地址；新增规则时使用 `{{callback}}`，不要填写公网第三方服务。无法出站只代表没有观察到回连，不等于安全。

## 5.43 任意文件读取编码绕过（`file_read_encoded`）

承接双重 URL 编码、`....//` 路径归一化和 `file://` URI 变体。参数候选与核心 `file_read` 分开配置；默认迁移会复制候选名。每个 Payload 的 `expected` 必须是文件强指纹，首次命中后同一请求再确认一次。

增加规则时优先选择 Linux 稳定文件，并使用完整行结构；不要只匹配 `root`、`localhost`、`Linux`。如果应用先解码两次再归一化路径，可在这里增加对应编码层数，同时关注网关对 `%25` 的提前拒绝。

## 5.44 文件上传执行确认（`file_upload_execution`）

包含双扩展文件和 `execute_canary` JSP。插件保留 Multipart 其他字段和原文本字节；只有上传成功响应提供同源路径后才 GET 验证。执行确认 JSP 只计算随机整数乘积，期望结果不直接出现在源码；返回结果必须包含乘积且不包含 `<%=` 源码，才给出 L5 确认。

该插件属于状态变更阶段并独占执行。若系统不返回访问 URL，可用规则 `header` 配置经管理员确认安全的同源验证路径；不要指向真实用户文件，不要在 JSP 中加入 Runtime、文件、网络或命令操作。

## 5.45 OS 命令注入离线回连（`command_injection_oast`）

只检查插件 `parameter_names` 或全局 `command_parameter_names` 命中的输入，默认用 curl 访问 `{{callback}}`。规则覆盖`;`、`|`、`||`、`&&`、换行、反引号和`$()`；其中反引号与`$()`采用整值替换，能够覆盖路径值位于Shell双引号内部、分号无法形成控制符的场景。发送完全部探针后共享一次回连等待窗口；只有独立监听器收到唯一 Token 才报告 L5。HTTP状态、报错、Payload反射均不会命中。

可针对 BusyBox 改为 `wget -qO-`，但仍只能请求本机一次性 Token，不应下载文件或执行二阶段内容。修改候选参数名时同步检查命令核心/时间插件是否也需要更新。

## 5.46 OS 命令注入时间差分（`command_injection_timing`）

使用同组 `delay/control`。Shell上下文覆盖`;`、`|`、`||`、`&&`、换行、反引号和`$()`的`sleep 2/sleep 0`；脚本/表达式语义参数另有`sleep(2000)/sleep(0)`，用于Groovy或兼容的ScriptEngine。当前每组各发送一次，要求延时至少多1700ms且大于控制耗时两倍，结论为严重/较确定；高抖动接口可能漏报，因此优先使用输出canary或OAST。

不要把延时提升到长时间，也不要配置 fork bomb、锁或资源消耗命令。若目标参数嵌入 shell 引号，应添加成对且等价的上下文规则。

## 5.47 Java 表达式注入扩展（`java_expression_extended`）

包含 Thymeleaf `*{}`/`__${}__::.x`、OGNL `%{}`、FreeMarker `${}` 和 Velocity `#set(...)` 算术模板。每条模板执行两轮随机乘法，响应必须出现请求中不存在的正确乘积；原样反射表达式不会命中。配置必须同时保留 `{{left}}`、`{{right}}`，禁止类型访问、反射、文件、网络和命令。

CTP 若使用自定义包裹语法，应先手工确认无害整数表达式的实际输出格式，再把模板加在此插件；如输出带千分位，当前严格匹配会漏报而不会误报。

## 5.48 Mass Assignment 扩展绑定（`mass_assignment_extended`）

复用核心敏感字段规则，但打开额外绑定来源：Multipart 同时增加 Query 变体，无明确 JSON/Form/Multipart 类型时尝试 Query。每个变体发送两次；仅响应稳定回显字段时为低危/待确认，能够通过同源读取再次看到字段才提升为高危/已确认。

配置中的 `group` 是敏感字段名，`payload` 是 JSON 值，`expected` 匹配回显。优先测试无破坏性的测试字段或测试账号；`header` 可配置管理员确认安全的读取路径。

## 5.49 GraphQL 别名批处理限制（`graphql_alias_abuse`）

生成包含 `jhs1` 到 `jhs32` 的单条查询并重复两次。两次均 HTTP 200 且响应同时包含首尾 alias，才报告缺少别名数量/复杂度限制。插件不猜测业务字段、不执行 Mutation。

路径配置应包含真实 GraphQL 入口。默认 `alias_batch` Payload 主要提供规则元数据，数量由代码固定；如果服务端允许 `__typename` 但对业务 resolver 有更严格限制，仍需结合网关/GraphQL 引擎配置人工确认影响。

## 5.50 异常信息泄露扩展诱导（`error_disclosure_extended`）

包含超大整数、非法日期和空字节文本，使用与核心插件相同的“异常、恢复原始、异常”三段确认。两次异常必须命中同一 Java/Spring/ORM/路径 Pattern，原始恢复响应不得命中。它识别的是内部信息泄露，不会仅因 HTTP 500 报告。

对 CTP 自定义类型转换器，可增加数组后缀、非法枚举、日期边界等无破坏输入；Pattern 应包含框架类名、Mapper/DAO/存储过程上下文或绝对路径结构，不要使用宽泛的 `error|message|500`。

## 6. 如何新增或调整规则

### 6.1 先建立可重复基线

1. 在扫描中心粘贴报文。
2. 选择正确协议或自动协议。
3. 点击“测试原始报文”，确认状态行、Header、Body 完整。
4. 连续测试数次，观察真正动态的字段。
5. 只把随机 ID、时间等加入 `dynamic_patterns`。

如果原始请求自身间歇报错、一次成功一次失败，差分型插件无法保证准确率，应先解决会话刷新、签名、限流或测试数据问题。

### 6.2 用扫描计划确认适用性

扫描结果的覆盖率会说明插件：

- `complete`：完成计划；
- `partial`：请求预算不足或运行中触达预算；
- `skipped`：报文不适用，例如 XML 插件遇到 JSON；
- `failed/cancelled`：网络或用户取消。

增加大量规则或扩展插件后，应同步提高 `max_requests`，否则规则虽保存成功但可能只执行一部分。提高请求预算也会增加耗时和测试环境压力。

### 6.3 Payload 配对检查表

以下插件要求严格配对：

| 插件 | 左 Kind | 右 Kind | 配对字段 |
| --- | --- | --- | --- |
| SQL 错误型 | `error_break` | `error_repair` | `group` |
| SQL 布尔 | `boolean_true` | `boolean_false` | `group` |
| SQL 时间 | `time_control` | `time_delay` | `group` |
| NoSQL/LDAP/XPath | `boolean_true` | `boolean_false` | `group` |
| 命令时延 | `delay` | `control` | `group` |

缺少任一侧、group 拼写不同或 kind 写错时，该组不会执行。

### 6.4 正则编写原则

- 在前台保存的是 JSON；`\s` 需要写成 `\\s`。
- 使用 `(?i)` 忽略大小写，`(?s)` 让点号跨行，`(?m)` 开启行首行尾。
- 优先匹配框架类名 + canary + 错误语义，而非宽泛的 `error|exception`。
- 敏感信息 Pattern 尽量使用捕获组只保留真正敏感值。
- 每次增加后用一条确定安全报文和一条确定漏洞报文做最小回归。

### 6.5 典型 Spring/CTP 配置补充

建议从以下内容收集本系统实际值：

- 统一认证失败 JSON code/message → `denied_patterns`；
- 正常业务成功 code → `success_patterns`；
- traceId、流水号、服务器时间 → `dynamic_patterns`；
- 自定义会话/票据字段 → `session_identifiers`；
- 自定义 CSRF Header → `csrf_header_names`；
- CTP 排序/动态字段名 → `mybatis_dynamic_sql.parameter_names`；
- 业务对象主键 → `idor.parameter_names`；
- 文件/URL/跳转字段 → 对应插件 `parameter_names`；
- CTP 包装后的 Mapper、DAO、存储过程异常 → SQLi、MyBatis、error_disclosure Patterns；
- 自定义管理路径 → Actuator/API Exposure Paths。

## 7. 测试矩阵建议

每个插件至少准备：

1. 一条确定安全的反例；
2. 一条能稳定复现的正例；
3. 一条原始响应本身包含相似错误词的基线污染用例；
4. 一条动态字段每次变化的用例；
5. JSON 插件再增加根数组与深层数组用例；
6. 会话插件覆盖 Header、Cookie、Query、Form、JSON/数组中的不同位置。

SQLi、MyBatis、异常泄露应重点覆盖：

- MySQL 与 PostgreSQL；
- MyBatis `#{}` 安全绑定与 `${}` 危险拼接；
- Mapper XML；
- `CallableStatement` 与存储过程；
- Spring/CTP 统一异常包装；
- 200 状态码但业务 code 失败；
- 网关把 500 改写为 200 的场景。

文件上传应覆盖：

- 文本 `.txt` 原文件能正常透传；
- 带中文文件名；
- Multipart 中多个普通字段；
- CRLF 与 LF 边界兼容；
- 文件上传成功但不返回 URL；
- 返回同源相对 URL 并可读取 canary。

## 8. 已知能力边界

- 扫描器只处理一条 Raw HTTP 报文，不自动登录、不爬站、不推导多步业务状态。
- IDOR 只能根据邻近对象响应和 ID 特征提示风险，无法自动获知对象实际归属，需业务复核。
- 反射型 XSS 不启动真实浏览器执行 JavaScript。
- Java 反序列化默认只确认入口，不内置 gadget。
- SSRF、`xxe_extended`、`command_injection_oast` 离线确认依赖目标可访问的 `callback_base_url`；程序默认监听 HTTP 61166，但防火墙和路由仍需管理员放通。
- JNDI 确认依赖 `callback_ldap_base_url` 与 TCP 61167；该监听器不提供利用内容。无法出站时只能视为“未观察到回连”，不能证明没有漏洞。
- `file_upload` 只确认危险类型被接受/可读；`file_upload_execution` 仅当同源 URL 返回请求中不存在的随机算术结果且不返回 JSP 源码时，才确认无害 JSP 执行。
- GraphQL 不猜测业务字段，不执行 Mutation。
- CSRF 无法替代浏览器 SameSite、CSP、Fetch Metadata 的完整验证。
- Normal、Deep、Custom 仅选择插件；规则中的旧 `mode` 字段不参与运行时过滤。
- `max_requests` 太小会导致 partial；短信插件每个手机号插入点需要 60 个主动请求预算（30 次轰炸 + 30 个喷洒号码）。应以覆盖率而不是“0 漏洞”判断是否完整。

## 9. 安全维护建议

- 只扫描已授权测试系统。
- 配置写入密码不要提交到源码或文档；使用环境变量或权限为 600 的密码文件。
- 证据包含请求/响应原文，请仅扫描已授权目标并限制管理页面和代理监听的可访问网段；`redact_evidence` 仅作为兼容字段保留，不再改变证据内容。
- 对共享部署配置 `allowed_hosts`、`shared_service_mode`、来源限流和管理 CIDR。
- 规则修改前备份 `config/config.json`；保存使用原子写入，但错误正则和过宽规则仍可能影响准确率。
- Deep 会勾选全部扩展插件并产生更多真实变异请求，应在隔离测试数据上使用。
- 每次升级二进制后重新打开页面；V2.4 前端资源带独立缓存标识，可避免旧资源混用。
