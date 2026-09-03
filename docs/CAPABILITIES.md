# 扫描能力、模式与限制

## V3.5 CodeMirror、HTTPS MITM 与短信 URL 门控

V3.5 全局使用离线 CodeMirror 6 编辑/查看 HTTP 报文，长 Cookie、JWT 和单行 JSON 自动折行时不再通过透明 textarea 与高亮层同步排版，光标、鼠标和实际输入位置由同一编辑器布局决定。超过 500 KiB 时只关闭语法 Decoration，仍保留虚拟化编辑、选区和正确光标定位。

WEB 代理可在明确作用域内启用 HTTPS 解密：下载并信任 HappyScan 代理 CA 后，HTTPS 明文进入现有捕获、拦截、资产与扫描链路；未启用、未信任或范围外 CONNECT 保持透明隧道。可导入 PEM/PFX/P12 mTLS 客户端证书供代理到目标的上游 TLS 使用；私钥和 CA 均以受限权限保存，PFX/P12 密码不写入任务摘要或恢复配置。

`sms_abuse` 除发现手机号语义参数外，还必须命中持久规则 `url_keywords` 中的 URL 关键字，默认仅 `send`。管理员可增加 `message` 等厂内路由关键字，因此包含 `phone` 的普通 `update` 接口不会被误判为短信接口。

## V3.4 SSRF回连兼容

V3.4修复Java后端对目标URL追加固定业务路径并使用POST访问时的SSRF漏报。61166回连端支持GET、HEAD和有界POST，可从追加路径或Query提取已注册的一次性Token；默认候选参数新增`domain`。回连端返回不在Payload URL中的专属响应标记，业务响应出现该标记时可确认服务端实际读取了回连内容，而普通URL或Token反射仍不会报警。

## V3.3 WEB 扫描、恢复与 HTTP 拦截

V3.3将拦截工作台和资产刷新改为事件驱动长轮询，并按资产、进度、漏洞和拦截拆分Revision；历史第一页通过增量时间索引近似O(10)读取，漏洞汇总按类型延迟加载受影响接口。代理设置、资产、插件、配置和手册按页面加载，超长报文自动降级为低DOM成本的纯文本展示。创建任务主配置压缩为一行，目标URL自动定义主作用域，附加Host进入高级设置。静态资源使用内置默认后缀并允许通过`static_extensions`逐行追加。

V3.0 新增手工浏览器代理入口，但不改变 V2.4 的 52 个检测插件。浏览器正常访问 HTTP 测试系统时，代理负责转发、捕获、静态资源过滤、接口指纹去重和有界排队；扫描执行仍复用单报文引擎及其请求预算、Host 限流、证据分级和覆盖率。

V3.1 在普通 HTTP 转发链路中增加请求、响应两个独立人工拦截点。管理页面可以查看 Raw 报文、原样放行、修改后放行或丢弃；修改请求重新校验 HTTP 语法和任务作用域，修改响应重新校验状态行和 Header。等待队列、超时、历史和报文体积均有硬上限。V3.5 在此基础上增加可选的作用域内 HTTPS MITM；未启用解密时仍由浏览器通过 CONNECT 完成端到端 TLS，HappyScan 不读取 TLS 明文。

V3.2把代理“允许转发”与“进入测试范围”分离。本机环回代理会直接放行指定目标之外的HTTP和CONNECT流量，但不缓存、不拦截、不建立资产、不扫描；非环回监听仍严格拒绝目标外流量。空目标或`*`继续表示全局Passive，仅运行三个被动插件。

WEB任务使用内存热索引和`var/webscan_state`本地压缩恢复文件。任务、每个接口的一份代表性请求/响应、扫描基线与Finding异步原子保存；进程重启后恢复为已停止任务，排队或运行中的扫描标为中断且不会自动重放。浏览器关闭、刷新、休眠和心跳中断不再控制任务生命周期。管理页面默认跨任务分页展示全部历史接口；“清空历史资产”需连续两次确认，只清除接口、证据和漏洞，不停止仍在监听的代理任务。

开启请求或响应人工拦截时，前端保持一个最长25秒的事件长轮询，发现新等待项后只读取一条Raw报文；任务、资产和报告依据各自Revision增量刷新，空闲时不产生高频请求。

接口指纹综合 HTTP 方法、Scheme、Host、规范化路径、Content-Type 和参数结构。数字、UUID 等动态路径段会归一化，Query/Form/JSON/XML/Multipart 使用字段结构而不是业务值去重；不同方法、不同内容类型和 GraphQL operation 不应被合并。重复访问只更新捕获次数和最新代表报文，不会无界创建任务。

首期支持边界如下：

- HTTP：完整转发并捕获请求/响应，可自动或手工扫描；
- HTTPS：未启用 `intercept_tls` 或浏览器未信任 HappyScan CA 时仅处理 `CONNECT` 隧道，不能读取或扫描加密内容；
- WebSocket/长连接：首期只保证普通 HTTP 请求，升级连接不作为可扫描接口；
- 资产与结果：内存保存热摘要，本地压缩文件用于当前任务恢复；明确删除任务时同步删除对应恢复目录；
- 代理安全：只有环回监听允许目标外透明旁路；部署到服务器的非环回代理继续执行严格Host范围，并应通过安全组或防火墙限制来源。

捕获层应在不改变浏览器收到的完整响应前提下，只保存配置上限内的证据副本；当前证据保留命中上下文原文，不执行脱敏，因此 Cookie、Token、客户端证书和业务响应均属于敏感数据。共享测试环境应限制管理页面和代理监听的可访问网段。

## 扫描模式

- `Passive`：快捷勾选敏感信息、JWT 和安全响应头三个被动插件。
- `Normal`：快捷勾选全部被动插件和 9 个常见主动插件。
- `Deep`：快捷勾选全部 52 个插件。
- `Custom`：保留当前手工勾选组合。

四种模式只是前台插件选择预设。前端向扫描接口提交最终插件 ID 数组，不再提交隐藏的 Payload 强度。异步 V1 API 仍兼容 `mode` 字段，但该字段不会改变已选插件的规则。手工修改任何预设后自动进入 Custom。

V1.4 的 Normal 会自动选择全部 passive 插件，以及 XSS、文件读取、文件上传、异常信息泄露、未授权、CORS、SQL 注入、XXE 和短信漏洞。短信插件会真实高并发发送请求，只能用于已授权测试环境。

高成本能力通过独立插件表达，例如 `sqli_timing`、`command_injection_oast`、`file_read_encoded`、`file_upload_execution`。因此 Normal 不选这些插件，Deep 会选中，Custom 可按需添加；选中后无论从哪个预设进入，其请求序列都一致。

## 52 个插件

| ID | 能力 | 默认 | 主要判定方式 |
|---|---|---:|---|
| `unauthorized` | 未授权访问 | 是 | 删除全部配置/自动识别凭据后双响应差分；无凭据必登录接口直接判定 |
| `idor` | 对象级越权 | 是 | 对象标识邻值变异、结构和标识确认 |
| `sqli` | SQL 注入核心 | 是 | 单引号恢复信号、PostgreSQL/GaussDB 条件错误 A-B-B-A、自定义数据库错误正则和类型适配布尔差分 |
| `sqli_extended` | SQL 注入扩展差分 | 是 | PostgreSQL/MySQL/GaussDB/MyBatis/存储过程扩展错误与布尔配对 |
| `sqli_timing` | SQL 时间盲注 | 是 | `pg_sleep`/`SLEEP` 与零延时控制的反向重复对照，包含 MySQL 双引号上下文 |
| `sqli_order_by` | SQL ORDER BY 注入 | 是 | 可配置排序参数的条件错误与时间配对，不根据普通排序变化报警 |
| `sqli_limit` | SQL LIMIT/OFFSET 注入 | 是 | 可配置分页参数的注释恢复与引号破坏配对 |
| `xxe` | XXE 核心 | 是 | DTD 展开和本地文件实体 |
| `xxe_extended` | XXE 扩展与回连 | 是 | XInclude、编码实体与独立 HTTP OAST 确认 |
| `file_read` | 任意文件读取核心 | 是 | passwd/hosts/proc/version/os-release 的绝对路径/目录穿越与双请求确认 |
| `file_read_encoded` | 文件读取编码绕过 | 是 | 编码、双重编码及路径归一化变体 |
| `file_upload` | 危险文件上传核心 | 是 | 文本危险扩展名和 MIME 欺骗 canary |
| `file_upload_execution` | 上传执行确认 | 是 | 高风险扩展与响应同源路径的无害执行标记确认 |
| `sensitive_data` | 敏感信息泄露 | 是 | 手机号、身份证、银行卡、邮箱、微信 AppSecret 及 Java/SQL/IP/密钥/Kubernetes/Docker 特征 |
| `cors` | CORS 错误 | 是 | Origin 反射、凭证、null 和后缀绕过 |
| `reflected_xss` | 反射型 XSS | 是 | 唯一标记定位反射上下文与关键字符验证 |
| `ssrf` | SSRF | 是 | 唯一同服务 callback canary |
| `command_injection` | OS 命令注入核心 | 是 | 请求中不存在的算术输出结果三步确认 |
| `command_injection_oast` | OS 命令注入回连 | 是 | curl 一次性 HTTP OAST Token |
| `command_injection_timing` | OS 命令注入时间差分 | 是 | sleep 与零延时控制成对比较 |
| `ssti` | 服务端模板注入 | 是 | 无害算术表达式执行结果 |
| `spring_actuator` | Spring Actuator 暴露 | 是 | 匿名访问同源管理路径并验证结构特征 |
| `api_exposure` | OpenAPI 暴露 | 是 | Java 常见 OpenAPI、Swagger、Knife4j 同源路径与明确结构特征 |
| `csrf` | CSRF 防护缺失 | 是 | Cookie 状态变更请求、跨站 Origin 和 token 移除 |
| `jwt_weak` | JWT 弱配置 | 是 | 被动解析 none、过期时间和敏感声明 |
| `security_headers` | 安全响应头 | 是 | 被动检查 CSP、点击劫持、MIME 嗅探 |
| `open_redirect` | 开放重定向 | 是 | 唯一外部域名与 Location 精确匹配 |
| `crlf_injection` | CRLF/响应头注入 | 是 | 唯一响应头 canary |
| `error_disclosure` | 输入诱导异常信息泄露核心 | 是 | 常见异常输入、原始对照、异常输入三段重复确认 |
| `error_disclosure_extended` | 异常泄露扩展诱导 | 是 | 类型、路径、表达式和边界值扩展输入 |
| `nosql_injection` | NoSQL 注入 | 是 | MongoDB 操作符真假差分及错误特征复核 |
| `ldap_injection` | LDAP 注入 | 是 | LDAP 过滤器真假差分及解析异常复核 |
| `xpath_injection` | XPath 注入 | 是 | XPath 真假表达式差分及语法异常复核 |
| `java_deserialization` | Java 不安全反序列化入口 | 是 | 畸形对象流重复确认；默认不执行命令 |
| `method_override` | HTTP Method Override 绕过 | 是 | 直接方法拒绝、Header/Spring `_method` 覆盖响应偏离基线并重复确认 |
| `mass_assignment` | Mass Assignment | 是 | JSON 对象/数组、Query、Form、Multipart 常见绑定敏感字段重复回显 |
| `mass_assignment_extended` | Mass Assignment 扩展绑定 | 是 | Multipart/Query 混合及无明确内容类型绑定入口 |
| `mybatis_dynamic_sql` | MyBatis 动态 SQL 片段注入 | 是 | 高风险语义参数、唯一不存在列、破坏/恢复反序确认 |
| `path_normalization` | URL 路径归一化权限绕过 | 是 | 规范匿名路径拒绝、路径变体两次返回授权内容 |
| `parameter_confusion` | HTTP 参数污染与身份优先级混淆 | 是 | 同名参数/凭据 A/B/B/A 顺序反转差分 |
| `json_polymorphic` | Fastjson SafeMode 检测 | 是 | 无害不存在 `@type` 两次确认；只判断 SafeMode，未开启时报高危，不测试 RCE |
| `graphql_security` | GraphQL 安全配置 | 是 | Introspection、字段建议和 JSON 批量限制检测 |
| `graphql_alias_abuse` | GraphQL 别名批处理 | 是 | 32 个 alias 的数量/复杂度限制验证 |
| `sms_abuse` | 短信轰炸/喷洒 | 是 | 同步屏障高并发批次，一分钟成功响应超过 5 次/5 个号码 |
| `shiro` | Apache Shiro RememberMe | 是 | 随机密文 deleteMe 对照 + 已知密钥加密的最小 Java null 对象流；无 gadget/命令 |
| `java_expression` | Java 表达式注入核心 | 是 | 两组随机无害算术结果确认核心 SpEL/JSP EL 求值 |
| `java_expression_extended` | Java 表达式注入扩展 | 是 | Thymeleaf/FreeMarker/OGNL 扩展语法求值 |
| `jndi_injection` | JNDI/Log4j 回连注入 | 是 | Header 中唯一 LDAP Token 回连；监听器不返回远程类或对象 |
| `host_header_injection` | Host Header 信任注入 | 是 | 两次确认 X-Forwarded-Host 等污染 Location/HTML 绝对链接 |
| `jwt_active` | JWT 签名校验绕过 | 是 | Header/Cookie/Query/Form/嵌套 JSON 中错误签名拒绝对照与两次 `alg=none` 接受确认 |
| `proxy_trust_bypass` | 反向代理信任头权限绕过 | 是 | 匿名拒绝对照与转发 IP/原始路径 Header 两次授权响应确认 |
| `http_trace` | HTTP TRACE 方法开放 | 是 | 匿名 TRACE 响应精确反射唯一 Header 名和值 |

## Web 持久规则

管理页面“插件 Payload 与检测规则”按插件保存以下内容：

- `parameter_names`：插件关注的参数名。
- `url_keywords`：插件 URL 关键字；`sms_abuse` 只有 URL 命中其中任一关键字且存在手机号语义参数时才执行，默认值为 `send`。
- `paths`：Actuator、OpenAPI、GraphQL 等同源探测路径。
- `payloads`：Payload JSON 数组，支持名称、类型、分组、模式、MIME、Header 和预期响应。
- `patterns`：检测正则 JSON 数组，支持漏洞名称、正则、严重性和置信度。

Payload 模板支持 `{{value}}`、`{{token}}`、`{{host}}`、`{{callback}}`、`{{root}}`、短信 `{{prefix}}` 及命令算术 `{{left}}/{{right}}/{{sum}}` 占位符。SQL 注入使用相同 `group` 的 `error_break/error_repair`、`boolean_true/boolean_false` 或 `time_control/time_delay` 成对验证；错误型执行破坏、恢复、恢复、破坏的反序复核，布尔与时间型也执行两轮对照，并排除鉴权失败、限流、WAF 常见状态和不稳定时延。默认规则覆盖 PostgreSQL/GaussDB `pg_sleep`、MySQL `SLEEP`、GaussDB JDBC/内核指纹、MyBatis/Spring JDBC 包装异常与 CallableStatement/存储过程异常。管理员可以按相同结构追加 payload。敏感信息规则可追加任意响应正则；身份证和银行卡默认规则仍执行校验算法以降低误报。

V2.4 对 SQL 插入点按位置、参数语义、词法类型和上下文排序。单引号 Gate 只裁剪错误恢复分支，数值/布尔上下文继续执行；漏洞确认使用完整原子 A-B-B-A。响应 Oracle 支持数据库/JDBC 最高价值错误、递归 JSON 同路径业务状态、JSP 成功/失败语义、长响应完整 Body 精确差分和时间对照。ORDER BY 与 LIMIT/OFFSET 同时覆盖 MySQL、PostgreSQL/GaussDB；MyBatis 动态片段复用已有基线，只发送两次 canary。全部 SQL 插件在独占 Oracle Lane 中执行，并共享自适应回收的任务预算。

V2.3 对 Query、Form、JSON 字符串、Multipart、Cookie 和配置 Header 中的 JSON/XML（含 Base64）实现递归变异；`excluded_parameter_names` 可按 Key 在所有位置统一排除。Java 探针覆盖直接命令、Shell、Groovy/ScriptEngine 裸表达式及主流模板语法。危险文件上传逐一扫描所有 Multipart 文件 Part；反射型 XSS 区分单双引号/无引号属性和 JavaScript 字符串上下文，并排除注释、不可执行容器和明确的 text/plain；安全响应头额外标记 HTML 样式响应缺失/歧义 Content-Type 的 MIME 嗅探风险。

任务百分比按计划请求槽位计算，不再按插件个数平均。插件因低成本筛选未命中或已经获得高价值证据而提前停止时，未发请求显示为“收敛跳过”；预算不足、失败或取消的未执行范围不会伪装成覆盖完成。

所有规则保存在 `config/config.json` 的 `plugin_rules` 中，通过管理页面保存后原子写入，新任务立即使用，不需要重启。

## 高性能与资源边界

- V2 按被动分析、安全主动、OAST 回连、状态变更独占四阶段调度。前三阶段内部使用 Goroutine 并发，共享单任务 HTTP Transport 和 Keep-Alive；状态变更插件串行独占，避免文件上传、短信、CSRF 等互相污染。
- 每个任务保留 `max_concurrency`/`requests_per_second`，进程再统一执行 `global_max_concurrency`、`global_requests_per_second` 与 `per_host_concurrency`。多调用方不能将单任务配置倍增压向同一个 Java 服务。
- `max_queued_scans` 提供有限排队；单一调度器取得活跃槽后才启动任务，排队长度不会等比例制造等待 goroutine。插件真正返回错误时 coverage 标记 `failed`，不会再被当作 completed。
- V1.3 计划器先判断插件适用性并估算请求量；预算不足时提供插件保底额度并按风险优先级公平分配，不再让高请求插件无提示地挤占后续检查。
- 单任务配置最大连接并发、RPS、最大请求数、响应大小和超时。
- 扫描页可先发送一次原始报文并在右侧查看完整 Response、耗时和实际协议。
- 每条报文可选择 Auto、HTTP 或 HTTPS；Auto 固定先试 HTTP，连接或协议失败后再试 HTTPS，正式扫描沿用成功协议，不依赖持久默认协议。
- V2.1 可上传 PEM/PFX/P12 客户端 TLS 证书；连通性测试和正式 HTTPS 扫描均带证。同步接口也接受服务器绝对路径 `client_tls_file`，PFX 密码不持久化。
- V3.5 WEB 代理启用 `intercept_tls` 后，使用本地 HappyScan CA 解密作用域内 HTTPS；同一任务可提供 `client_tls_file` 让代理完成目标站点的上游 mTLS 握手，密码仅存在于创建时内存。
- 两个同步接口会在创建任务前发送一次未修改的原始报文；成功响应复用为首个基线。HTTP、HTTPS 都不可达时直接返回失败说明和空漏洞数组，不执行插件扫描。
- 全局 `max_active_scans` 控制同时运行任务数；超出后任务保持 queued，可取消。
- 单任务 DNS 解析结果缓存并固定到直接连接，重定向每一跳重新校验 Host。
- 任务取消会传播到网络请求；结果只在内存保留到 TTL 到期。
- 每个结果包含逐插件覆盖率。`completed` 仅表示任务到达终态，是否完整扫描必须同时检查 `coverage.complete`。

性能取决于目标响应时间、启用插件和配置。`sqli_timing` 与 `command_injection_timing` 会显著增加耗时；是否执行由插件勾选决定，而不是隐藏模式。

## 联网行为

- 安装包包含静态二进制，部署不下载依赖。
- 不含遥测、许可证检查、在线更新、CDN 或第三方前端资源。
- 扫描器只请求报文目标，以及管理员显式启用的同源相邻路径。
- 空 `allowed_hosts` 在创建任务时自动收紧为报文 Host。
- 不读取 `HTTP_PROXY`、`HTTPS_PROXY` 等环境代理；只有前台明确填写 `proxy_url` 才使用代理。
- 直接连接使用已校验并缓存的 DNS IP；同步接口的可选 `host` 映射可把域名固定到指定 IP，同时保留 Host Header 和 TLS SNI。显式代理模式不能与 `host` 映射同时使用。
- `callback_base_url` 只作为 payload 发给目标；主程序默认监听 `0.0.0.0:61166` 的 HTTP 一次性 Token 接口。
- `callback_ldap_base_url` 供 JNDI 插件使用，默认监听 `0.0.0.0:61167`。该最小 LDAP Sink 只返回匿名 Bind 成功以接收搜索 Token，不返回目录条目、Java class、序列化对象或命令。

## V1.3 报文和协议覆盖

- 原有 Query、Form、JSON、XML 文本和 multipart 普通字段继续支持。
- 新增 URL 数字/UUID 路径段、非会话 Cookie、可配置 Header、XML 属性、CDATA、GraphQL variables 和 multipart 文件名。
- 对 Query、Form、JSON、Cookie、Header 中可解码为 JSON 的 Base64 字符串继续递归发现对象和数组字段，变异后使用原 Base64 编码回填。
- `normalized` 使用 Go 标准 HTTP 客户端和连接池；`force_http1` 禁用 HTTP/2 协商；`raw_http1` 每次直接构造 HTTP/1.1 报文，保留 Header 顺序、大小写和重复 Header。
- Raw HTTP/1.1 仍会重算 Content-Length、移除 Transfer-Encoding/Connection/Accept-Encoding，并继续执行目标白名单、DNS 固定、超时、RPS、并发和最大响应限制。
- 动态请求变换可生成时间戳/UUID、执行正则替换、SHA-256/HMAC-SHA256/Base64；V2 在每次响应后提取 CSRF、Token 或 nonce，并在下一请求前写回。响应提取规则默认按原子会话流水线串行；只有全部规则显式 `parallel_safe=true` 时才以快照并发。
- JSON 普通变异按原字节偏移只替换目标值，不重排 Key、不改变空白、不把 64 位以上整数转成浮点；XML 同名节点按 occurrence 单点修改。
- GBK/GB2312/GB18030 的 JSP/Servlet 响应在插件匹配前转 UTF-8；长 HTML 响应使用头部/中部/尾部分段归一化，V2 Full 证据保留完整响应头和命中附近最多 30 行、64 KiB 的上下文，并分别标明捕获截断与证据视图裁剪。

## V2.0 证据等级与 API

- L1：被动配置或信息指标。
- L2：响应相似度/状态差分启发式。
- L3：唯一错误、框架或文件强指纹。
- L4：真假成对、破坏/恢复或重复请求确认。
- L5：严格一次性 OAST 回连或执行级唯一证据。

V1 API 为兼容继续使用中文严重性和置信度。`/api/v2/jungle_happy_scan` 与 Lite 版使用稳定英文机器码 `severity`、`confidence`、`category`，并同时返回中文 Label、`score`、`correlation_id`、`api_version`、`rule_pack_version` 和随持久规则内容变化的 `rule_pack_digest`。

## V1.31 Spring、CTP 与 MyBatis 专项

- Method Override 不再因覆盖 Header 被忽略而报警；必须同时看到直接 PUT/PATCH/DELETE 被拒绝、覆盖后的响应与原始方法显著不同、重复请求一致。支持 `X-HTTP-Method-Override`、`X-Method-Override` 和 Spring `HiddenHttpMethodFilter` 的 `_method` Query/Form/Multipart。
- Mass Assignment 支持 JSON 根对象、根数组内对象、Query、Form、Multipart，以及 Spring `@ModelAttribute`/CTP 兼容层可能采用的 Query+Body 混合来源。两次明确回显只给出低危、待确认；只有同源二次读取确认字段已持久化才提升为高危、已确认。
- MyBatis 动态 SQL 只选择排序列、方向、字段名、表名、字段列表和分组等语义参数；唯一不存在列必须两次进入 MySQL/PostgreSQL/JDBC/MyBatis 错误，恢复原值的两次响应必须回到基线。
- 路径归一化先确认正常匿名路径被拒绝，再测试重复斜杠、点段、矩阵参数和尾斜杠；变体必须两次接近授权基线。
- 参数污染反转同一组值的顺序并反向复核；会话凭据出现“一个顺序授权、另一个顺序拒绝”时才提升为高危确定结论。
- Jackson/Fastjson 检测只使用不存在的无害类型名；错误必须同时包含 canary 与明确框架类型解析特征，恢复原始请求后消失；该插件在任何预设入口下均不执行命令。

## V1.4 高并发短信、GaussDB 与中文报告

- V1.41 将短信轰炸提升为 30 个同号码请求同步起跑，短信喷洒提升为 30 个不同号码请求同步起跑。只有一分钟窗口内成功响应超过 5 次才报告。
- 短信成功优先解析 JSON `code/status/resultCode/retCode`、`success` 和成功消息，并可由 `sms_abuse.patterns`、全局 `success_patterns` 扩展；结果明确限定为“接口返回成功”，不能证明运营商短信真实到达。
- GaussDB 增加专属 JDBC/内核异常指纹，并使用官方支持的 `pg_sleep(0/2)` 构造双轮反序时间对照；MySQL 兼容场景继续由 `SLEEP` 组覆盖。
- 命令输出探针在请求中仅包含两个随机操作数，响应必须出现请求中不存在的和；同一变异执行两次，中间恢复原请求。单纯回显 `printf` 或完整参数不再报警。
- OpenAPI 插件不再访问 `/graphql`；GraphQL 的 introspection 和批量限制检测全部由 `graphql_security` 负责。
- Finding 的 API 输出统一为中文：严重性为提示/低危/中危/高危/严重，置信度为待确认/较确定/已确认，类别为信息提示/疑似漏洞/确认漏洞/配置暴露。
- Jackson/Fastjson 的 SafeMode、AutoType 禁用和 PolymorphicTypeValidator 拒绝归类为“防护已阻断”的信息提示；ClassNotFoundException 随机类型才视为危险类加载入口，普通不存在子类型仅作为中危多态入口。

## 结果可信度与覆盖率

- Finding 统一输出 `score` 和 `category`，高分结论需要明确或重复证据；暴露类配置问题不会伪装成已确认可利用漏洞。
- 相同插件、输入点和标题自动去重。
- 同一输入点出现多种独立信号时生成 `correlation_id`，例如 SQL 注入与 Java/MyBatis 异常泄露关联，有助于优先处理根因。
- 文件上传只有“接受危险类型”时为疑似漏洞；若上传返回同源资源地址且读取到唯一 canary，置信度才提升为已确认。
- Mass Assignment 要求两次稳定回显；可定位资源或管理员配置同源验证路径时再执行二次读取确认持久化。
- GraphQL 批量类只在一次接受至少 20 个 JSON 操作或 32 个别名时报告。

## 服务安全边界

- 外部扫描 API 按需求不启用 API Key，但可设置单来源每分钟任务限额。
- `shared_service_mode` 强制要求非空目标白名单，避免扫描器成为任意 Host 的访问代理。
- 管理 CIDR 可限制配置读取和写入来源；配置写入还需要管理密码，建议通过 `JUNGLE_CONFIG_PASSWORD` 设置。
- 配置 API 自动遮蔽 HMAC Secret，保存未修改的 `<redacted>` 值时由服务端恢复原值。
- 扫描创建日志只记录任务 ID、来源地址和插件数量，不记录 Raw HTTP、Cookie 或请求体。

## 准确率边界

- 所有结果应结合证据人工确认；“未发现”不表示目标绝对安全。
- IDOR 无法自动知道对象归属，结果必须结合测试账号人工复核。
- CSRF 仍需结合 Cookie SameSite 属性和浏览器行为复核。
- 文件上传不执行上传文件；仅在响应明确给出同源地址时使用 GET 读取唯一不可执行 canary 进行落地确认。
- 命令注入 canary 不读取文件；勾选 `command_injection_timing` 时可能发送最多两秒的延时测试。
- 相邻路径类插件可能在测试环境发现预期开放的文档或管理端点。
- Raw HTTP/1.1 用于兼容对报文细节敏感的服务，但不支持显式 HTTP 代理，也不等价于保留畸形 Content-Length 或请求走私报文。
- 动态签名只支持已配置的通用算法与字段组合；自定义 JavaScript、国密硬件、设备指纹或多步骤登录流程仍需在测试网关侧适配。
