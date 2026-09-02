# jungle_happy_Scan V2.4 验证报告

验证日期：2026-07-28  
验证对象：V2.4 源码、管理页面、V1/V2 API、离线安装包与三平台可执行文件。

V2.4 专注 SQL 注入，新增/更新的白盒与回归矩阵包括：

- clean quote Gate 后仍执行数值布尔 Oracle；
- Gate 与确认请求完全分离，预算不足时 A-B-B-A 整组拒绝；
- 单引号/双单引号与空拼接恢复的疑似、两路径提升和强 Oracle 分级；
- 未知方言按通用、PostgreSQL/GaussDB、MySQL 有界回退；
- 嵌套 JSON/根数组业务结果及同一路径对比；
- JSP 成功/失败正则、长响应完整 Body 精确真假分支；
- 基线已有 SQL 错误不污染 repair，多个正则取最高价值证据；
- PostgreSQL/GaussDB ORDER BY 字段/方向与 LIMIT/OFFSET 条件错误；
- MyBatis 只发送两次 canary、复用已有基线；
- JSON `+json`/正文嗅探、XML 属性转义和文本值词法分类；
- SQL 配置 kind/group/占位符/成对数量/时间 expected 校验；
- 请求估算包含 Gate，SQL 独占 Oracle Lane，预算回收及变异/预算部分覆盖。

V2.3 在 V2.1 矩阵上曾新增：

- 普通参数值和 Base64 参数值中的 JSON/XML 递归发现、叶节点变异、原位置/原编码回填；JSON 对象路径中的排除 Key 不再泄漏子字段。
- `excluded_parameter_names` 对 Query、Form、JSON/数组、Multipart、Cookie 和配置 Header 大小写不敏感统一过滤。
- MyBatis LIKE 包裹字符串真假组、ORDER BY 字段/方向分组选择；直接 `Runtime.exec/ProcessBuilder` 算术命令、Groovy/ScriptEngine 裸表达式与主流 Java 模板语法。
- Fastjson SafeMode 开启为无 Finding 负例；Fastjson 特征两次出现且无 SafeMode 拒绝为高危正例；Jackson 错误和普通 JSON 500 为负例。
- HTML 样式响应缺失/歧义 Content-Type 的 MIME 风险，以及 `text/plain` HTML 样式正文不升级为 XSS 的负例。
- SQL 普通参数单引号筛选无差异时只发送 1 次，不进入恢复、条件或布尔 A-B-B-A；空响应、状态变化、新数据库错误和显著差异仍能进入确认。
- 单引号筛选响应复用为 A-B-B-A 第一条请求，已有业务空响应、条件错误、长 JSP 小差异和明确数据库错误正例保持原确认请求数。
- 输入诱导异常核心普通参数只发送一次单引号；命中新增泄露特征时才发送原值对照和重复异常。
- 请求级进度按已解析/计划槽位计算；正常提前收敛计入跳过，预算不足不冒充完成，实际发包数独立保留。
- 页面插件按七个漏洞族完整分组，桌面一行两项并常驻显示小字说明，窄屏切换为单列；独立插件进度列表已删除，实时进度、实发请求、预算和状态只在逐插件覆盖率行中显示一次。

V2.1 保留定向矩阵：

- SQL 引号恢复成立后，条件正常/错误按 A-B-B-A 执行；两次错误命中可配置溢出正则时分类为高危、已确认。
- 条件正常分支不回基线、错误分支不稳定、基线已有同一错误、鉴权/限流/WAF 响应均不得升级结论。
- 合并 PEM 证书链+私钥解析、现代 PFX/P12 密码解析、相对路径拒绝、2 MiB 上限和 TLS Transport 证书装载。
- 前端上传保留原文件名，连通性与扫描请求携带 `client_tls_file`，PFX 密码不写入配置或证据。
- SQL 参数排序、上下文分类、跨 MySQL/PostgreSQL/GaussDB 条件错误对、最高价值正则证据选择及已确认后短路。
- Multipart 多文件字段逐一变异，第二个及后续文件 Part 可独立检出。
- 旧 Servlet 报文使用带前导连字符的 boundary、文件名式 field name、`Content-Transfer-Encoding: binary` 和 LF 粘贴换行时仍可解析；普通后缀探针保留原始 `1234` 内容，必要时同时变更 `name/filename`；JSP 被拒绝而 JSPX 返回转义重命名文件名（含统一 500 包装）时可检出。
- XSS 注释/不可执行容器负例、单双引号属性正例和精确上下文 Payload。
- 重复 Set-Cookie 保真、无效安全头取值、HTTPS HSTS 与会话 Cookie 属性检查。

## 1. 验证原则

扫描器的有效性不以“某个 Payload 得到 500”作为充分条件。测试按以下层次执行：

1. 纯函数单元测试：Raw HTTP 解析、无损 JSON/XML 插入点、响应解码、动态归一化、差异比较和证据窗口。
2. 插件正反例：正例必须满足插件的完整判定链，反例覆盖反射、统一错误页、鉴权失败、WAF/限流和随机响应等误报来源。
3. 传输集成测试：HTTP/HTTPS、Raw HTTP/1.1、重复 Header、Host 到 IP 映射、动态 Token 提取与刷新。
4. 引擎集成测试：预检与基线复用、分阶段调度、请求预算、任务队列、失败覆盖率和同步 API 生命周期。
5. 并发竞态测试：对回连注册、插入点、传输治理、任务引擎、API 和插件执行 `go test -race`。
6. 浏览器验收：使用真实 V2.4 进程加载页面，检查 52 个插件、七个漏洞族、四档插件预设、客户端证书上传、SQL 错误可信度配置、版本更新和离线手册。
7. 模式一致性：分别以 `normal`、`standard`、`deep` 直接调用同一个插件，验证网络请求数与规则完全一致；前台只提交最终 `scan_type`。
8. SQL 恢复差分：覆盖普通 200 业务错误、无 SQL 关键字的统一 500 包装、动态长 JSP 小范围差异和随机不稳定反例。
7. 交付验收：三平台静态编译、SHA-256、全新目录离线安装、健康检查、端口监听和停止脚本。

## 2. 自动化测试范围

| 层级 | 重点覆盖 |
|---|---|
| `internal/httpraw` | Burp Raw 报文、JSON 根数组/嵌套数组、超大整数与科学计数法无损变异、XML 重名节点、multipart、Base64 JSON、路径/Header/Cookie 插入点；动态值写回 Query/JSON/Cookie/Form/Multipart 时保持无关线内容不变 |
| `internal/responsebody` | UTF-8、GBK、GB2312、GB18030、HTML meta charset、文本非法 UTF-8 回退、二进制不误解码、响应截断元数据 |
| `internal/diff` | JSON/HTML/JSP 归一化、动态字段、长响应头中尾分段、相似度和命中点摘录 |
| `internal/transport` | Normalized/HTTP1/Raw 模式、重复 Header、HTTPS、Host 映射、代理禁用默认值、进程/Host 并发与 RPS 治理 |
| `internal/callback` | HTTP/LDAP Token、URL 编码后的 Token 定位、超时拒绝、一次性消费、过期清理、并发等待和 LDAP 连接硬上限 |
| `internal/plugin` | 52 个插件注册与旧 mode 规则迁移；SQL 参数排序/上下文/通用条件错误/最佳证据；Multipart 多文件字段；XSS 可执行上下文；安全头与重复 Cookie；SSRF 反射负例；XXE/命令/JNDI 批量等待；JWT 主动校验、代理信任头、TRACE 及其余插件正反例 |
| `internal/engine` | 原子有限队列、删除取消 TTL、四阶段顺序、状态变更独占、插件失败覆盖率、L5 可信分、预检基线复用、会话提取流水线 |
| `internal/api` | V1 兼容接口、V2 稳定 Code/中文 Label/类别/可信分/关联 ID/规则摘要、Lite 证据裁剪、默认 Normal/Auto、失败连通性短路、前端嵌入资源 |

## 3. 最终执行命令与结果

```sh
go test ./... -count=1
go test -race ./internal/callback ./internal/httpraw ./internal/transport \
  ./internal/engine ./internal/api ./internal/plugin -count=1
go test -cover ./... -count=1
go vet ./...
```

最终结果：全部通过；Race Detector 未发现数据竞争；`go vet` 无告警。

最终语句覆盖率（命令入口与纯数据模型不计入质量阈值）：API 65.2%、Callback 58.0%、Config 77.9%、Diff 95.3%、Engine 71.4%、HTTP Raw 62.8%、Plugin 69.2%、Response Body 81.6%、Transport 67.9%。覆盖率不是漏洞检出率；插件测试仍以判定链正例、Payload 反射/统一错误页等负例及现场已知样本复核为准。

浏览器实机检查结果：

- 首页显示 V2.4，注册插件数量为 52。
- Normal 预设选择 12 个插件；Passive、Custom、Deep 可切换。
- 版本页展示 V2.4 SQL 专项更新项，并保留 V2.3、V2.1、V2.0 架构图和历史记录。
- 进度面板同时展示请求级百分比、实际发包、收敛跳过和覆盖率；结果区不再重复覆盖率面板。
- 持久配置展示最大排队任务、进程全局并发/RPS、单 Host 并发和 HTTP/LDAP 回连参数。
- 持久配置展示 LDAP/JNDI 最大并发连接；动态会话说明覆盖 Header、Query、JSON、Cookie、Form、Multipart。
- 使用说明从内嵌 `docs/plugins.md` 离线渲染，左侧目录可定位各插件章节。
- 页面全局英文与 Raw HTTP 编辑器使用同一个等宽字体栈。

## 4. 插件结论正确性的边界

自动化测试证明的是：在受控响应满足判定链时能够发现，在典型负例不满足判定链时不会误报，并且并发执行没有已知竞态。它不能证明任意目标上的零漏报。生产测试仍应遵守以下规则：

- `L5`：独立一次性 OAST 回连或重复无害执行证据，可信度最高。
- `L4`：真假条件、破坏/恢复、双随机算术或重复请求等成对证据。
- `L3`：唯一框架/数据库错误签名，并经过基线排除。
- `L2`：单一差分或启发式响应，需要人工复核。
- `L1`：被动指标或配置提示，不等价于可利用漏洞。

扫描报告还应结合 `coverage` 查看插件是否完整执行。`failed`、`partial` 或预算耗尽均不能解释为“目标无漏洞”。

## 5. 离线和高性能验收标准

- 运行时不包含更新检查、遥测、云 API 或外部规则下载；所有页面、规则和文档嵌入本地程序。
- Go 二进制使用 `CGO_ENABLED=0` 构建，Linux 服务器不需要 Python、Go、Docker 或联网安装依赖。
- 性能限制同时存在于任务、进程和目标 Host 三层；状态变更插件独占执行，其他安全主动插件并发执行。
- HTTP OAST 默认使用 61166，LDAP/JNDI 安全接收器默认使用 61167；两者仅接收一次性 Token。

## 6. 建议的现场验收

在被授权测试环境准备一组已知正例和已修复负例，每个插件至少包含：明确漏洞、统一 500、Payload 原样反射、鉴权失效、WAF/限流五类响应。使用相同原始报文分别执行 Normal 与 Deep，核对请求预算、覆盖率、证据强度和人工复现结果。涉及状态变更、上传和短信的插件应使用隔离测试数据。
