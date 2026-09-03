# jungle_happy_Scan V2.0 架构设计

## V2.4 SQL Oracle Lane

V2.4 不改变 V2 API 或四阶段总体架构，只重构安全主动阶段中的 SQL 家族：

```text
代表性基线（medoid）
        ↓
SQL 插入点排序 / 词法与语义上下文分类
        ↓
独占 SQL Oracle Lane
        ├─ 核心 Gate → 原子 A-B-B-A 错误恢复 / 条件错误 / 布尔
        ├─ SQL 扩展上下文与时间 A-B-B-A
        ├─ ORDER BY / LIMIT-OFFSET
        └─ MyBatis 双 canary（复用已有基线）
        ↓
数据库错误 + 内容指纹 + 同路径业务状态 + 时间 Oracle
        ↓
证据分级 / 真实覆盖状态 / 未用预算返回任务共享池
```

Gate 只提供适用性，不能成为漏洞证据。A-B-B-A 和 MyBatis 双请求都在首条发送前完整预留，避免预算边界形成半观察。SQL 家族串行，但 SQL 之外的安全主动插件仍按原并发模型执行。

## 1. 设计目标

V2.0 仍然只接收一条 Burp Suite Raw HTTP 报文，但把“能发送 Payload”提升为“结论可信、覆盖可解释、旧 Java Web 兼容、并发可治理”。运行环境不需要 Python、Go、数据库或互联网；HTML/CSS/JavaScript、默认规则和使用手册均嵌入静态 Go 二进制。

## 2. 总体架构

```text
Web UI / V1 API / V2 API
              │
              ▼
严格输入校验 ─ HTTP→HTTPS 连通性预检 ─ 成功响应复用为首基线
              │
              ▼
Burp Raw 解析器 ─ 无损插入点 ─ 会话/签名/轮换 Token 流水线
              │
              ▼
前台预设展开为插件 ID ─ 插件 ID 即完整能力 ─ 无隐藏 Payload 强度
              │
              ▼
扫描计划器 ─ 适用性 ─ 请求估算 ─ 公平预算 ─ 覆盖率
              │
              ▼
① 被动分析 → ② 安全主动并发 → ③ OAST 并行确认 → ④ 状态变更独占
              │
              ▼
任务并发/RPS + 进程全局并发/RPS + 单 Host 并发 + 有限任务队列
              │
              ▼
HTTP/HTTPS/Host 映射/Raw HTTP1 ─ HTTP 61166 + LDAP 61167 一次性回连
              │
              ▼
字符集解码 ─ JSON/HTML 动态归一化 ─ 头/中/尾长响应特征
              │
              ▼
命中点证据窗口 ─ L1–L5 强度 ─ 去重/关联 ─ V1 兼容 / V2 稳定报告
```

## 3. 输入和变异层

- 解析标准请求行、Header、Cookie、Query、Form、JSON、XML、Multipart；支持 LF/CRLF Burp 报文和文本文件上传原字节保留。
- JSON 扫描器记录每个标量的原始字节偏移，变异时只替换一个值。字段顺序、空白、科学计数法和超过 JavaScript 安全整数范围的 ID 不会被全量反序列化破坏。
- JSON 根数组、数组中对象、深层数组、GraphQL variables、Base64 包裹 JSON 均递归发现。
- XML 同名元素/属性按 occurrence 变异，避免一次 Payload 修改所有同名节点。
- 未授权访问统一根据 Key 在 Header、Cookie、Query、Form、Multipart、JSON 对象/数组中删除或失效全部凭据。

## 4. 基线、会话和响应层

- 同步 API 的原始连通性响应复用为首基线；剩余样本用于动态稳定性判断。
- 请求变换在每次发送前执行；响应提取器在每次响应后更新 Session/CSRF/nonce，并可写回 Header、Query、JSON、Cookie、Form 或 Multipart。Query/JSON 使用定位替换，不重排无关字段或损坏超大整数。轮换规则默认执行原子“写入→发送→提取”串行流水线，避免一次性 Token 被并发抢用；只有所有规则显式标记 `parallel_safe` 时才采用快照并发。
- 响应读取受 `max_response_bytes` 约束，并明确返回 `truncated`、`raw_bytes` 和 `charset` 元数据。V2 Full 的 finding evidence 另外返回完整响应头；正文不超过 64 KiB 时完整保留，超过后围绕关键证据上下各 30 行（最多 61 行）；缺少显式 marker 时先使用响应与代表性基线的差异定位，再使用 markerless 兜底。`response_capture_truncated` 与 `response_context_clipped` 分别表示捕获截断和证据视图裁剪，旧 `response_truncated` 对两者兼容置真。
- `Content-Type charset` 或 HTML meta 标记为 GBK/GB2312/GB18030 时，进入插件前转 UTF-8；缺少声明、属于文本响应且不是合法 UTF-8 的旧中文页面按 GB18030 兼容解码。二进制响应不会被猜测成中文文本。
- JSON 响应移除动态 Key；HTML/JSP 移除注释、脚本/样式噪声、标签和隐藏动态值后比较。超长响应保留头部 50%、中部 20%、尾部 30% 的有界样本。

## 5. 调度与资源治理

| 层级 | 配置 | 作用 |
|---|---|---|
| 单任务 | `max_concurrency` | 一个扫描任务的连接并发 |
| 单任务 | `requests_per_second` | 一个任务的令牌桶速率 |
| 单任务 | `max_requests` | 插件公平预算总上限 |
| 进程 | `global_max_concurrency` | 所有任务共享的连接并发 |
| 进程 | `global_requests_per_second` | 所有任务共享的速率 |
| 目标 | `per_host_concurrency` | 同一 Host 跨任务并发 |
| 队列 | `max_active_scans` / `max_queued_scans` | 活跃任务和有限排队 |

阶段 1–3 内部可并发；文件上传、短信、CSRF、Mass Assignment、Method Override、IDOR、JWT 主动验证和代理信任头等状态变更插件在阶段 4 逐个运行。Normal、Deep 和 Custom 只负责把预设展开成插件 ID；同一插件在任何入口下执行完全相同的规则。SQL 核心、扩展差分和时间盲注是三个独立插件，一个插入点获得可靠证据后各自在自己的能力范围内短路。任务取消通过 Context 传播到队列、限流等待、网络请求和回连等待。

有限队列容量检查与任务插入使用同一临界区，不会因并发调用超卖；单一调度器先取得活跃任务槽再启动任务，因此大量排队任务不会各自占用等待 goroutine。同步调用删除任务时同时取消 TTL 计时。单 Host 限流器按空闲时间回收，调用方每分钟限额表按固定周期清理；响应归一化和正则编译使用有界缓存。LDAP Sink 默认最多接受 128 个并发原始连接（可在前台配置），防止长期运行时内存或 goroutine 无界增长。

传输层在最接近真实发包的位置原子预留请求预算，先等待任务级并发/RPS，再申请进程与目标资源，避免排队任务无效占用全局槽。响应超过 `max_response_bytes` 后仅做有界排空以争取复用 Keep-Alive，不会为复用连接无限读取大响应。

## 6. OAST 安全边界

- HTTP 61166 服务只接受随机 Token 路径，不暴露管理 API。
- LDAP 61167 Sink 只返回最小匿名 Bind 成功，让客户端继续发送包含 Token 的 Search DN；随后关闭连接。
- 不返回 LDAP Entry、JNDI Reference、Java class、序列化对象或 gadget。
- Token 十分钟过期，格式严格校验、注册数量有硬上限，第一次命中后拒绝重复，Wait 消费后从内存删除；后台定期清理过期项。
- SSRF、XXE、OS 命令和 JNDI 的多个 Payload 均先发送后批量等待，共享同一个 8 秒窗口，不按探针累计等待；HTTP 回连只在独立 61166 端口开放，管理端口 8888 不提供回连路由。
- 回显在响应中的 callback URL/Token 不构成 SSRF 或 L5 证据；必须由独立回连监听器确认。

## 7. 结论与接口

插件错误、网络异常和预算不足分别呈现为 `failed`、`failed/partial`、`partial`；只要存在 failed/partial，`coverage.complete` 就是 false。证据强度分为：

- L1：被动指标；
- L2：差分启发式；
- L3：唯一错误/强指纹；
- L4：成对、反序或重复确认；
- L5：严格一次性回连或执行级证据。

V1 接口保留中文 `severity`/`confidence`。V2 使用稳定英文机器码，并额外返回中文 Label、类别、可信分、关联 ID、`api_version`、`rule_pack_version`、`rule_pack_digest`、证据强度和响应完整性/上下文状态。规则摘要由当前插件规则及全局成功/拒绝/动态正则确定，便于调用方判断两次结果是否使用相同规则集。证据响应视图不是字节级网络报文，也不承诺返回完整响应正文。

## 8. 离线与依赖

源码构建期 vendoring `golang.org/x/text` 的字符集实现；发布时通过 `CGO_ENABLED=0` 为 Linux AMD64/ARM64 和 macOS ARM64 生成静态二进制。运行时不解析第三方 API、不访问 CDN、无遥测、无在线更新、无许可证校验。只有目标报文 Host、管理员配置的同源相邻路径和目标主动回连到本机端口属于扫描网络流量。
