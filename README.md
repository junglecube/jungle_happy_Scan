# jungle_happy_Scan V3.6

当前源码版本：`v3.6.3`。

## V3.6.3 更新

- 内网 HTTPS 扫描默认关闭证书校验（`verify_tls=false`），可显式开启严格校验；HTTP/1.1、代理和 mTLS 兼容模式保持不变。
- Full 扫描 API 返回最终扫描结果，Evidence 保留完整响应头并按命中位置提供最多 30 行、64 KiB 的有界上下文，同时明确区分捕获截断与证据截取。
- Evidence 的选中 Request、Response Header/Body 和响应片段保留原文，不执行脱敏；旧 `redact_evidence` 字段继续兼容但不再改变输出。
- 提供 Linux AMD64 与 ARM64 的静态离线安装包，内含对应二进制、配置文件及 `install.sh`、`start.sh`、`stop.sh`、`status.sh`，两种架构使用相同启动方式。

## V3.6 更新

- 全局使用离线 CodeMirror 6 处理 HTTP 报文编辑、查看、语法高亮、折行、选区和光标，长 Cookie/JWT 单行不再因前后台排版不一致造成光标错位。
- 扫描引擎采用 Go 并发调度、分层分级扫描和请求预算控制；先进行低成本筛选，再对命中点执行配对确认，避免无差别全量发送 Payload。
- SQL 注入核心、拓展和时间盲注扫描不再把 Cookie 或普通 Header 作为 SQL 插入点，降低无关请求和误报。
- 时间盲注支持可配置的对照/延迟 Payload，并通过多次时间差确认，HTTP 200 延迟响应也可作为有效证据。
- Normal 模式的默认插件可在持久配置中维护并保存；现有配置升级时保留管理员规则和自定义参数。
- 支持代理导入 PEM/PFX/P12 客户端证书，用于访问需要上游 mTLS 的 HTTPS 站点。
- 漏洞名称统一优化为“反射型XSS”；证据保留请求、响应头和命中上下文原文，不执行脱敏。
- 配置版本自动升级到 31，V3.6 之前的配置文件可直接继续使用，无需手工改写。

V3.3重点优化管理前端性能：人工拦截由200毫秒轮询升级为事件驱动长轮询；资产、扫描进度、漏洞和拦截使用独立Revision，避免一次轻量变化重载整页；长HTTP报文、高亮结果和漏洞证据按接口缓存，进度变化只更新轻量元数据。所有HTTP报文视图固定宽度并自动折行，不再产生横向滚动。创建任务表单压缩为一行主配置，目标URL的Host自动成为作用域；静态资源过滤支持“内置默认后缀＋管理员追加后缀”。V3.2本地恢复、跨任务历史与V2.4扫描内核全部保留。

普通 HTTP 流量可捕获并人工拦截，捕获到的原始上游响应直接作为 V2 扫描首基线。未安装 HappyScan CA 时，HTTPS/mTLS `CONNECT` 仅透明转发：客户端证书由浏览器使用，HappyScan 不读取 TLS 明文，也不宣称可修改 HTTPS。原 V1/V2 单报文接口、同步接口和插件规则继续兼容。

V3.2命令注入规则覆盖`;`、`|`、`||`、`&&`、换行、反引号和`$()`上下文；输出canary、成对时间差分与唯一HTTP回连仍采用独立强证据判定。`backuppath`已作为显式候选，反引号curl回连可检测路径值进入Shell命令替换的无回显执行。

V2.4 只专注 SQL 注入插件族。核心 SQL 将单引号 Gate 限定为错误恢复分支的适用性信号，数值/布尔上下文不再被误剪枝；所有确认均使用原子 A-B-B-A 请求组。新增递归 JSON 同路径业务结果、JSP 成功/失败语义、长响应完整 Body 精确 Oracle、未知数据库有界回退、PostgreSQL/GaussDB ORDER BY 与 LIMIT/OFFSET 条件错误对、MyBatis 双 canary 基线复用。SQL 规则选择最高价值错误证据，管理员可配置简化正则的默认可信度。

调度层把全部 SQL 家族放入独占 Oracle Lane，自适应剪枝未使用的额度会返回任务共享预算。计划和结果明确区分已发送、自适应剪枝、变异失败与预算跳过；Gate、四请求组和 MyBatis 双请求组的估算与原子性保持一致。响应指纹保留重复业务行、原始截断长度和 JSP 内联脚本业务数据；JSON 请求支持 `application/*+json` 及合法正文嗅探，XML 属性变异精确转义。

V2.3 新增普通参数值及 Base64 参数值中的 JSON/XML 递归插入点，并提供跨 Query、Form、JSON、Multipart、Cookie、Header 的全局扫描排除参数名。Java 专项补齐 Shell、Runtime.exec/ProcessBuilder、Groovy/ScriptEngine、SpEL、Thymeleaf、FreeMarker、Velocity 等无害上下文探针；Fastjson 插件收敛为 SafeMode 安全基线。

V2.2 将总体进度改为按计划请求槽位计算，并把插件实时进度、实际请求、预算和最终状态合并到逐插件覆盖率行。核心 SQL 和输入诱导异常插件采用“低成本筛选 → 命中后配对确认”；扫描中心把 52 个插件按漏洞族分组，桌面端每行两个卡片。

面向已授权测试环境的主动 Web/API 漏洞扫描器。输入 Burp Suite Raw HTTP 报文，选择插件后扫描，并通过管理页面、轮询 API、SSE 或同步总接口获取结果。

V2.0 在保持单个静态 Go 可执行文件、离线运行和无数据库的基础上重构精度与调度内核：无损 JSON 单值变异、XML 同名节点 occurrence 定位、GBK/GB2312/GB18030 JSP 解码、长响应头/中/尾分段归一化、命中点证据窗口、L1–L5 证据强度、真实失败覆盖率、连通性基线复用和逐响应动态 Token 刷新。插件按被动分析、安全主动、OAST、状态变更独占四阶段运行，SQL 等高成本插件按证据信号停止后续升级，并由进程级、单目标并发及全局 RPS 共同治理。

V2.0 新增 Apache Shiro RememberMe 已知密钥安全验证、Java SpEL/Thymeleaf/FreeMarker/OGNL/JSP EL 无害算术求值、JNDI/Log4j LDAP 一次性回连和 Host Header 信任注入；扩展 Spring Boot Actuator/management 探测。本次白盒收口再加入 JWT 签名校验绕过、反向代理信任头权限绕过和 HTTP TRACE 精确反射检测，并把时间、回连、编码绕过和执行确认等高成本能力拆成 11 个显式插件，插件总数为 50。Normal、Deep 与 Custom 现在只选择插件组合；选择同一个插件时，执行逻辑不再受隐藏的 mode/standard/deep 参数影响。JNDI 监听器只确认随机 Token，不返回远程类、序列化对象或命令。

SQL 注入核心插件增加严格的单引号破坏/双单引号恢复差分：按“破坏、恢复、恢复、破坏”顺序重复验证。即使 Spring/CTP 把数据库异常包装成普通业务 JSON，只要单引号响应稳定偏离、双单引号响应稳定回到原始基线，也会给出较确定结论；扫描器不使用数据提取 payload。

扫描页支持先测试原始报文：可选择自动、HTTP 或 HTTPS 协议，右侧直接显示 Response。自动模式能够识别“HTTP 服务被按 HTTPS 访问”的常见 Burp Raw 报文协议问题。

V1.1 增加插件规则中心：SQL 注入、XXE、文件读取、文件上传、敏感信息、XSS、SSRF、CORS、命令注入等 payload、参数名、路径和响应正则均可在 Web 端编辑并持久保存。扫描结果证据统一按 Request、Response 展示，Response 内严格采用状态行、Header、空行、Body 顺序。

V1.2 将原 V1.1.1 的功能正式合并升级：管理页面默认显示“扫描中心”、“持久配置”和“版本更新”，也可以使用 `/?config=true` 或 `/?version=true` 直接进入对应页面。外部 API 可只调用 `POST /api/v1/jungle_happy_scan`，连接返回时直接得到最终扫描状态和漏洞数组；V1.4 已将该同步接口收敛为独立的三字段契约，详见下文和 API 文档。

V1.2 当时共 28 个插件，新增输入诱导异常信息泄露、NoSQL/LDAP/XPath 注入、Java 不安全反序列化入口、HTTP Method Override、Mass Assignment 和 GraphQL 专项检测。所有新增 Payload 与检测正则均可在持久配置中维护。

V1.3 新增扫描计划器、公平请求预算和逐插件覆盖率报告，能够明确区分“完整执行”“预算内部分执行”和“不适用跳过”。发现结果统一加入可信分、结论类别、去重和同输入点关联；协议层新增 URL 路径、业务 Cookie、可配置 Header、XML 属性/CDATA、GraphQL variables、multipart 文件名及 Base64 JSON 嵌套变异，并支持强制或 Raw HTTP/1.1。动态签名、响应 Token 提取、共享服务限流、目标白名单强制和管理 CIDR 均可在前台持久配置。

V1.31 面向 Spring/Spring Boot、MyBatis、存储过程和 CTP 类框架新增 MyBatis 动态 SQL 片段注入、URL 路径归一化权限绕过、HTTP 参数污染/身份优先级混淆、Jackson/Fastjson 多态反序列化入口；同时重构 Method Override 与 Mass Assignment，覆盖 Spring `_method`、JSON 根数组、Query/Form/Multipart 和混合绑定。扫描中心提供 Passive、Normal、Custom、Deep 四档选择，插件总数为 32。

V1.4 新增高并发短信轰炸/喷洒插件，以同步屏障并发发送并统计一分钟内成功响应；SQL 注入增加 GaussDB JDBC/内核异常与 `pg_sleep` 对照；命令注入改用请求中不存在的算术计算结果三步确认。OpenAPI 与 GraphQL 完全拆分，Normal 模式精简为全部被动插件和 9 个常用主动插件，漏洞报告的严重性、置信度及结论类别统一输出中文。插件总数为 33。

V1.4 的任意文件读取规则同时覆盖 `/etc/passwd`、`/etc/hosts`、`/proc/version` 与 `/etc/os-release`，包含绝对路径、目录穿越、编码和路径归一化变体；命中后必须再次请求并重复出现文件强指纹才报告。旧配置升级时自动补齐规则并保留管理员自定义项。

V1.4 修正 Jackson/Fastjson 多态结果分级：SafeMode/验证器拒绝仅作为防护生效提示，ClassNotFoundException 随机类型作为危险加载入口，普通不存在子类型降为中危入口。Normal 模式为 SQL 注入和异常泄露启用核心 Payload，Custom/Standard 与 Deep 保留完整规则。同步 `jungle_happy_scan` 只传 `http` 时默认使用 Normal 和自动协议，也可通过 `["passive"]`、`["normal"]`、`["deep"]` 选择预设；V1.41 进一步增加可选 `host` 映射。

外部调用方如不需要保存 HTTP 请求/响应证据视图，可调用 `POST /api/v1/jungle_happy_scan_lite`；其入参和扫描结果与同步总接口一致，但每条 evidence 不返回 `request` 和 `response`。

V1.41 修正多凭据未授权误报，并支持无鉴权字段的必登录接口判定；短信轰炸和喷洒均提升为 30 请求并发批次；Auto 协议按 HTTP 优先、失败后 HTTPS；同步接口增加可选 `host` 域名到 IP 映射，并在创建扫描任务前测试原始报文连通性。主程序默认额外启动 `0.0.0.0:61166` 一次性 Token 回连服务，供 XXE、SSRF 与 Deep OS 命令无回显确认。敏感信息新增微信小程序 AppSecret，前端新增离线“使用说明”页面。

## 交付特性

- 单个 Go 静态可执行文件；目标服务器不需要 Python、Go、Docker 或联网安装依赖。
- 支持 Linux x86_64、Linux ARM64 和 macOS ARM64；不支持 Windows。
- 页面和全部前端资源嵌入可执行文件，不使用 CDN、遥测或在线更新。
- 管理页面与扫描接口默认监听 `0.0.0.0:8888`；WEB 扫描代理默认填写 `127.0.0.1:8088`（部署在服务器供远程浏览器使用时需改为服务器可达监听地址）；HTTP 一次性回连默认监听 `0.0.0.0:61166`，只收 Token 的 LDAP/JNDI 回连默认监听 `0.0.0.0:61167`，不启用 API Key。
- 外部扫描 API 保持无 API Key；持久配置写入需要管理密码，可通过 `JUNGLE_CONFIG_PASSWORD` 环境变量设置。
- 不使用外部数据库；单报文任务按 TTL 回收，WEB任务按每任务2000个接口及报文大小设硬上限，并在`var/webscan_state`保存权限受限的压缩恢复文件。进程重启后恢复为已停止任务，不自动重放未完成Payload。
- 有限任务队列原子入队；同步删除会取消 TTL 生命周期；单 Host 限流器自动回收，LDAP/JNDI 并发连接有可配置硬上限。
- 配置保存在本地 JSON 文件，管理页面可配置全部运行参数。
- 内嵌 `jungle.jpg` Logo 和浅色 HTTP 语法高亮编辑器，不依赖第三方前端资源。

## 一键离线安装

将以下两个文件放在同一目录：

- `jungle_happy_Scan-v3.6.tar.gz`
- `jungle_happy_Scan-v3.6.tar.gz.sha256`（建议一并复制）
- `install_jungle_happy_Scan.sh`

执行：

```bash
chmod +x install_jungle_happy_Scan.sh
./install_jungle_happy_Scan.sh
```

默认安装到当前目录的 `jungle_happy_Scan-installed`。服务器上可安装到 `/opt`：

```bash
SCANNER_INSTALL_DIR=/opt/jungle_happy_Scan ./install_jungle_happy_Scan.sh
```

安装脚本自动识别操作系统和 CPU 架构，选择包内二进制并启动服务。整个安装过程不连接互联网。

从 V2.4/V3.x 原目录升级时仍将 `SCANNER_INSTALL_DIR` 指向原安装目录。脚本先校验交付包和当前平台二进制，再停止旧 PID、原子替换、启动 V3.6.3，并验证 `-version` 与 `/api/health`；`config/`、客户端证书和 `var/` 不包含在交付包中，不会被归档内容覆盖。若管理端口不是默认值，可通过 `SCANNER_HEALTH_URL` 指定健康检查地址。

页面和健康检查：

```text
http://服务器IP:8888/
http://服务器IP:8888/?single=true
http://服务器IP:8888/?config=true
http://服务器IP:8888/?version=true
http://服务器IP:8888/api/health
```

## 日常管理

```bash
cd /opt/jungle_happy_Scan
./start.sh
./stop.sh
./status.sh
```

日志位于 `var/jungle_happy_Scan.log`，PID 文件位于 `var/jungle_happy_Scan.pid`，配置位于 `config/config.json`。

共享部署建议在启动前设置配置管理密码：

```bash
export JUNGLE_CONFIG_PASSWORD='替换为高强度密码'
./start.sh
```

也可以将密码单独写入仅管理员可读的 `config/config-password`（建议权限 `600`），`start.sh` 会自动读取；该文件不会由程序创建或写入。

## 从源码构建

源码使用 Go 1.26；字符集解码依赖已完整 vendoring 到仓库，构建过程不需要联网：

```bash
./build_release.sh
```

脚本使用根目录 `VERSION` 作为唯一版本源，在 `bin/` 生成各平台静态二进制及 SHA-256，在 `release/` 生成完整源码交付包，并在 `release/minimal_packages/` 生成 Linux/Windows 最小包。构建机需要 Go 1.26，目标部署机不需要。

## 文档

- [HTTP API](docs/API.md)
- [能力、模式与限制](docs/CAPABILITIES.md)
- [插件扫描逻辑与持久配置手册](docs/plugins.md)
- [V3 WEB 扫描架构设计](docs/ARCHITECTURE_V3.md)
- [V3 验证矩阵与报告](docs/TESTING_V3.md)
- [V2.0 架构设计](docs/ARCHITECTURE_V2.md)
- [V2.4 验证报告](docs/TESTING_V2.md)
- [V2 MCP Tool 标准](jungle_happy_scan_MCP_V2.txt)

> 本项目按要求没有扫描 API 认证并监听所有网卡。请只部署在已授权的测试/管理网络中；任何能够访问 8888 端口的人都可以创建主动扫描任务。配置写入受管理密码保护，可配置管理 CIDR、来源任务限额、目标白名单和共享服务安全模式。
