# V3.8.1 发布说明

V3.8.1 针对 Spring/Spring Boot、MyBatis、JDBC 和银行 Java 接口的 SQL 注入扫描，收敛插件入口并重做时间盲注确认。目标是让快速扫描的成本可控，让深度扫描能够覆盖真实报文中的闭合差异，同时减少固定慢响应、网关异常和业务状态变化造成的误报。

## 插件入口

公开选择只保留两个 SQL 能力：

- `sqli`：快速。包含单引号破坏、双单引号恢复、PostgreSQL 字符串拼接恢复、条件错误和按参数类型选择的数字/字符串/LIKE 布尔差分。它不发送时间延迟或堆叠语句。
- `sqli_deep`：深度。包含快速能力，并增加双引号、括号、注释、OR、CAST、ORDER BY、LIMIT/OFFSET、MyBatis 动态片段、MySQL/PostgreSQL/GaussDB 时间盲注和无数据读写的堆叠时间探测。

Normal 默认选择 `sqli`，Deep 选择 `sqli_deep` 并自动去掉重复的 `sqli`。同时提交两个 ID 时服务端只执行深度。旧版本的 `sqli_extended`、`sqli_timing`、`sqli_order_by`、`sqli_limit` 和 `mybatis_dynamic_sql` 仍可被调用，并映射为深度；旧规则桶和管理员自定义规则保留。

## 时间盲注修复

此前时间插件的主要不足是：依赖少量固定闭合形式；部分 Payload 在保留原业务值后语法上下文已经改变；确认只比较一次长延迟和零延迟，没有验证延迟剂量是否随设定值变化；所有 5xx 被直接排除，导致“SQL 已执行延迟、Java 随后统一返回 500”的接口漏报；旧 OR 形式还同时改变了真假条件和查询工作量。

V3.8.1 补充了以下覆盖：

- `SLEEP(3)` 的精确替换及原值追加；
- `pg_sleep(3)` 的显式比较形式和用户提供的 `SELECT 1 FROM pg_sleep(3)` 形式；
- `') AND 5014=(SELECT 5014 FROM pg_sleep(3)) AND ('1'='1` 括号闭合；
- 单层、双层括号，LIKE 尾部，OR、XOR、字符串拼接和注释终止；
- MySQL、PostgreSQL、兼容 GaussDB 的分号堆叠延迟探测；
- 稳定应用 500 的延迟证据，以及鉴权、限流、网关错误和传输超时的排除。

时间确认使用六条请求的 `A-B-B-A-C-A` 顺序。A 是零延迟控制，B 是设定延迟，C 是半时长延迟。先发送 A/B 两条，只有达到延迟门槛才继续四条；最终同时要求两次长延迟、半时长延迟、局部控制抖动和延迟剂量关系成立。固定慢响应、全体请求变慢、单次尖峰和只改变 HTTP 状态的响应不会被确认。

标准 PostgreSQL 的 `AND` 操作数需要是布尔值，因此用户提供的第二条报文是否可执行取决于外层 SQL、兼容模式和前置条件。扫描器保留该实测形式，同时补充显式比较的 PostgreSQL 形式。`pg_sleep` 是否实际执行也可能受优化器、函数权限、连接超时和请求行数影响。

堆叠探测只使用 `SELECT SLEEP/pg_sleep`，不读取业务数据，不执行 INSERT、UPDATE、DELETE 或 DROP。Java 技术栈不等于一定支持堆叠；例如 MySQL Connector/J 的 `allowMultiQueries` 默认关闭，驱动和连接池配置会决定分号语句是否到达数据库。

## 配置升级

配置版本升为 32。升级会保留旧规则和自定义 Normal 列表；旧 Normal 中的 `sqli_extended` 合并到快速，时间、排序、分页、MyBatis 等专项只有在列表中明确出现时才映射为深度，不会因为升级自动增加深度请求。新增内置时间规则使用 0 秒/3 秒成对控制，旧 OR 时间规则会修复为相同真假尾部，避免把逻辑结果变化混入时间差。

## 使用示例

快速：

```json
{"http":"GET /search?q=abc HTTP/1.1\r\nHost: test.local\r\n\r\n","scheme":"http","scan_type":["sqli"]}
```

深度：

```json
{"http":"GET /search?q=abc HTTP/1.1\r\nHost: test.local\r\n\r\n","scheme":"http","scan_type":["sqli_deep"]}
```

默认全任务 `max_requests=500` 由所有选中的插件共享。多参数深度扫描可能因预算不足进入 `partial`，应同时查看 `requests_sent`、`adaptive_pruned`、`budget_skipped` 和 `mutation_failed`。完整使用说明见 [插件手册](plugins.md) 和 [API 文档](API.md)。
