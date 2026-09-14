# 目标

让调用方可以仅通过应用名选择服务器内置的 JavaScript 请求签名脚本，避免为每次扫描重复传递脚本绝对路径、运行时和超时配置。

# 范围

- 为所有现有支持签名的入口新增可选 JSON 字段 `signature_app_name`。
- `signature_app_name` 的值直接映射为固定目录 `config/signature_scripts/<应用名>.js` 中的脚本；例如 `"FS_PMC"` 映射到 `FS_PMC.js`。
- 保留现有 `signature` 对象调用格式，包括 HTTP 签名器和本地脚本模式。
- 当请求同时包含 `signature_app_name` 和 `signature` 时返回参数错误，避免签名器选择不明确。
- 为路径安全、脚本不存在、脚本执行与现有调用兼容性补充测试，并更新 API 文档。

# 非目标

- 不删除或迁移现有签名脚本。
- 不修改签名脚本的 Base64 输入/输出协议。
- 不改变现有 `signature` 对象的字段、默认值或 HTTP 签名器行为。

# 验收示例

Scenario: 应用名选择本地签名脚本
- GIVEN 固定脚本目录中存在 `FS_PMC.js`
- WHEN 任一支持签名的扫描入口收到 `"signature_app_name":"FS_PMC"`
- THEN 扫描器以该脚本和默认 Node 运行时重签每次变异后的请求。

Scenario: 旧签名对象保持可用
- GIVEN 调用方提供现有 `signature` 对象
- WHEN 请求进入任一支持签名的入口
- THEN 现有 HTTP 或本地脚本签名行为保持不变。

Scenario: 不明确或不安全的应用名被拒绝
- WHEN 请求同时提供 `signature_app_name` 与 `signature`，或应用名不能安全映射到固定目录下的 `.js` 文件
- THEN 接口返回 `400`，且不会执行目录外的脚本。

# 约束与不变量

- `signature_app_name` 是唯一规范 JSON 字段名。
- 应用名仅用于构造固定目录内的 `<应用名>.js` 路径；不得接受路径分隔符或目录跳转。
- 应用名与脚本基名按大小写不敏感方式匹配；若固定目录中存在仅大小写不同的多个候选脚本，必须拒绝请求并报告歧义。
- 固定目录仍相对扫描器配置目录解析为 `signature_scripts`。

# 决策

- 覆盖同步、异步、连通性测试和爆破等全部既有签名调用入口。
- 新字段采用 `signature_app_name`，示例值为 `FS_PMC`；不引入 camelCase 别名。
- 旧 `signature` 对象兼容保留；两种形式不得在同一请求混用。
- 应用名映射不区分大小写以提高调用容错性；同目录中仅大小写不同的候选脚本视为歧义并拒绝。

# 待解决问题

无。

# 验证预期

- 运行签名、API 与引擎相关 Go 测试。
- 检查应用名无法越过固定目录，且旧调用格式仍通过。
