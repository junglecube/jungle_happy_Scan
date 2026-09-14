---
generated_from_state_version: 22
---

# 验证

## 当前结果

- 结果: **已归档**
- 验证情况: **已完成检查，验证结果已确认**
- 目标周期: 2
- 迭代: 2
- 验证器尝试次数: 2
- 完成时间: 2026-09-14T08:37:06.428Z
- 摘要: 最终独立复核通过：go test ./... 全绿，A1-A8 全部通过，无阻塞。

## 验收

| 编号 | 结果 | 来源 | 验收项 | 原因 |
| --- | --- | --- | --- | --- |
| A1 | passed | brief.md | GIVEN 固定脚本目录中存在 `FS_PMC.js` | 固定配置目录仅枚举常规 .js 文件，测试创建并映射 FS_PMC.js。 |
| A2 | passed | brief.md | WHEN 任一支持签名的扫描入口收到 `"signature_app_name":"FS_PMC"` | 所有既有签名入口和同步 Lite/非 Lite V1/V2 路由均已接入解析器。 |
| A3 | passed | brief.md | THEN 扫描器以该脚本和默认 Node 运行时重签每次变异后的请求。 Scenario: 旧签名对象保持可用 | 映射生成默认 Node 的 local_js 签名器，签名在传输层每次发送前执行。 |
| A4 | passed | brief.md | GIVEN 调用方提供现有 `signature` 对象 | 旧 signature 字段与 HTTP/local_js 行为未变。 |
| A5 | passed | brief.md | WHEN 请求进入任一支持签名的入口 | 新字段转换为既有 SignatureInput 后沿用原有引擎/重放调用链。 |
| A6 | passed | brief.md | THEN 现有 HTTP 或本地脚本签名行为保持不变。 Scenario: 不明确或不安全的应用名被拒绝 | 全量测试通过，旧 HTTP 签名端到端测试仍通过。 |
| A7 | passed | brief.md | WHEN 请求同时提供 `signature_app_name` 与 `signature`，或应用名不能安全映射到固定目录下的 `.js` 文件 | 混用、路径、缺失和大小写歧义均被拒绝，覆盖单测。 |
| A8 | passed | brief.md | THEN 接口返回 `400`，且不会执行目录外的脚本。 | 解析失败由全部 handler 转为 400，解析过程不执行目录外脚本。 |

## 检查

_没有记录 Runtime 检查。_

## 阻塞项

_无。_

## 风险与跳过的工作

_未报告风险。_

## 之前的迭代

| 目标周期 | 迭代 | 尝试 | 结果 | 未解决项 | 摘要 | 完成时间 |
| ---: | ---: | ---: | --- | --- | --- | --- |
| 1 | 0 | 0 | recovery | — | Native confirmed acceptance criteria changed | 2026-09-14T08:05:22.800Z |
| 2 | 1 | 1 | blocked | A1, A2, A3, A4, A5, A6, A7, A8 | 独立验证被仓库基线的冲突标记阻断。确认 d385a8c 未引入该阻断，静态实现符合范围，但所有验收均无法进行运行时验证。 | 2026-09-14T08:15:14.236Z |
| 2 | 1 | 1 | recovery | — | 用户已授权修复上游已提交的合并冲突标记，以恢复编译并重新验证当前签名应用名改动。 | 2026-09-14T08:15:55.268Z |
| 2 | 1 | 2 | blocked | A1, A2, A3, A4, A5, A6, A7, A8 | 用户已授权但尚未实际修复上游冲突；必须返回 Build 完成冲突解决和端点验证。 | 2026-09-14T08:17:39.067Z |
| 2 | 1 | 2 | recovery | — | 按用户授权返回 Build，实际修复上游已提交的冲突标记，并补充应用名签名入口的运行时验证。 | 2026-09-14T08:17:46.822Z |
| 2 | 2 | 1 | recovery | — | Repair verification passed for A1, A2, A3, A4, A5, A6, A7, A8; final full verification is required. | 2026-09-14T08:25:02.309Z |
| 2 | 2 | 2 | pass | — | 最终独立复核通过：go test ./... 全绿，A1-A8 全部通过，无阻塞。 | 2026-09-14T08:37:06.428Z |



## 结论

最终独立复核通过：go test ./... 全绿，A1-A8 全部通过，无阻塞。
