# 实现计划

## Checklist

1. 在 `diff` 中提取/扩展可返回命中原因的鉴权拒绝判定，同时保持 `LikelyAuthDenied` 现有布尔调用方语义不变。
2. 扩展 `engine.ConnectivityResult` 或等价内部结果，记录预检网络状态、鉴权状态和稳定的命中规则信息；让 `CheckConnectivity` 复用统一判定，但不改变手动 connectivity API 的网络成功语义。
3. 在 `jungleHappyScanResponse` 中仅对 `jungle_happy_scan`/`lite` 的同步处理链路增加鉴权失败短路；保证网络失败、鉴权失败都不创建 Task，并返回空 Findings 与诊断字段。
4. 覆盖 V1、V2、Full、Lite 以及根路径兼容别名的成功/失败 JSON；确认异步 `/scan`、手动 `/connectivity`、replay 和 WEB 路径没有被调用新门禁。
5. 更新现有持久配置页“响应语义”文案和相关 API/插件文档，说明 `denied_patterns` 的共享用途与 200 + 登录失败场景。
6. 增加后端测试：401/403、200 + denied pattern、普通 200、网络失败、无 Task/无插件请求、规则索引返回、V1/V2/Lite 兼容和异步入口不变。
7. 运行格式化、Go 测试、静态检查，审查差异只包含本任务文件和必要文档。

## Validation

```bash
gofmt -w internal/diff/diff.go internal/engine/manager.go internal/api/server.go
go test ./internal/diff ./internal/engine ./internal/api ./internal/plugin ./internal/config -count=1
go test -race ./internal/diff ./internal/engine ./internal/api -count=1
go vet ./internal/diff ./internal/engine ./internal/api ./internal/plugin ./internal/config
node --check internal/api/web/app.js
```

## 风险与回滚点

- `denied_patterns` 是共享规则；新增返回式判定时必须回归未授权插件，避免正则语义分叉。
- 同步接口的 `connectivity.ok` 新增“整体门禁”语义，必须同时提供 `network_ok` 和 `auth_valid`，并更新 API 文档。
- 不得把新预检接到 `createScan` 或 WEB adapter，否则会超出用户确认的范围。
- 状态改变请求只能复用已有预检响应作为 baseline，不能因为诊断而重复发包。
- 配置页提交的是完整 `Config`，前端保存时要保留既有字段和插件规则，避免只更新文案时丢失配置。

## 开始实现前检查（已完成）

- PRD 的入口范围、鉴权规则、失败短路、配置复用和“不绕过”决策已获用户确认。
- 已创建 ADR 0004 并更新根 `CONTEXT.md`，术语使用“扫描前鉴权预检”“鉴权拒绝响应”“同步扫描接口”。
- 用户已明确批准规划摘要，任务已通过 `task.py start` 进入 `in_progress`，并已完成产品代码修改与验证。
