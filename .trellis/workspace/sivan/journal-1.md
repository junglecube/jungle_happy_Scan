# Journal - sivan (Part 1)

> AI development session journal
> Started: 2026-09-03

---



## Session 1: Intranet TLS and bounded scan evidence
<!-- trellis-session: v=2 fp=d70a4176cfae9384 -->

**Date**: 2026-09-03
**Task**: Intranet TLS and bounded scan evidence
**Branch**: `main`

### Summary

完成内网扫描 HTTPS 默认跳过证书校验（保留严格开关），新增 30 行/64 KiB 的证据上下文选择器、请求响应完整性元数据和二进制摘要；保持同步终态与 Lite 兼容，更新 API/schema/架构文档并通过 go test -p=1 ./... 与 go vet -p=1 ./...。

### Git Commits

| Hash | Message |
|------|---------|
| `07717e6` | docs: plan bounded scan evidence |
| `0d7cb1e` | feat: support intranet TLS and bounded evidence |

### Status

[OK] **Completed**


## Session 2: 保留扫描证据原文
<!-- trellis-session: v=2 fp=1c2d995ba15d981d -->

**Date**: 2026-09-03
**Task**: 保留扫描证据原文
**Branch**: `main`

### Summary

取消 finding evidence 的 Header、Body 和响应片段脱敏；保留有界上下文与旧配置字段兼容，补充回归测试、文档和 ADR。全量 go test、go vet、git diff --check 通过。

### Git Commits

| Hash | Message |
|------|---------|
| `4b8cfb9` | fix: preserve raw finding evidence |

### Status

[OK] **Completed**


## Session 3: 同步接口鉴权连通性预检
<!-- trellis-session: v=2 fp=bcbd08e08b948257 -->

**Date**: 2026-09-03
**Task**: 同步接口鉴权连通性预检
**Branch**: `codex/preflight-auth-connectivity`

### Summary

完成 jungle_happy_scan 与 lite 同步接口的扫描前鉴权预检：复用 401/403 和 denied_patterns，拦截 200 登录失败响应，返回 network_ok/auth_valid 诊断且不创建失败任务；保持异步、手动 connectivity、重放和 WEB 扫描不变。更新配置页、API/插件文档、ADR、领域术语和后端代码规范；完整测试、竞态测试、vet 与前端语法检查通过。

### Git Commits

| Hash | Message |
|------|---------|
| `dc8a2e9` | docs: plan synchronous auth preflight |
| `bf5898c` | feat: gate synchronous scans on auth preflight |

### Status

[OK] **Completed**


## Session 4: 发布 v3.6.4
<!-- trellis-session: v=2 fp=1fa79fae014611da -->

**Date**: 2026-09-04
**Task**: 发布 v3.6.4
**Branch**: `codex/preflight-auth-connectivity`

### Summary

完成 v3.6.4 发布准备：新增同步扫描鉴权预检、传入 response 相似度校验、预检响应复用为首个基线及机器可读诊断；同步更新版本源、README、内嵌版本页、前端缓存参数、页面断言和 Linux AMD64/ARM64 二进制。go test ./...、go vet ./...、Node 语法检查和差异检查全部通过，发布提交已推送到远程分支。

### Git Commits

| Hash | Message |
|------|---------|
| `f225853` | release: bump version to v3.6.4 |

### Status

[OK] **Completed**
