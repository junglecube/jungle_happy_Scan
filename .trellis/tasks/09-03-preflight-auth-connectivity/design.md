# 技术设计

## 边界

逻辑边界只放在同步处理器 `jungleHappyScanResponse` 的预检成功与创建任务之间。共享的拒绝判定放在 `diff`，由 `CheckConnectivity` 计算一次内部鉴权结论；手动 `/api/v1/connectivity` 可以继续只展示网络连通性，不改变其外部 `ok` 语义。

```text
同步 jungle_happy_scan/lite 路径
  → Plan
  → CheckConnectivity（原始鉴权请求，网络预检）
  → 共享鉴权拒绝判定
      ├─ 传输失败：现有连通性失败响应
      ├─ 鉴权拒绝：auth_valid=false，短路且不创建任务
      └─ 未命中拒绝：auth_valid=true
  → CreateWithPreflight
  → 既有正式扫描 / V1、V2、Full、Lite 转换
```

## 判定与数据流

1. `CheckConnectivity` 继续沿用当前 HTTP→HTTPS Auto fallback、Host override、mTLS 和原始报文发送逻辑；不调用 `RemoveSessions`/`InvalidateSessions`。
2. 请求成功后调用统一的拒绝匹配函数。该函数保留当前 `LikelyAuthDenied` 的语义：内置 `401/403`，以及大小写不敏感地匹配状态行和 Body 的 `denied_patterns`。
3. 为了返回诊断信息，在布尔判定之外返回稳定的匹配类别和规则索引，例如 `status_code` 或 `denied_pattern[index]`；不存在命中时不返回伪造的规则。
4. 同步处理器发现鉴权拒绝时构造与网络失败相同生命周期的终态失败视图，设置明确的预检阶段和错误文本，返回空 Findings，并不调用 `CreateWithPreflight`。
5. 通过预检后继续使用既有预检响应作为第一个 baseline，避免非幂等原始请求重复发送。正式未授权插件仍在自己的扫描阶段 clone 请求后删除/替换会话信息。

## API 合同

同步接口的 `connectivity` 对象增加以下字段（均为增量字段）：

```json
{
  "ok": true,
  "network_ok": true,
  "auth_valid": true,
  "reason": ""
}
```

鉴权失效示例：

```json
{
  "ok": false,
  "network_ok": true,
  "auth_valid": false,
  "reason": "auth_denied",
  "matched_rule": "denied_pattern[3]"
}
```

传输失败时 `network_ok=false`，`auth_valid` 不应被表达为已验证的 `false`；可以省略或返回 `null`，`reason` 使用既有连通性错误信息。成功时 `network_ok=true`、`auth_valid=true`。`ok` 在同步接口中表示“本次扫描前置门禁整体通过”，手动 `/api/v1/connectivity` 的 `ok` 仍表示请求发送成功，以避免扩大该入口的行为变更。

由于现有 `denied_patterns` 是无名称字符串数组，规则定位采用内置规则标识或数组索引，不把响应正文返回到诊断对象。完整响应仍只按既有同步接口/API 证据合同处理。

## 配置页

不引入新字段。增强现有“响应语义”卡片中的“登录/授权失败正则”帮助文案，明确：每行一条 RE2 正则，匹配状态行或响应 Body；`401/403` 无需配置；这些规则同时参与未授权插件和两个同步接口的预检。现有 `GET/PUT /api/v1/config` 和保存密码/CIDR 防护保持不变。

## 兼容性与风险

- 路由层继续复用 `jungleHappyScanResponse`，确保 V1、V2、Full、Lite 和根路径别名不会出现判定分叉。
- 普通异步扫描的 `createScan` 不调用预检，避免把用户要求的局部行为扩散到全局扫描入口。
- 共享判定函数必须保留现有未授权插件结果，尤其是状态行/Body 正则、大小写不敏感匹配以及 200 + 拒绝文本场景。
- 同步失败必须不创建 Task，否则调用方可能得到不一致的“失败但可轮询”状态。
- `ok` 在同步结果中改为门禁整体结果，因此同时提供 `network_ok`，让调用方区分网络失败与鉴权失效；手动 connectivity 输出保持兼容。
- 不记录原始请求、Cookie、Token 或响应 Body；只返回规则类别/索引和已有摘要字段。

## 回滚

回滚只需移除同步处理器对鉴权拒绝结果的短路和新增诊断字段；保留当前原始请求预检、预检基线复用、未授权插件及持久配置字段，不需要数据迁移。
