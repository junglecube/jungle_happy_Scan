# V3.8.2 发布说明

## 本次更新

- 敏感信息插件新增通用 `flag{...}` 标记检测，内容可以为空，也可以包含中文、换行或其他字符。
- 敏感信息规则现在正确使用配置中的 `severity` 等级。
- 未授权访问插件新增 `unauthorized.allow_paths` 持久化白名单，支持大小写不敏感的路径片段匹配，用于排除 `login`、`checkHealth` 等公开接口。
- 未授权白名单在扫描计划阶段生效，命中后不会发送未授权检测请求，也不影响其他插件。
- 持久配置页面重新整理卡片、规则编辑器和响应式布局，新增白名单维护框。

## 配置示例

在【持久配置】的【插件 Payload 与检测规则】中选择“未授权访问”，在白名单框中每行填写一个公开接口路径：

```text
/login
/checkHealth
```

也可以在 `plugin_rules.unauthorized` 中配置：

```json
{
  "allow_paths": ["/login", "/checkHealth"]
}
```

白名单按大小写不敏感的路径片段模糊匹配，忽略查询参数。例如 `login` 可匹配 `/api/login`、`/api2/Login/`。
