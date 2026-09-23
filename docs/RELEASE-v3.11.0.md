# V3.11.0 配置与升级说明

V3.11.0 深度修改反射型 XSS 插件，并新增可独立选择的 `reflected_xss_deep`。快速模式用于低成本覆盖，深度模式包含快速 Payload，同时增加常见事件属性、无引号属性、反引号函数、脚本上下文和 XSS-oneliner 风格的一行式变体。

## XSS 检测变化

- 先发送唯一标记定位每个原始反射位置，再按 HTML 文本、属性、标签和脚本上下文选择 Payload。
- 快速模式增加 `<img src=x onerror=...>`、`<details open ontoggle=...>` 和标签闭合探针，能够覆盖表单参数被原样放回 HTML/XML 包装响应的场景。
- 深度模式额外覆盖无引号属性、反引号调用、`Object.bind`、`Symbol.replace`、脚本字符串/代码和自索引一行式 Payload，例如 `self[0X10f8809.toString\`36\`]\`1\``。
- 只在同一原始上下文中找到完整 Payload 才报告，编码回显、JSON/XML 中的其他副本不会替代执行上下文。
- 记录隐藏容器和强制 CSP 对当前内联 Payload 的影响，但不会因为 CSP 存在就把潜在反射误判为安全。

快速插件 ID 为 `reflected_xss`，深度插件 ID 为 `reflected_xss_deep`。在 Normal 选择快速即可；选择 Deep 时自动去重快速插件并运行深度插件。插件均报告低危的反射候选，不启动真实浏览器执行 JavaScript。

## 原 config 直接升级

配置版本从 33 升至 34。替换同架构的可执行文件并使用原启动参数即可，首次读取旧配置时会自动备份为 `<config>.pre-v34.bak`，然后补齐 XSS 快速/深度规则。原有自定义规则、响应语义和其他持久配置继续保留。

## 发布文件

- `jungle_happy_Scan-linux-amd64`：Linux amd64 零依赖可执行文件。
- 使用 `sha256sum` 校验发布目录中的 `SHA256SUMS`。
