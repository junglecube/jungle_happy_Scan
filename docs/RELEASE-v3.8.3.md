# V3.8.3 发布说明

## 本次更新

- HTTP 应用签名接口统一使用 JSON 协议。
- 扫描器发送：`POST`，`Content-Type: application/json`。
- 请求格式：

  ```json
  {"request":"<完整HTTP请求的标准Base64>"}
  ```

- 成功响应格式：

  ```json
  {"request":"<重新签名后的完整HTTP请求的标准Base64>"}
  ```

- 签名失败时，`preSign.py` 返回非 2xx 状态码及 JSON `error` 字段，扫描器会保留接口返回的错误原因。
- 修复 `preSign.py` 与扫描器原先“JSON 请求/纯文本响应”与“纯文本请求/纯文本响应”的协议不一致问题。
- 修复 Linux 下签名脚本目录大小写不匹配、`node.exe` 命令不适用以及从任意工作目录启动时相对路径失效的问题。
- 不修改 `config/config.json`，不修改现有 `PreSignJS/F-XXX.js`、`crypto-js.js` 或 `sm2.js`。

## `preSign.py` 使用说明

在扫描器服务器上运行：

```bash
python3 /opt/jungle_happy_Scan/config/signature_scripts/preSign.py
```

默认监听 `0.0.0.0:12888`，默认使用系统 `node` 命令，并按 `preSign.py` 所在目录加载 `PreSignJS`。如 Node.js 不在 PATH，可设置：

```bash
PRESIGN_NODE_RUNTIME=/opt/node/bin/node \
python3 /opt/jungle_happy_Scan/config/signature_scripts/preSign.py
```

扫描器签名接口地址应填写对应路径，例如：

```text
http://127.0.0.1:12888/preSign/FS-PMC
```

接口只要求 JSON 中存在 `request` 字段；未知应用名会原样返回，已配置的应用名会调用对应的现有 JS 文件。

## 交付内容

- Linux amd64 静态可执行文件。
- Linux amd64 最小部署包，仅包含可执行文件及 `start.sh`、`stop.sh`、`status.sh`。
- 最小包不包含 Node.js、配置文件或签名脚本；Node.js 和 `config/signature_scripts` 请继续保留在服务器安装目录中。
