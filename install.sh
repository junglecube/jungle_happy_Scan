#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXPECTED_VERSION=${JUNGLE_HAPPY_SCAN_EXPECTED_VERSION:-$(sed -n '1p' "$ROOT/VERSION")}
PID_FILE=${JUNGLE_HAPPY_SCAN_PID_FILE:-"$ROOT/var/jungle_happy_Scan.pid"}
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
  linux|darwin) ;;
  *) echo "不支持的操作系统：${os}（不支持 Windows）" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "不支持的 CPU 架构：$arch" >&2; exit 1 ;;
esac

source_bin="$ROOT/bin/jungle_happy_Scan-$os-$arch"
target_bin="$ROOT/bin/jungle_happy_Scan"
if [ ! -f "$source_bin" ]; then
  echo "交付包缺少当前平台二进制：$source_bin" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  expected=$(awk -v file="$(basename "$source_bin")" '$2 == file {print $1}' "$ROOT/bin/SHA256SUMS")
  actual=$(sha256sum "$source_bin" | awk '{print $1}')
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || {
    echo "当前平台二进制 SHA-256 校验失败" >&2
    exit 1
  }
elif command -v shasum >/dev/null 2>&1; then
  expected=$(awk -v file="$(basename "$source_bin")" '$2 == file {print $1}' "$ROOT/bin/SHA256SUMS")
  actual=$(shasum -a 256 "$source_bin" | awk '{print $1}')
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || {
    echo "当前平台二进制 SHA-256 校验失败" >&2
    exit 1
  }
else
  echo "警告：系统缺少 sha256sum/shasum，跳过二进制校验" >&2
fi

case "$("$source_bin" -version 2>/dev/null || true)" in
  *"$EXPECTED_VERSION"*) ;;
  *) echo "交付二进制版本不匹配，预期 $EXPECTED_VERSION" >&2; exit 1 ;;
esac

if [ -f "$PID_FILE" ]; then
  "$ROOT/stop.sh"
fi

target_tmp="$target_bin.installing"
rm -f "$target_tmp"
cp "$source_bin" "$target_tmp"
chmod 755 "$target_tmp"
mv "$target_tmp" "$target_bin"
chmod 755 "$target_bin" "$ROOT/start.sh" "$ROOT/stop.sh" "$ROOT/status.sh"
"$ROOT/start.sh"

case "$("$target_bin" -version 2>/dev/null || true)" in
  *"$EXPECTED_VERSION"*) ;;
  *) echo "安装后的版本校验失败，预期 $EXPECTED_VERSION" >&2; exit 1 ;;
esac

echo "安装完成。默认管理页面：http://本机IP:8888/（如设置 SCANNER_LISTEN，请使用对应端口）"
echo "浏览器手工代理默认端口：8088；实际地址以【WEB扫描】任务页面显示为准。"
echo "离线回连默认监听：0.0.0.0:61166；如需 SSRF、XXE 扩展或 OS 命令 OAST 插件确认，请放通该端口并在前台填写目标可访问地址。"
echo "JNDI 安全回连默认监听：0.0.0.0:61167；仅接收一次性 LDAP Token，不返回远程类或对象。"
