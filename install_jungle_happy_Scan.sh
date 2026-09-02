#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCHIVE=${SCANNER_ARCHIVE:-"$SCRIPT_DIR/jungle_happy_Scan-v3.6.tar.gz"}
INSTALL_DIR=${SCANNER_INSTALL_DIR:-"$SCRIPT_DIR/jungle_happy_Scan-installed"}

if [ ! -f "$ARCHIVE" ]; then
  echo "未找到交付包：$ARCHIVE" >&2
  exit 1
fi

checksum_file="$ARCHIVE.sha256"
if [ -f "$checksum_file" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    expected=$(sed -n '1{s/[[:space:]].*$//;p;}' "$checksum_file")
    actual=$(shasum -a 256 "$ARCHIVE" | sed -n '1{s/[[:space:]].*$//;p;}')
    [ "$expected" = "$actual" ] || {
      echo "交付包 SHA-256 校验失败" >&2
      exit 1
    }
  else
    echo "警告：系统缺少 sha256sum/shasum，跳过外层交付包校验" >&2
  fi
fi

mkdir -p "$INSTALL_DIR"
tar -xzf "$ARCHIVE" -C "$INSTALL_DIR" --strip-components=1
chmod 755 "$INSTALL_DIR/install.sh" "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh" "$INSTALL_DIR/status.sh"
"$INSTALL_DIR/install.sh"
echo "安装目录：$INSTALL_DIR"
