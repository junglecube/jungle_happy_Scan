#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE=${JUNGLE_HAPPY_SCAN_PID_FILE:-"$ROOT/var/jungle_happy_Scan.pid"}
BIN=${JUNGLE_HAPPY_SCAN_BIN:-"$ROOT/bin/jungle_happy_Scan"}

if [ -f "$PID_FILE" ]; then
  pid=$(sed -n '1p' "$PID_FILE")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    version=$("$BIN" -version 2>/dev/null || echo "版本未知")
    echo "jungle_happy_Scan 正在运行，PID=${pid}，${version}"
    exit 0
  fi
fi
echo "jungle_happy_Scan 未运行"
exit 1
