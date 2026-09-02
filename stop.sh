#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE=${JUNGLE_HAPPY_SCAN_PID_FILE:-"$ROOT/var/jungle_happy_Scan.pid"}

if [ ! -f "$PID_FILE" ]; then
  echo "jungle_happy_Scan 未运行（PID 文件不存在）"
  exit 0
fi
pid=$(sed -n '1p' "$PID_FILE")
if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
  rm -f "$PID_FILE"
  echo "jungle_happy_Scan 未运行（已清理旧 PID 文件）"
  exit 0
fi

kill -TERM "$pid"
count=0
while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 15 ]; do
  sleep 1
  count=$((count + 1))
done
if kill -0 "$pid" 2>/dev/null; then
  echo "优雅关闭超时，发送 KILL"
  kill -KILL "$pid"
fi
rm -f "$PID_FILE"
echo "jungle_happy_Scan 已停止"
