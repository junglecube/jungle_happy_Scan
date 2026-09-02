#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN=${JUNGLE_HAPPY_SCAN_BIN:-"$ROOT/bin/jungle_happy_Scan"}
CONFIG=${JUNGLE_HAPPY_SCAN_CONFIG:-"$ROOT/config/config.json"}
PID_FILE=${JUNGLE_HAPPY_SCAN_PID_FILE:-"$ROOT/var/jungle_happy_Scan.pid"}
LOG_FILE=${JUNGLE_HAPPY_SCAN_LOG_FILE:-"$ROOT/var/jungle_happy_Scan.log"}
PASSWORD_FILE=${JUNGLE_CONFIG_PASSWORD_FILE:-"$ROOT/config/config-password"}

mkdir -p "$ROOT/config" "$ROOT/var"
if [ -z "${JUNGLE_CONFIG_PASSWORD:-}" ] && [ -f "$PASSWORD_FILE" ]; then
  JUNGLE_CONFIG_PASSWORD=$(sed -n '1p' "$PASSWORD_FILE")
  export JUNGLE_CONFIG_PASSWORD
fi
if [ ! -x "$BIN" ]; then
  echo "未找到可执行文件：$BIN" >&2
  exit 1
fi
if [ -f "$PID_FILE" ]; then
  old_pid=$(sed -n '1p' "$PID_FILE")
  if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
    echo "jungle_happy_Scan 已运行，PID=$old_pid"
    exit 0
  fi
fi

if [ -n "${SCANNER_LISTEN:-}" ]; then
  nohup "$BIN" -config "$CONFIG" -listen "$SCANNER_LISTEN" >>"$LOG_FILE" 2>&1 &
else
  nohup "$BIN" -config "$CONFIG" >>"$LOG_FILE" 2>&1 &
fi
pid=$!
echo "$pid" >"$PID_FILE"

listen=${SCANNER_LISTEN:-}
if [ -z "$listen" ] && [ -f "$CONFIG" ]; then
  listen=$(sed -n 's/^[[:space:]]*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | sed -n '1p')
fi
[ -n "$listen" ] || listen="0.0.0.0:8888"
port=${listen##*:}
HEALTH_URL=${SCANNER_HEALTH_URL:-"http://127.0.0.1:$port/api/health"}

health_tool=none
if command -v curl >/dev/null 2>&1; then
  health_tool=curl
elif command -v wget >/dev/null 2>&1; then
  health_tool=wget
fi

attempt=0
healthy=false
while [ "$attempt" -lt 20 ]; do
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "启动失败，请检查 $LOG_FILE" >&2
    exit 1
  fi
  if [ "$health_tool" = curl ] && curl --noproxy '*' -fsS --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
    healthy=true
    break
  fi
  if [ "$health_tool" = wget ] &&
    NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
      wget -q -T 2 -O /dev/null "$HEALTH_URL" >/dev/null 2>&1; then
    healthy=true
    break
  fi
  if [ "$health_tool" = none ] && [ "$attempt" -ge 1 ]; then
    healthy=true
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done

if [ "$healthy" != true ]; then
  kill -TERM "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  echo "健康检查失败：${HEALTH_URL}，请检查 ${LOG_FILE}" >&2
  exit 1
fi
if [ "$health_tool" = none ]; then
  echo "警告：系统缺少 curl/wget，已使用进程存活检查；可设置 SCANNER_HEALTH_URL 后自行访问 /api/health" >&2
fi
echo "jungle_happy_Scan 已启动，PID=${pid}，健康检查=${HEALTH_URL}，日志=${LOG_FILE}"
