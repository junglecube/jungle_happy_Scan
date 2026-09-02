#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=$(sed -n '1p' "$ROOT/VERSION")
PACKAGE_VERSION=${VERSION%.*}
BUILD_TIME=${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
GO=${GO:-go}
OUT=${OUT:-"$ROOT/bin"}
RELEASE_DIR=${RELEASE_DIR:-"$ROOT/release"}
PACKAGE_NAME=${PACKAGE_NAME:-jungle_happy_Scan-$PACKAGE_VERSION}
ARCHIVE=${ARCHIVE:-"$RELEASE_DIR/$PACKAGE_NAME.tar.gz"}
MINIMAL_DIR=${MINIMAL_DIR:-"$RELEASE_DIR/minimal_packages"}

mkdir -p "$OUT"
mkdir -p "$RELEASE_DIR"
mkdir -p "$MINIMAL_DIR"

checksum_files() {
  checksum_dir=$1
  shift
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$checksum_dir" && sha256sum "$@")
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    (cd "$checksum_dir" && shasum -a 256 "$@")
    return
  fi
  echo "缺少 sha256sum 或 shasum，无法生成发布校验值" >&2
  exit 1
}

build_one() {
  os=$1
  arch=$2
  suffix=
  if [ "$os" = "windows" ]; then
    suffix=.exe
  fi
  output="$OUT/jungle_happy_Scan-$os-$arch$suffix"
  echo "构建 $os/$arch -> $output"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch "$GO" build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION -X main.buildTime=$BUILD_TIME" \
    -o "$output" ./cmd/jungle_happy_Scan
  chmod 755 "$output"
}

cd "$ROOT"
cp "$ROOT/docs/plugins.md" "$ROOT/internal/api/web/plugins.md"
build_one linux amd64
build_one linux arm64
build_one darwin arm64
build_one windows amd64
build_one windows arm64

checksum_files "$OUT" \
  jungle_happy_Scan-linux-amd64 \
  jungle_happy_Scan-linux-arm64 \
  jungle_happy_Scan-darwin-arm64 \
  jungle_happy_Scan-windows-amd64.exe \
  jungle_happy_Scan-windows-arm64.exe >"$OUT/SHA256SUMS"

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
host_arch=$(uname -m)
case "$host_arch" in
  x86_64|amd64) host_arch=amd64 ;;
  arm64|aarch64) host_arch=arm64 ;;
esac
host_binary="$OUT/jungle_happy_Scan-$host_os-$host_arch"
if [ -x "$host_binary" ]; then
  case "$("$host_binary" -version 2>/dev/null || true)" in
    *"$VERSION"*) ;;
    *) echo "版本校验失败：$host_binary 未报告 $VERSION" >&2; exit 1 ;;
  esac
fi

archive_tmp="$ARCHIVE.tmp"
rm -f "$archive_tmp"
root_name=$(basename "$ROOT")
tar -czf "$archive_tmp" \
  --exclude=".DS_Store" \
  --exclude="*/.DS_Store" \
  --exclude="$root_name/config" \
  --exclude="$root_name/var" \
  --exclude="$root_name/release" \
  --exclude="$root_name/node_modules" \
  --exclude="$root_name/bin/jungle_happy_Scan" \
  -C "$(dirname "$ROOT")" "$root_name"
mv "$archive_tmp" "$ARCHIVE"
cp "$ROOT/install_jungle_happy_Scan.sh" "$RELEASE_DIR/install_jungle_happy_Scan.sh"

rm -f "$RELEASE_DIR/jungle_happy_Scan-v3.1-windows-amd64-minimal.zip" \
  "$RELEASE_DIR/jungle_happy_Scan-v3.1-windows-amd64-minimal.zip.sha256"
rm -rf "$MINIMAL_DIR"
mkdir -p "$MINIMAL_DIR"

package_windows_minimal() {
  arch=$1
  package="$MINIMAL_DIR/jungle_happy_Scan-$PACKAGE_VERSION-windows-$arch-minimal.zip"
  stage="$RELEASE_DIR/.windows-$arch-minimal"
  rm -rf "$stage"
  mkdir -p "$stage"
  cp "$OUT/jungle_happy_Scan-windows-$arch.exe" "$stage/"
  cp "$ROOT/start_windows.bat" "$stage/"
  (cd "$stage" && zip -q "$package" \
    "jungle_happy_Scan-windows-$arch.exe" start_windows.bat)
  rm -rf "$stage"
}

package_linux_minimal() {
  arch=$1
  package="$MINIMAL_DIR/jungle_happy_Scan-$PACKAGE_VERSION-linux-$arch-minimal.tar.gz"
  stage="$RELEASE_DIR/.linux-$arch-minimal"
  rm -rf "$stage"
  mkdir -p "$stage/jungle_happy_Scan/bin"
  cp "$OUT/jungle_happy_Scan-linux-$arch" "$stage/jungle_happy_Scan/bin/jungle_happy_Scan"
  cp "$ROOT/start.sh" "$ROOT/stop.sh" "$ROOT/status.sh" "$stage/jungle_happy_Scan/"
  chmod 755 "$stage/jungle_happy_Scan/bin/jungle_happy_Scan" \
    "$stage/jungle_happy_Scan/start.sh" "$stage/jungle_happy_Scan/stop.sh" "$stage/jungle_happy_Scan/status.sh"
  (cd "$stage" && tar -czf "$package" jungle_happy_Scan)
  rm -rf "$stage"
}

package_windows_minimal amd64
package_linux_minimal amd64
package_linux_minimal arm64

checksum_files "$RELEASE_DIR" "$(basename "$ARCHIVE")" >"$ARCHIVE.sha256"
checksum_files "$MINIMAL_DIR" \
  jungle_happy_Scan-$PACKAGE_VERSION-windows-amd64-minimal.zip \
  jungle_happy_Scan-$PACKAGE_VERSION-linux-amd64-minimal.tar.gz \
  jungle_happy_Scan-$PACKAGE_VERSION-linux-arm64-minimal.tar.gz >"$MINIMAL_DIR/SHA256SUMS"

echo "构建完成：$OUT"
echo "交付包：$ARCHIVE"
echo "最小交付包目录：$MINIMAL_DIR"
echo "一键安装脚本：$RELEASE_DIR/install_jungle_happy_Scan.sh"
