#!/usr/bin/env bash
# Build the flashable module: vet, compile both ABIs, stage the module
# tree, inject the WebUI cache version, generate notices and package the zip.
#
# usage: scripts/build.sh [--skip-vet]
# env:   GO (go binary), BUILD_ID (defaults to a UTC timestamp)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GO=${GO:-go}
export GOFLAGS=-mod=vendor GOTOOLCHAIN=local GOWORK=off GOPROXY=off CGO_ENABLED=0

prop() { sed -n "s/^$1=//p" "$ROOT/module.prop" | tr -d '\r'; }
VERSION=$(prop version)
VERSION_CODE=$(prop versionCode)
[ "$(prop id)" = ksu_proxy_manager ] || { echo "module.prop id mismatch" >&2; exit 1; }
grep -q "Version     = \"$VERSION\"" "$ROOT/src/internal/buildinfo/buildinfo.go" || { echo "buildinfo.Version != module.prop version ($VERSION)" >&2; exit 1; }
grep -q "VersionCode = \"$VERSION_CODE\"" "$ROOT/src/internal/buildinfo/buildinfo.go" || { echo "buildinfo.VersionCode != module.prop versionCode ($VERSION_CODE)" >&2; exit 1; }
BUILD_ID=${BUILD_ID:-$(date -u +%Y%m%d%H%M%S)}

OUT="$ROOT/build/module"
DIST="$ROOT/dist"
rm -rf "$ROOT/build"
mkdir -p "$OUT/bin/arm64-v8a" "$OUT/bin/x86_64" "$DIST"

cd "$ROOT/src"
if [ "${1:-}" != "--skip-vet" ]; then
  "$GO" vet ./...
fi
LDFLAGS="-s -w -buildid= -X ksu_proxy_manager/internal/buildinfo.ID=$BUILD_ID"
# -buildvcs=false keeps binaries identical whether or not the tree is a checkout.
GOOS=linux GOARCH=arm64 "$GO" build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$OUT/bin/arm64-v8a/" ./cmd/proxy-managerd ./cmd/proxyctl
# x86_64 serves emulators; the installer keeps only the device's ABI.
GOOS=linux GOARCH=amd64 "$GO" build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$OUT/bin/x86_64/" ./cmd/proxy-managerd ./cmd/proxyctl

cd "$ROOT"
for f in module.prop customize.sh service.sh action.sh uninstall.sh proxyctl README.md; do
  cp "$f" "$OUT/$f"
done
cp -r META-INF webroot docs "$OUT/"
# Cache busting: every asset URL and module import carries ?v=<versionCode>.
find "$OUT/webroot" -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \) -exec sed -i "s/__V__/$VERSION_CODE/g" {} +
if grep -rq '__V__' "$OUT/webroot"; then
  echo "unreplaced version placeholder in webroot" >&2
  exit 1
fi

{
  echo "KSU Proxy Manager $VERSION 第三方组件许可"
  echo "========================================"
  echo
  echo "本模块不包含任何代理核心。用户自行下载或导入的 Mihomo（GPL-3.0）与 sing-box（GPL-3.0）"
  echo "以独立进程运行，适用其各自的许可。规则集数据来自 MetaCubeX/meta-rules-dat。"
  echo
  echo "proxy-managerd / proxyctl 静态链接了以下 Go 模块："
  while read -r line; do
    case "$line" in
      "# "*)
        mod=$(echo "$line" | awk '{print $2}')
        ver=$(echo "$line" | awk '{print $3}')
        dir="src/vendor/$mod"
        for lic in LICENSE LICENSE.md COPYING NOTICE; do
          if [ -f "$dir/$lic" ]; then
            echo
            echo "---- $mod $ver ($lic) ----"
            cat "$dir/$lic"
          fi
        done
        ;;
    esac
  done < src/vendor/modules.txt
  echo
  echo "---- Go 标准库 ----"
  echo "Copyright 2009 The Go Authors. BSD-3-Clause，见 https://go.dev/LICENSE"
  echo
  echo "---- 内置 CA 证书包（src/internal/netx/ca_bundle.pem） ----"
  echo "来源于 Mozilla CA Certificate Program，按 MPL-2.0 分发：https://www.mozilla.org/MPL/2.0/"
  echo
  echo "---- Lucide 1.69.0 图标（ISC；部分源自 Feather，MIT） ----"
  cat "$ROOT/webroot/assets/vendor/lucide-LICENSE.txt"
} > "$OUT/THIRD_PARTY_NOTICES.txt"

python3 "$ROOT/scripts/package.py" "$OUT" "$DIST/ksu_proxy_manager-v$VERSION.zip" "$VERSION" "$VERSION_CODE" "$BUILD_ID"
