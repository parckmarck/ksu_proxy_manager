#!/usr/bin/env bash
# Full test suite: Go vet/tests (including network-namespace end-to-end tests
# with real cores when KPM_TEST_CORES is set), shell script checks, a simulated
# installer run and the WebUI end-to-end test.
#
# env: GO, JSDOM_NODE_PATH (directory containing node_modules/jsdom)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GO=${GO:-go}
export GOFLAGS=-mod=vendor GOTOOLCHAIN=local GOWORK=off GOPROXY=off CGO_ENABLED=0

step() { printf '\n==> %s\n' "$*"; }

step "go vet"
(cd "$ROOT/src" && "$GO" vet ./...)
unformatted=$(cd "$ROOT/src" && "$(dirname "$(command -v "$GO")")/gofmt" -l ./cmd ./internal)
if [ -n "$unformatted" ]; then echo "gofmt needed: $unformatted" >&2; exit 1; fi

step "go test"
(cd "$ROOT/src" && "$GO" test -count=1 -timeout 20m ./...)

step "go test -race (core packages)"
if command -v gcc >/dev/null; then
  (cd "$ROOT/src" && CGO_ENABLED=1 "$GO" test -race -count=1 -timeout 20m ./internal/daemon/ ./internal/engine/ ./internal/capture/ ./internal/store/ ./internal/logx/ ./internal/supervisor/)
else
  echo "gcc not found: race detector skipped"
fi

step "shell syntax"
for f in customize.sh service.sh action.sh uninstall.sh proxyctl; do
  if grep -q $'\r' "$ROOT/$f"; then echo "CRLF in $f" >&2; exit 1; fi
  for sh in dash "bash --posix"; do
    $sh -n "$ROOT/$f"
  done
  if command -v busybox >/dev/null; then busybox ash -n "$ROOT/$f"; fi
done
echo "shell scripts ok"

step "simulated installer"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
MODPATH="$tmp/modules_update/ksu_proxy_manager"
stage() {
  rm -rf "$MODPATH"
  mkdir -p "$MODPATH/bin/arm64-v8a" "$MODPATH/bin/x86_64" "$MODPATH/webroot"
  cp "$ROOT"/{module.prop,customize.sh,service.sh,action.sh,uninstall.sh,proxyctl} "$MODPATH/"
  touch "$MODPATH"/bin/{arm64-v8a,x86_64}/{proxy-managerd,proxyctl} "$MODPATH/webroot/index.html"
}
cat > "$tmp/harness.sh" <<EOF
ui_print() { echo "\$1"; }
abort() { echo "ABORT: \$1"; exit 1; }
set_perm() { chmod "\$4" "\$1"; }
set_perm_recursive() { find "\$1" -type d -exec chmod "\$4" {} +; find "\$1" -type f -exec chmod "\$5" {} +; }
getprop() { case "\$1" in ro.product.cpu.abilist) echo "\$ABILIST";; ro.product.cpu.abi) echo "\${ABILIST%%,*}";; esac; }
MODPATH="$MODPATH"; API=34; KSU=true
. "$MODPATH/customize.sh"
EOF
stage
out=$(ABILIST=arm64-v8a,armeabi-v7a dash "$tmp/harness.sh")
echo "$out"
echo "$out" | grep -q "安装完成"
[ "$(stat -c %a "$MODPATH/bin/arm64-v8a/proxy-managerd")" = 755 ]
[ "$(stat -c %a "$MODPATH/module.prop")" = 644 ]
[ ! -e "$MODPATH/bin/x86_64" ] || { echo "unused ABI kept" >&2; exit 1; }
stage
out=$(ABILIST=x86_64,arm64-v8a,x86 dash "$tmp/harness.sh")
echo "$out" | grep -q "设备架构：x86_64"
[ -x "$MODPATH/bin/x86_64/proxyctl" ] && [ ! -e "$MODPATH/bin/arm64-v8a" ]
stage
if ABILIST=armeabi-v7a,armeabi dash "$tmp/harness.sh" >/dev/null 2>&1; then echo "installer accepted armeabi-v7a" >&2; exit 1; fi
echo "installer checks ok"

step "uninstall data handling"
DATA_TEST="$tmp/data"
mkdir -p "$DATA_TEST/config"
sed "s#^DATA=.*#DATA=$DATA_TEST#" "$ROOT/uninstall.sh" > "$tmp/uninstall.sh"
dash "$tmp/uninstall.sh"
[ -d "$DATA_TEST" ] || { echo "data removed without marker" >&2; exit 1; }
touch "$DATA_TEST/.delete-on-uninstall"
dash "$tmp/uninstall.sh"
[ ! -e "$DATA_TEST" ] || { echo "data kept with marker" >&2; exit 1; }
mkdir -p "$tmp/real"; touch "$tmp/real/.delete-on-uninstall"; ln -s "$tmp/real" "$DATA_TEST"
dash "$tmp/uninstall.sh"
[ -d "$tmp/real" ] || { echo "followed a symlinked data dir" >&2; exit 1; }
echo "uninstall checks ok"

step "frontend syntax"
while IFS= read -r -d '' file; do
  node --check "$file"
done < <(find "$ROOT/webroot" "$ROOT/scripts" -type f \( -name '*.js' -o -name '*.mjs' \) -print0)

step "webui end-to-end"
WEB="$tmp/webmod"
mkdir -p "$WEB/bin/arm64-v8a"
cp -r "$ROOT/webroot" "$WEB/"
cp "$ROOT/module.prop" "$WEB/"
(cd "$ROOT/src" && "$GO" build -o "$WEB/bin/arm64-v8a/" ./cmd/proxyctl ./cmd/proxy-managerd)
NODE_PATH="${JSDOM_NODE_PATH:-}/node_modules" node "$ROOT/scripts/test-webui.mjs" "$WEB"

step "all tests passed"
