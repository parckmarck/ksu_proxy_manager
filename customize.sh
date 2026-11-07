#!/system/bin/sh
# Installer hook (sourced by KernelSU / Magisk / APatch). It only validates the
# package and sets permissions: no network access, no data changes.
SKIPUNZIP=0

case "${MODPATH:-}" in
  /*/ksu_proxy_manager) ;;
  *) abort "! 安装路径异常：${MODPATH:-空}" ;;
esac
if ! grep -qx 'id=ksu_proxy_manager' "$MODPATH/module.prop" 2>/dev/null; then
  abort "! module.prop 标识不匹配"
fi

abi=$(getprop ro.product.cpu.abi)
case "$abi" in
  arm64-v8a | x86_64) ;;
  *)
    case ",$(getprop ro.product.cpu.abilist)," in
      *,arm64-v8a,*) abi=arm64-v8a ;;
      *) abort "! 不支持的设备架构：$abi（需要 arm64-v8a 或 x86_64）" ;;
    esac
    ;;
esac
ui_print "- 设备架构：$abi"
if [ -n "$API" ] && [ "$API" -lt 29 ]; then
  ui_print "! Android 版本较旧（API $API），未经测试"
fi

for f in proxyctl service.sh action.sh uninstall.sh "bin/$abi/proxy-managerd" "bin/$abi/proxyctl" webroot/index.html; do
  [ -f "$MODPATH/$f" ] || abort "! 安装包不完整，缺少 $f"
done
for d in "$MODPATH"/bin/*; do
  [ "${d##*/}" = "$abi" ] || rm -rf "$d"
done

set_perm_recursive "$MODPATH" 0 0 0755 0644
for f in proxyctl service.sh action.sh uninstall.sh "bin/$abi/proxy-managerd" "bin/$abi/proxyctl"; do
  set_perm "$MODPATH/$f" 0 0 0755
done

DATA=/data/adb/ksu_proxy_manager
if [ -f "$DATA/config/model.json" ]; then
  ui_print "- 检测到 1.x 配置：首次启动时自动迁移，原文件备份到 config/backups/"
fi
if [ -z "$KSU" ]; then
  ui_print "- 当前不是 KernelSU：可使用 WebUI X / KsuWebUI 打开管理界面，"
  ui_print "  或在设置中开启浏览器访问"
fi
ui_print "- 安装完成，重启后生效"
ui_print "- 模块不内置代理核心：请在 WebUI「核心」页下载官方核心或导入本地文件"
