#!/system/bin/sh
# Runs early during the boot after the module was marked for removal, before
# any of its services start, so there is no routing state to clean up. User
# data in /data/adb/ksu_proxy_manager is kept unless "卸载时删除数据" was
# enabled in the WebUI (marker file .delete-on-uninstall).
DATA=/data/adb/ksu_proxy_manager

if [ -f "$DATA/.delete-on-uninstall" ] && [ ! -L "$DATA" ] && [ -d "$DATA" ]; then
  real=$(cd -P "$DATA" 2>/dev/null && pwd -P)
  if [ "$real" = "$DATA" ]; then
    rm -rf "$DATA"
  fi
fi
exit 0
