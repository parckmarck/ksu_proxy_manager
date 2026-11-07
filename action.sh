#!/system/bin/sh
# Module action button: start the proxy core when it is stopped, stop it when
# it is running, then print the resulting status.
MODDIR=${0%/*}
echo "KSU Proxy Manager"
echo "-----------------"
"$MODDIR/proxyctl" toggle
rc=$?
if [ "$rc" -ne 0 ]; then
  echo ""
  echo "操作失败。可在 WebUI「日志」页查看详情，或执行："
  echo "  $MODDIR/proxyctl doctor"
fi
exit 0
