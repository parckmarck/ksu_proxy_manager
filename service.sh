#!/system/bin/sh
# Late-start service: start the management daemon once boot has completed.
# Runs in the background so that the boot sequence is never blocked. Startup
# output is kept in the data directory so that a failed boot start can be
# diagnosed (proxyctl doctor shows the tail of this log).
MODDIR=${0%/*}
LOGDIR=/data/adb/ksu_proxy_manager/logs
(
  n=0
  until [ "$(getprop sys.boot_completed)" = "1" ]; do
    n=$((n + 1))
    [ "$n" -gt 300 ] && break
    sleep 2
  done
  [ -f "$MODDIR/disable" ] && exit 0
  [ -f "$MODDIR/remove" ] && exit 0
  mkdir -p "$LOGDIR" 2>/dev/null
  LOG="$LOGDIR/service.log"
  [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 65536 ] && mv -f "$LOG" "$LOG.1"
  for delay in 5 15 0; do
    echo "$(date '+%Y-%m-%dT%H:%M:%S') daemon start" >> "$LOG"
    "$MODDIR/proxyctl" daemon start >> "$LOG" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && exit 0
    echo "$(date '+%Y-%m-%dT%H:%M:%S') daemon start failed (rc=$rc)" >> "$LOG"
    [ "$delay" -eq 0 ] && break
    sleep "$delay"
  done
) </dev/null >/dev/null 2>&1 &
exit 0
