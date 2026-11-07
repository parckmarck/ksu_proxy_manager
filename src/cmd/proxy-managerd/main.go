// Command proxy-managerd is the long-running management daemon.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ksu_proxy_manager/internal/buildinfo"
	"ksu_proxy_manager/internal/daemon"
	"ksu_proxy_manager/internal/fsutil"
	"ksu_proxy_manager/internal/paths"
	"ksu_proxy_manager/internal/proc"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println(buildinfo.String())
			return
		case "run":
		default:
			fmt.Fprintln(os.Stderr, "用法: proxy-managerd [run|version]（通常由 proxyctl daemon start 启动）")
			os.Exit(2)
		}
	}
	os.Exit(run())
}

func run() int {
	syscall.Umask(0o077)
	_ = os.Chdir("/")
	layout := paths.FromEnv()
	if err := layout.Ensure(); err != nil {
		fmt.Fprintln(os.Stderr, "无法创建数据目录:", err)
		return 1
	}
	lock, err := fsutil.TryLock(layout.DaemonLock())
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			fmt.Fprintln(os.Stderr, "管理服务已在运行")
			return 3
		}
		fmt.Fprintln(os.Stderr, "无法获取运行锁:", err)
		return 1
	}
	defer lock.Release()
	if os.Geteuid() == 0 && proc.IsAndroid() {
		proc.Detach(os.Getpid())
	}
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	d, err := daemon.New(daemon.Options{Layout: layout, CaptureEnabled: daemon.CaptureAllowed(), Echo: os.Getenv("KPM_ECHO") == "1"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化失败:", err)
		return 1
	}
	if err := d.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		d.Shutdown(20 * time.Second)
		return 1
	}
	select {
	case <-sig:
		go d.Shutdown(30 * time.Second)
	case <-d.Done():
	}
	select {
	case <-d.Done():
	case <-time.After(45 * time.Second):
		fmt.Fprintln(os.Stderr, "退出超时")
		return 1
	}
	return 0
}
