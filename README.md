# KSU Proxy Manager 2.0.3

KernelSU / Magisk / APatch 代理管理模块。使用 Mihomo 或 sing-box 作为代理核心，通过 TUN 透明代理设备流量，提供按应用分流、订阅管理、分流规则与 DNS 设置，全部在模块自带的 WebUI 中完成。

模块**不内置任何代理核心**：首次使用时在 WebUI「核心」页从官方 GitHub 发布页下载（自动校验 SHA-256），或导入本地文件。

## 功能

- **双核心**：Mihomo（≥ 1.19.33）与 sing-box（≥ 1.13.21），共用同一份配置，随时切换。旧版核心须先升级，避免入站认证或配置兼容性问题。
- **透明代理**：核心只创建 TUN 网卡，路由规则由模块自行维护（按 UID 的策略路由），两种核心行为一致；VPN 与显式绑定网络的非 DNS 连接保留系统路由优先级，端口 53 查询另行接管。
- **按应用分流**：全部应用 / 仅名单内 / 名单外三种模式，支持多用户（工作资料、分身）；名单修改即时生效，新安装的应用自动识别。
- **热点共享**：可选代理 Wi-Fi 热点与 USB 共享的设备。
- **节点**：Shadowsocks、VMess、VLESS（含 Reality）、Trojan、Hysteria2、TUIC、AnyTLS、SOCKS5、HTTP(S)、WireGuard；支持链式代理（前置节点，最多 3 层）。
- **订阅**：分享链接 / Base64 / Clash YAML / sing-box JSON；更新前预览新增、删除与变更；节点 ID 稳定，代理组引用不会因更新失效；显示流量与到期时间；可定时更新。
- **分流**：预设（中国大陆直连 / 全部代理 / 仅自定义）、广告拦截、阻止 QUIC，自定义规则（域名、IP 段、geosite/geoip 规则集、应用包名、端口、网络类型）；规则/全局/直连模式即时切换。
- **DNS**：Fake-IP 或真实 IP 模式，直连与代理 DNS 分离，支持 UDP/TCP/DoT/DoH/DoQ。
- **可靠性**：启动前由核心自检配置，失败不影响正在运行的核心；新配置启动失败自动回滚；核心崩溃或卡死时按策略自动重启；“防泄漏”开关决定核心异常时被代理应用是断网还是直连。
- **安全**：凭据与订阅地址只保存在设备上，API 不返回明文；日志自动脱敏；所有数据文件仅 root 可读。
- **界面**：手机底部导航与宽屏侧栏、可折叠代理组、节点类型筛选、实时流量图、深浅主题；图标全部离线内置。

## 要求

- arm64-v8a 或 x86_64（模拟器）设备，Android 10 及以上。
- KernelSU（推荐，可直接打开 WebUI）、Magisk 或 APatch。非 KernelSU 环境可用 WebUI X / KsuWebUI 等应用打开，或在设置中开启浏览器访问。
- 内核需支持按 UID 的策略路由（Linux 4.10+，常见 Android 内核均支持）与 TUN。

## 安装与升级

1. 在管理器中刷入 `ksu_proxy_manager-v2.0.3.zip`，重启。
2. 打开模块 WebUI：
   1. 「核心」页：下载 Mihomo 或 sing-box（或导入本地文件），在“使用的核心”中选择。
   2. 「订阅」页添加订阅，或在「节点」页导入分享链接 / 手动添加。
   3. 「概览」页点击“启动核心”。
3. 之后开机会自动启动（可在设置中关闭）。模块列表中的“操作”按钮可一键启动/停止核心。

从 1.x 升级：首次启动时自动迁移旧配置（节点、订阅、代理组、应用名单、分流设置），原文件备份在 `/data/adb/ksu_proxy_manager/config/backups/legacy-*.json`；已安装的核心继续可用。

## 工作方式

```
应用（UID 在名单内）──策略路由──▶ TUN(ksu-proxy0) ──▶ 核心 ──▶ 代理节点 / 直连
```

- 普通应用规则位于 netd 的 LOCAL_NETWORK 规则之后（Android 12+ 为 20270 左右，Android 10–11 为 17270 左右，自动探测），因此 VPN、显式绑定网络的非 DNS 套接字保留系统路由优先级；核心自身以 root 运行，不会被接管。Android 系统共享 UID（<10000）及标准网络认证应用的共享 UID、对应 SDK 沙箱均从应用与 DNS 接管中排除。
- 被接管应用经系统解析器发出的 DNS（端口 53）由一条位于 netd 显式网络规则之前的规则导入 TUN（需要内核 4.17+），否则这些查询会绕过核心。
- 模块使用自有路由表 `20260`、`20261` 接管流量，`20262` 隔离核心库的辅助路由，以及仅在开启热点共享时创建的 `KPM_FWD` iptables 链；停止核心或执行 `proxyctl cleanup` 会全部移除。辅助路由只在确认核心退出后清理，不清理其他 VPN 使用的通用表。
- **防泄漏（失败关闭）**：开启后，核心异常时被代理的应用会断网而不是直连；关闭（默认）时自动恢复直连。守护进程恢复且启用开机自启时先安装阻断计划，再处理遗留核心；显式停止或禁用仍会解除接管。
- 自动重启失败后继续使用剩余预算（10 分钟内最多 3 次，退避 2/5/15 秒）；开机首次启动失败后最多再重试 3 次（5/15/60 秒）。用户停止、禁用或手动启动会取消旧的重试；已确认损坏的配置不进入无效重试。

## 常见问题

- **域名分流不生效 / DNS 不走代理**：系统设置中的“私人 DNS”若设为“指定主机名”，DNS 查询由系统直接加密发出，不经过核心。请改为“关闭”或“自动”。概览页会提示该情况。
- **Wi-Fi 网页认证或 IoT 配网失败**：已排除 `com.android.captiveportallogin` 和 `com.google.android.captiveportallogin`；厂商自有认证应用和其他显式绑定网络的应用仍可能受端口 53 接管影响，此时先暂停核心。模拟器不能代替真实认证热点的完整验证。
- **启动失败**：查看「概览」的错误提示与「日志」页（核心日志）。常见原因：未安装核心、节点参数有误（核心自检会给出具体字段）。
- **网络异常需要立即恢复**：在终端执行 `su -c /data/adb/modules/ksu_proxy_manager/proxyctl cleanup`，会停止服务并移除本模块的全部路由规则；或在管理器中禁用模块（核心会在数秒内停止）。
- **WebUI 打不开或显示“无法连接管理服务”**：执行 `proxyctl doctor` 查看诊断；管理服务的启动日志在 `/data/adb/ksu_proxy_manager/logs/daemon-start.log`。

## 命令行

```
proxyctl status [--json]        查看状态
proxyctl start | stop | restart 启动 / 停止 / 重启核心
proxyctl toggle                 启动或停止（模块操作按钮使用）
proxyctl mode rule|global|direct
proxyctl logs [daemon|core] [-n 200]
proxyctl doctor                 诊断信息
proxyctl cleanup                紧急清理
proxyctl daemon start|stop|restart|status
proxyctl version
```

完整路径为 `/data/adb/modules/ksu_proxy_manager/proxyctl`，需要 root。

## 数据与隐私

- 数据目录：`/data/adb/ksu_proxy_manager/`（配置 `config/config.json`、最近 10 次实际修改前的自动备份 `config/backups/`、核心 `cores/`、规则集 `rulesets/`、日志 `logs/`），目录 0700、文件 0600，仅 root 可读。订阅更新时间、流量、错误等元数据不提升修订号或占用备份；显式恢复仍保留新的修订边界。损坏原件和旧版迁移原件独立保留，只有通过校验的内容才能恢复。
- 节点密码、UUID、密钥与订阅地址只保存在该目录中，管理接口与 WebUI 不会再显示明文。
- 设置中可导出备份到内部存储的 Download 目录，也可从这些文件或自动备份恢复。含凭据导出仅允许管理器内的本机桥接；浏览器只允许导出不含凭据的备份。含凭据的备份请勿分享。
- 浏览器访问默认关闭；开启后仅监听 `127.0.0.1`，需要访问密钥，并校验 Host 与 Origin。密钥仍有修改代理配置和下载官方核心的管理权限，必须妥善保管；浏览器禁止导入本地可执行文件和按路径恢复备份，这些操作仅允许管理器内的 root 桥接。
- 经代理下载的域名解析也经过核心：以固定公网 IPv4/IPv6 地址连接 Cloudflare DoH，失败后尝试其他引导地址及 Google DoH，不回退到本地 DNS。解析结果全部通过公网地址校验后再钉住 IP 下载，TLS 证书校验保持开启；两个 DoH 服务都不可达时会明确失败。
- 卸载模块默认保留数据，便于重新安装；在设置中勾选“卸载模块时同时删除数据”后卸载会一并删除。

## 构建与测试

源码位于 `src/`（Go，依赖已 vendor），在 Linux / WSL 中：

```
make test    # go vet、单元测试、网络命名空间内的真实核心端到端测试、脚本检查、WebUI 端到端测试
make build   # 生成 dist/ksu_proxy_manager-v<版本>.zip 与 release-manifest.json
```

端到端测试需要环境变量 `KPM_TEST_CORES`（含 mihomo、sing-box 可执行文件或官方压缩包的目录）、`KPM_TEST_RULESETS`（可选）与 `JSDOM_NODE_PATH`（含 `node_modules/jsdom` 的目录），并依赖 `unshare` 创建用户/网络命名空间。

设计说明见 [docs/DESIGN.md](docs/DESIGN.md)。

设备测试位于 `src/internal/daemon/e2e_device_test.go`，只在显式设置 `KPM_DEVICE_TESTS=1` 的 root Android 测试设备运行。执行前须停止已安装模块，使用独立临时数据目录；测试后确认接管规则已清空，再恢复模块服务。

WebUI 浏览器回归另见 `scripts/test-webui-browser.mjs`，需要 Playwright 与本机 Chrome。用 `scripts/preview-webui.mjs <测试模块目录>` 在 Linux / WSL 启动隔离预览（目录格式与 `test-webui.mjs` 相同，二进制须为主机版本），输出访问地址与一次性测试密钥。预览使用独立临时配置和示例订阅，关闭流量接管，不访问设备数据。将密钥置于 `KPM_WEBUI_TEST_KEY`，执行 `node scripts/test-webui-browser.mjs <预览地址> <截图目录>`。浏览器测试会拒绝修改非预览数据目录；运行状态、流量与连接的视觉检查使用明确的测试数据，其余保存操作与真实服务往返。

## 已知限制

- 提供 arm64-v8a 与 x86_64 构建；安装时只保留设备主 ABI 对应的二进制，不支持 32 位设备。
- 内核低于 4.17 时无法按端口匹配策略路由，经系统解析器的 DNS 不会进入核心（域名分流依赖核心的嗅探）。
- XHTTP 仅 Mihomo 的 VLESS 节点支持；Mihomo 的 VMess+XHTTP、Trojan+HTTP/2 组合会在生成配置前明确拒绝。sing-box 的 XHTTP 节点仍跳过并提示。
- sing-box 的 Hysteria2/TUIC 不输出 uTLS，并提示指纹被忽略；含 `dialer-proxy`/`detour` 的订阅节点会跳过并显示原因，不静默改成无前置节点；未导入的多路复用字段会告警。
- 订阅总上限 8 MiB；Clash YAML 单独限制为 4 MiB，并在分配完整解析树前限制结构复杂度。异常密集的内容可能在字节上限前被拒绝。
- 规则集来自 MetaCubeX/meta-rules-dat，首次使用相关规则时需要联网下载；下载完成前相关规则暂不生效。
- WebUI 通过 `ksu.exec` 调用命令行桥接，请求内容会短暂出现在 root 进程的命令行参数中（Android 默认对普通应用隐藏其他进程信息）。
