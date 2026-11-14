# KernelSU Proxy Manager 2.0 设计文档

本文档依据本次重构要求重新编写，不沿用旧版技术文档。它描述 2.0 版本的目标、架构、关键决策与验证方法，是实现与测试的依据。

## 1. 目标与范围

### 1.1 目标

1. 在 KernelSU / Magisk / APatch 环境下，以一个 Go 守护进程统一管理 Mihomo 与 sing-box 两种代理核心，共用一份配置模型。
2. 透明代理稳定可靠：网络切换、核心崩溃、守护进程异常退出、模块禁用/卸载等场景下行为确定、可自愈、可清理。
3. 安全默认：不开放任何无认证的代理端口或控制端口；下载的核心必须经过 SHA-256 校验；所有文件仅 root 可读写。
4. 功能补齐：应用白名单/黑名单、域名/IP/应用/规则集分流、DNS 分流与 fake-ip、代理组（手动选择/自动测速）、订阅自动更新与差异预览、节点测速与复制、热点共享代理、真实应用名称、卸载时数据处理选项。
5. WebUI 不依赖页面跳转：在 KernelSU 管理器内通过 `ksu.exec` 桥接调用；在普通浏览器内通过带令牌的本机 HTTP 访问（默认关闭）。
6. 一次构建即一致发布：版本号、构建标识、静态资源缓存标识由构建脚本统一注入，发布前有门禁校验。

### 1.2 非目标

- 不内置代理核心与规则数据；首次使用需下载或导入。
- 不修改系统级网络设置（不改 APN、不全局关闭 IPv6、不改全局 `rp_filter`/`ip_forward`）。
- 不提供 TProxy / eBPF 接管模式（仅 TUN），但网络接管层按“计划 → 对账”抽象，后续可扩展。
- 不支持 Android 内核 < 4.10（缺少 `uidrange` 策略路由）。

## 2. 需求来源与处理对照

### 2.1 旧版已知问题

| 编号 | 问题 | 2.0 处理 |
|---|---|---|
| R01 | 源码领先于发布产物、门禁失败 | 版本升至 2.0.0；构建脚本同时生成二进制、静态资源版本、发布清单；门禁校验 ZIP 内容与清单一致 |
| R02 | 健康巡检把“状态不可读”当“不健康”直接停核心 | 健康结果三分类：进程退出 / 可修复偏差 / 暂不可读。只有进程退出触发重启流程；偏差由对账器补齐；读失败只记录并下次重试 |
| R03 | sing-box 仅用首个系统 DNS | 不再依赖系统 DNS；默认使用公共直连 DNS + 经代理 DoH，并按规则集分流，均可在设置中修改 |
| R04 | 核心异常后不自动恢复且直连 | 有界自动重启（10 分钟内最多 3 次，退避 2/5/15 秒）；可选“防泄漏”模式在核心异常期间阻断被接管应用流量 |
| R05 | Mihomo 固定开放无认证 7890 | 不再开放固定端口；仅在 127.0.0.1 随机端口开放带随机账号密码的 mixed 入站，供守护进程“经代理下载”使用 |
| R06 | 静态资源缓存标识不随版本更新 | 构建时注入 `versionCode`；守护进程对静态资源返回 `no-cache` + ETag |
| R07 | WebUI 依赖跳转到 loopback 页面 | 管理器内全部经 `ksu.exec` → `proxyctl api` 桥接，不跳转；浏览器访问为独立可选功能 |
| R08 | 健康只校验 IPv4 | 对账器同时管理 IPv4/IPv6 规则与路由 |
| R09 | `pm list packages` 慢、易超时 | 优先读取 `/data/system/packages.list`（按 mtime 缓存），失败才回退 `pm`/`cmd package` |
| R10 | daemon 继承调用者环境变量 | 守护进程与核心均使用最小白名单环境；移除可执行文件覆盖变量 |
| R11 | 停止只依赖 HTTP | 控制通道为 root 专属 Unix 套接字；`daemon stop` 失败时可按 pid 文件 + 进程身份核验发送信号；`proxyctl cleanup` 可在守护进程不在时清理网络 |
| R12 | 子进程表以 PID 为键 | 核心子进程由监督器单独持有 `exec.Cmd` 与退出通道，不存在 PID 映射表 |
| R13 | 回滚与正常启动环境不一致 | 只有一条启动路径；回滚即用上次成功配置走同一路径 |
| R14 | 超长函数、重复路径、遗留兼容代码 | 全量重写；按职责拆包；不保留旧 `ip` 文本解析路径 |

### 2.2 旧版功能缺口

| 缺口 | 2.0 处理 |
|---|---|
| 应用 allowlist | 模块自管 `uidrange` 策略路由，白名单为空时不接管任何应用（失败关闭），不存在“空名单扩大捕获” |
| 域名/IP 目的规则 | 规则支持 domain / domain_suffix / domain_keyword / ip_cidr / geosite / geoip / package / port / network |
| 节点复制、测速 | 提供复制接口；核心运行时经 Clash API 做端到端延迟测试，未运行时做 TCP 连接测试 |
| 真实应用名/图标 | WebUI 在 KernelSU 提供 `getPackagesInfo` 时读取应用名与图标，否则显示包名 |
| 订阅差异与自动更新 | 预览给出新增/删除/变更的完整名单；支持定时自动更新与流量/到期信息 |
| 投递目录枚举 | 列出 `/sdcard/Download` 中候选核心文件供选择导入 |
| 卸载 UI | 设置页提供“卸载时删除数据”开关（写入标记文件） |
| bridge 降级、WebSocket | 管理器内统一走桥接；浏览器模式使用轮询，无需 WebSocket |
| Hysteria2 obfs、SS 插件、sing-box WireGuard | 支持 salamander 混淆、obfs / v2ray-plugin 插件；sing-box 使用 endpoint 形式输出 WireGuard |

## 3. 参考模块取舍

| 来源 | 吸收的优点 | 在 2.0 中的实现 |
|---|---|---|
| mihomo_ref | 期望态/实际态对账、规则被外部删除可自愈 | `capture` 包的对账器，周期 + 事件触发 |
| mihomo_ref | 启停互斥、完成后才返回结果 | 守护进程内单一生命周期锁；API 同步返回最终状态 |
| mihomo_ref | 启动前配置预检，失败不停旧核心 | 先渲染并 `-t`/`check`，通过后才停止旧核心；新核心失败自动回滚 |
| mihomo_ref | 开机有界重试 + 失败兜底直连 | 监督器退避重启；放弃后清理接管规则 |
| mihomo_ref | 核心移出 App cgroup、`oom_score_adj` | 守护进程启动即迁入根 cgroup 并设置 `-1000`，核心继承 |
| mihomo_ref | 开机清理过期运行时状态 | 守护进程启动时清理 `run/staging`、`run/bridge`，并按身份核验结束遗留核心、清理路由（不在 post-fs-data 阶段做任何事） |
| mihomo_ref | 面板先于网络等待启动 | 守护进程开机立即启动，不等待网络 |
| mihomo_ref | 动态模块描述 | 守护进程在状态变化时原子更新 `module.prop` 的 description |
| mihomo_ref | 热点共享转发放行 | 自有 iptables 链放行 TUN 转发，仅作用于 TUN 接口 |
| sfm_ref | DNS 分流矩阵、fake-ip 排除 | 直连 DNS / 代理 DNS / fake-ip 三类服务器，按规则集选择；内置排除名单 |
| sfm_ref | 规则模板（广告、私有地址、大陆直连） | 预设 + 开关 + 用户规则分层 |
| sfm_ref | `packages.list` 按 mtime 缓存 | `apps` 包缓存 UID 映射并驱动路由更新 |
| sfm_ref | 数据与程序分离，升级保留用户数据 | 数据目录独立；配置迁移前保留原始备份 |

| 规避的缺陷 | 2.0 措施 |
|---|---|
| 无认证 root 命令执行面板、控制器监听 0.0.0.0 | 无任何命令执行接口；控制器只监听 127.0.0.1 随机端口并带随机密钥；管理 API 默认仅 Unix 套接字 |
| 核心下载无哈希、第三方镜像、任意 URL | 只接受 GitHub API 返回 digest 的官方资产；镜像仅在 digest 已知时用于资产下载 |
| 卸载不清理、路径错误 | 守护进程监听 `remove` 标记立即停止并清理；`uninstall.sh` 只处理数据删除且拒绝符号链接 |
| PID 复用误杀 | 发信号前核验 `/proc/<pid>/stat` 启动时刻、boot id 与可执行路径 |
| 按优先级整段删除他人规则 | 只修改/删除指向自有路由表 20260/20261/20262 的规则（与优先级无关）；iptables 只操作自有链 |
| 7777 权限、弱口令、静默装 APK、`pm clear` | 目录 0700、文件 0600、可执行 0755；随机强密钥；不安装 APK、不清除任何应用数据 |
| 改写 APN、全局关闭 IPv6 | IPv6 仅对被接管应用生效（代理或阻断），不触碰系统设置 |
| 巨型单体 shell 脚本 | shell 只做薄入口；全部逻辑在可测试的 Go 包中 |

## 4. 总体架构

```
KernelSU 管理器 WebView ──ksu.exec──► proxyctl api ──Unix 套接字──► proxy-managerd
浏览器（可选） ──HTTP + Bearer 令牌（127.0.0.1）────────────────────►      │
                                                                         ├─ store：配置/凭据/备份
                                                                         ├─ render：Mihomo / sing-box 配置
                                                                         ├─ supervisor：核心进程生命周期
                                                                         ├─ capture：策略路由对账（netlink）
                                                                         ├─ cores / rulesets：下载、校验、安装
                                                                         ├─ subscription：拉取、解析、差异
                                                                         └─ clashapi：流量、连接、选择、测速
```

- **proxy-managerd**：常驻守护进程。单实例（`flock`），开机由 `service.sh` 启动。
- **proxyctl**：命令行与 WebUI 桥接入口；通过 Unix 套接字访问守护进程。
- **核心进程**：由守护进程以子进程方式启动，独立进程组；守护进程持有其 `exec.Cmd`。

### 4.1 Go 包划分

| 包 | 职责 |
|---|---|
| `buildinfo` | 版本、构建标识（链接期注入） |
| `paths` | 模块目录与数据目录布局 |
| `fsutil` | 原子写入、JSON 读写、文件锁、安全路径 |
| `logx` | 带轮转、脱敏、环形缓冲的日志 |
| `config` | 配置模型 v3、默认值、校验、v2 迁移 |
| `store` | 持久化（单文件 + 修订号 + 备份） |
| `subscription` | 分享链接 / Clash YAML / sing-box JSON 解析与差异 |
| `render` | 引擎无关中间表示 + 两种渲染器 |
| `rulesets` | 规则集目录、下载、本地缓存 |
| `cores` | 核心注册表、GitHub 发布、下载、解包、ELF 校验 |
| `apps` | 包名与 UID 映射 |
| `capture` | 接管计划、netlink 对账、热点 iptables、sysctl |
| `proc` | 进程身份、cgroup 迁移、oom 调整 |
| `supervisor` | 核心启动、就绪判定、退出监控、停止 |
| `clashapi` | 两种核心共用的 Clash API 客户端 |
| `netx` | 直连 HTTP 客户端（自带 DNS、公网地址校验）与经代理客户端 |
| `daemon` | 编排（Manager）、HTTP API、任务、后台循环 |

## 5. 目录与数据布局

```
/data/adb/modules/ksu_proxy_manager/        模块目录（只读程序）
  bin/<abi>/proxy-managerd, proxyctl         abi 为 arm64-v8a 或 x86_64，安装时只保留一个
  proxyctl                                   稳定入口脚本（WebUI 调用）
  webroot/                                   WebUI
/data/adb/ksu_proxy_manager/                 数据目录 0700
  config/config.json                         配置 + 凭据（0600）
  config/backups/                            最近 10 份修订备份、迁移前原始文件
  cores/<engine>/<version>/<abi>/core        已安装核心（沿用 1.x 布局）
  core-index.json                            核心注册表（沿用 1.x 格式）
  rulesets/<engine>/<kind>-<name>.<ext>      规则集文件 + index.json
  run/                                       运行时：daemon.lock api.sock daemon.json core.json core/ bridge/ staging/（后两者在守护进程启动时清空）
  logs/daemon.log core.log                   各保留 1 份轮转
  .delete-on-uninstall                       卸载时删除数据的标记
```

**迁移**：首次启动发现 `config/model.json`（schema 2）且无 `config.json` 时，读取旧模型与 `config/secrets.json` 转换为 v3，旧文件原样复制到 `config/backups/legacy-*`。旧的 `generated/ staging/ runtime/` 为临时目录，迁移后删除。核心注册表格式兼容，直接沿用。

## 6. 配置模型 v3

单文件 JSON，顶层：

```
schemaVersion=3, revision, settings, nodes[], groups[], subscriptions[], routing, dns, apps, secrets
```

- `secrets` 段只在磁盘与内存存在，普通 API 永不返回；节点密码、UUID、私钥、订阅地址、浏览器访问密钥等均在此。唯一例外是用户显式请求的“含密钥备份”（`GET /backup?secrets=1`），它只能通过 root 专属的 Unix 套接字调用，浏览器访问的 TCP 监听拒绝该请求；导出到 Download 目录的含密钥备份在界面上需要二次确认。
- 实际配置修改和显式恢复时 `revision+1` 并写入备份；订阅 `LastError`、`UpdatedAt`、`Usage` 元数据单独判定，不提升修订号或轮转备份；完全相同的更新不写盘。写请求可带期望修订号，冲突返回 409。
- 损坏或丢失配置的恢复修订号不低于原文件可读出的修订号，且高于现存备份的最大修订号，避免复用旧编号；达到 int64 上限时明确失败。普通备份按修改时间保留最近 10 份，异常原件和旧版原件独立保留，恢复前仍须校验。
- `settings`：引擎、各引擎所选版本、自动启动、自动重启、防泄漏、IPv6、日志级别、TUN 协议栈、MTU、是否绕过局域网、热点共享、浏览器访问、下载方式、规则集自动更新。
- `nodes`：扁平结构，按协议使用相应字段；`subscriptionId` 标记来源；`upstream` 表示链式代理的前置节点。
- `groups`：`select`、`urltest`、`fallback` 或 `load-balance`；成员来自显式节点、其他组、全部节点、指定订阅，可加名称正则筛选；不允许组环。`fallback` 在 Mihomo 中按顺序使用首个可用出口，在 sing-box 中降级为 `urltest` 并告警（按延迟选优，无法保证相同优先级语义）。`load-balance` 仅 Mihomo 可用，`strategy` 支持 `consistent-hashing`（缺省）、`round-robin`、`sticky-sessions`，共用健康检查 URL/间隔但没有切换容差；sing-box 下的保存和渲染均拒绝，切换失败不写配置。负载均衡没有固定选中出口，API 不伪造 selected/now，WebUI 显示“按连接分配”。展开顺序为其他组、显式节点、订阅节点、全部节点，重复项保留首次出现；WebUI 可调整故障转移组显式节点和其他组各自的顺序。自动组清除手动选择与直连选项，非负载均衡组清除 strategy；空组仍使用 DIRECT 并告警。
- `routing`：运行模式（规则/全局/直连）、预设（绕过大陆 / 全局代理）、广告与 QUIC 拦截开关、用户规则（有序）、兜底出口。
- `dns`：fake-ip 或真实 IP、直连 DNS、代理 DNS、fake-ip 排除名单。
- `apps`：接管模式（全部 / 仅名单 / 排除名单）、包名、Android 用户列表；可选的 `routes`（包名 → 代理组 / `DIRECT` / `REJECT`，每个包名至多一条，上限 500）。`routes` 为空时不写入文件，schema 仍为 3；它被渲染为排在全部自定义规则与预设之前的包名规则（同一出口合并为一条），只对已被接管的应用、且在规则模式下起作用。接管范围（模式 / 包名 / 用户）的修改即时生效；`routes` 的修改属于核心配置，保存后处于“待生效”，重启核心后应用。被 `routes` 引用的代理组不能删除。

## 7. 网络接管设计

### 7.1 原则

核心关闭自动接管（`auto_route=false`），应用、DNS 与热点的接管规则由守护进程创建并对账。核心 TUN 库仍会为 IPv6 创建接口辅助规则，统一配置到专用表 `20262`，运行期间不干预，确认进程退出后再清理。这样：两种核心接管行为一致；白名单失败关闭；规则归属唯一可判定；应用安装/卸载后无需重启核心即可更新 UID 规则。

### 7.2 资源

| 资源 | 取值 |
|---|---|
| TUN 网卡 | `ksu-proxy0`，MTU 默认 9000 |
| 路由表 | `20260`（应用与热点流量，含绕行例外）、`20261`（仅 TUN，无绕行例外）、`20262`（核心库的接口辅助路由）；IPv4/IPv6 各一份 |
| 规则优先级 | 基准 = netd LOCAL_NETWORK 规则（`fwmark 0x0/0x10000 lookup local_network`）优先级 + 260；未找到时为 20260。TUN 子网回程 = 基准 + 1，热点入口 = 基准 + 2，应用 UID = 基准 + 10；DNS = netd EXPLICIT_NETWORK 规则优先级 − 100（Android 12+ 为 15900），未找到时为基准 − 1 |
| 归属判定 | 规则指向路由表 `20260` / `20261` / `20262` 即为本模块所有；`20262` 只在核心退出后清理，不按规则优先级删除。通用表 `2022` 及仅与本模块优先级相同的 goto/nop/unreachable 等动作规则不属于模块 |
| iptables 链 | `KPM_FWD`（仅热点共享启用时） |

普通应用规则位于 netd 的 LOCAL_NETWORK 之后、TETHERING / IMPLICIT_NETWORK / DEFAULT_NETWORK 之前（Android 12+：20000 → 20260；Android 10–11：17000 → 17260）：显式绑定网络或网卡的非 DNS 套接字不被接管；VPN（10000–14000）优先于本模块。端口 53 是下述例外。核心以 root（UID 0）运行，不在任何接管区间内。netd 布局变化时对账器会把规则移到新位置。

### 7.3 规则与路由

- 应用流量：每个 UID 区间一条 `uidrange A-B lookup 20260`（IPv4 与 IPv6 各一份）。全部模式为每个 Android 用户的 `10000–19999`、`20000–29999`（SDK 沙箱）、`90000–99999`（隔离进程）；名单模式由包名解析得到 UID（含对应沙箱 UID）并合并为区间；排除模式取补集。
- Android 系统共享 UID（<10000）以及 `com.android.captiveportallogin`、`com.google.android.captiveportallogin` 的整个共享 UID 和对应 SDK 沙箱始终排除。厂商其他认证包及 IoT 配网仍可能受 DNS 接管影响，不能宣称所有显式绑定网络流量都不受影响。
- DNS：系统解析器（netd）以应用 UID 发出查询，但套接字带“显式选择网络”标记，会在 EXPLICIT_NETWORK（16000）命中而绕过上述规则，导致 fake-ip 失效、得到被污染的解析结果。为此对同样的 UID 区间在 EXPLICIT_NETWORK 之前加 `uidrange A-B dport 53 lookup 20261`；热点接管时加入网络共享 DNS 转发进程的 UID 1052。只匹配端口 53，adbd（UID 2000）等显式绑定的非 DNS 流量不受影响。端口选择器需要内核 4.17+（旧内核会忽略未知属性把规则变成全匹配），更早的内核不加此规则。
- TUN 子网回程：核心的 system/mixed 协议栈用绑定在 TUN 地址上的内核套接字应答 TUN 上的 TCP 连接；Android 在 32000 处 `unreachable`，内核为 TUN 生成的直连路由所在的 main 表永远不会被查到。对 TUN 的每个实际地址（运行时读取，mihomo 与 sing-box 不同）加 `from <子网> iif lo lookup 20261`。
- 热点：对启用的共享网卡添加 `iif <网卡> lookup 20260`，并在 `KPM_FWD` 链放行进出 TUN 的转发；跳转位于现存 `bw_FORWARD` 之后。周期检查只补缺失项，不清空链；慢速 iptables 调用不持有状态锁。部分失败和清理失败分别保留重试状态，重新开启热点立即修复。
- 路由表 20260：`default dev ksu-proxy0`；对组播、广播、链路本地地址添加 `throw` 路由使其回落系统路由；开启“绕过局域网”时私有网段也 `throw`。fake-IP 和 TUN 自身网段具有更具体的 TUN/阻断路由，不会被 ULA 绕行覆盖。路由表 20261 只有 `default dev ksu-proxy0`（及下述防泄漏/IPv6 条目），局域网 DNS 服务器也进入 TUN。
- 防泄漏：在表中加入最大 metric 的 `unreachable default`，TUN 消失时被接管应用不可达而非直连。
- IPv6 关闭时：IPv6 表只有 `unreachable default`（被接管应用的 IPv6 立即失败并回退 IPv4），DNS 只返回 A 记录。
- TUN 出现后设置其 `rp_filter=2`（仅该网卡）。

### 7.4 对账器

周期 5 秒及关键事件（核心就绪、应用列表变化、设置变化）触发：计算期望规则/路由 → 读取内核实际（netlink dump，`ErrDumpInterrupted` 重试 3 次） → 增补缺失、删除多余。规则、路由、网卡任一读取失败均记为“暂不可读”，本轮不改动内核（不会把读取失败误判为 TUN/热点消失）。清理时删除指向自有表的全部规则并清空自有表，删除自有 iptables 链；清理未完成时标记为待清理，由维护循环继续重试。应用 UID 规则总数上限 1024。

应用列表缓存与引擎独立记录 generation，WebUI 读取不会消费引擎的变更信号。名单更新即使暂时无法对账也保留新的期望配置，并在后续维护中重试，不退回旧名单。

## 8. 核心生命周期

1. **准备**：加载配置快照 → 解析核心文件并复核 SHA-256 → 确认规则集文件（缺失则降级省略相关规则并后台补下载）→ 解析应用 UID → 渲染配置。
2. **预检**：`mihomo -t` / `sing-box check`，超时 45 秒，输出限长；失败直接返回错误，正在运行的核心不受影响。
3. **切换**：移除接管规则 → SIGTERM 进程组，5 秒后 SIGKILL → 启动新核心（最小环境、工作目录 `run/core`、标准输出接入日志）。
4. **就绪**：TUN 网卡出现且 Clash API `/version` 可用，限时 20 秒；失败则用上次成功配置回滚（“成功”指已建立接管并进入运行状态）。
5. **接管**：对账器建立规则；按配置通过 Clash API 同步每个手动选择组的选中项（sing-box 的 cache.db 会优先恢复上次的选择，必须覆盖）；状态置为运行中，记录 `run/core.json`（pid、启动时刻、boot id、可执行路径）。
6. **监督**：子进程退出 → 若非用户停止，按退避重启（10 分钟内最多 3 次），期间按“防泄漏”设置保留或移除规则；重启尝试本身失败（核心再次退出、超时未就绪）时同样遵守该设置：防泄漏开启则保留规则（TUN 不存在时只剩 unreachable 回退，应用被阻断），只有显式停止/禁用/卸载才无条件清理。退避等待不持有生命周期锁，等待中的停止/启动/退出优先；后台重载（规则集就绪）与维护循环的应用名单刷新在取得锁后重新核对核心仍在运行且未被用户停止。Clash API 连续 4 次无响应，或 TUN 网卡连续 3 个周期不存在而进程仍在，视为挂起：强制结束（记为意外退出）并走同一重启策略。
7. **停止**：先移除接管规则再结束进程，确认 TUN 消失后删除 `run/core.json`。
8. **孤儿处理**：守护进程启动时若同时启用防泄漏和开机自启，先安装显式阻断计划；其后核验并结束遗留核心，仅清理核心辅助资源，待新核心就绪再切换为 TUN 路由。显式阻断不因同名外部网卡存在而失效；未启用此保护时按普通清理流程处理。

自动重启失败后继续使用 10 分钟内 3 次的预算（2/5/15 秒）；开机首次失败后额外有限重试 3 次（5/15/60 秒）。损坏配置不反复重试。停止、禁用、手动启动与退出通过意图编号使旧重试失效。已就绪核心遇到暂不可读或热点防火墙失败时保留运行、后台对账；无法确认退出的进程也登记退出监听，确认退出后清理 PID 与辅助路由。上次成功配置保留深拷贝，避免与实时选择共用切片。

## 9. 配置渲染

引擎无关的中间表示包括：入站（TUN、本机 mixed）、出站（节点、组）、DNS、路由规则、规则集引用。两种渲染器只做字段映射，并对不支持的协议/特性给出明确告警（不支持的节点跳过并在状态中列出）。

Mihomo 的 VMess+XHTTP、Trojan+HTTP/2 等不支持的组合在渲染前明确拒绝，避免跳过节点后代理组退回直连。sing-box 的 Hysteria2/TUIC 不生成 uTLS 并提示忽略指纹。代理组保留名包括 DIRECT、REJECT、GLOBAL、PASS、REJECT-DROP、COMPATIBLE；迁移时统一重命名。组成员查找使用节点 ID 索引，避免每个组成员再次线性扫描全部节点。

- 本机 mixed 入站：127.0.0.1 随机端口，随机用户名密码（Mihomo 使用 `listeners`，sing-box 使用 `users`）。
- Mihomo 的 `sniffer.skip-src-address` 排除 IPv4/IPv6 回环源地址，保留管理客户端已校验的目标 IP；普通 TUN 应用仍正常嗅探。否则管理器的 CONNECT IP 会被改回域名，导致 DoH 引导重新依赖 DNS，且 IP 钉住失效。
- Clash API：127.0.0.1 随机端口 + 随机密钥；两种核心都启用，用于流量、连接、选择、测速、模式切换。
- 运行模式：Mihomo 原生 `mode`；sing-box 通过 `clash_mode` 规则实现 Global / Direct。
- 规则顺序：DNS 劫持 → 拒绝发往 TUN 自身网段（sing-box 为 IPv4/IPv6，Mihomo 为 IPv6；Mihomo 的 IPv4 网段与 fake-ip 池相邻，由核心自行处理）→ 私有地址直连 → 用户规则 → 预设规则（广告拦截、QUIC 拦截、大陆直连）→ 兜底。规则目标限于代理组、DIRECT、REJECT。已知差异：Mihomo 的原生 `global` 模式不再评估规则，私网流量也会进入 GLOBAL 组（需要局域网直连时应开启“绕过局域网”，由路由层实现）；sing-box 的私网直连规则位于 `clash_mode` 规则之前，Global 模式下仍直连私网。
- Mihomo 的 TUN IPv4 地址由 fake-ip-range 推导（198.18.0.1/30，`inet4-address` 会被忽略，已实测）；sing-box 使用 172.19.0.1/30。
- 规则集：只引用本地文件（Mihomo `type: file` + mrs；sing-box `type: local` + srs）。
- 来源 IP：schema 3 的 `Rule.Type=source_ip_cidr` 接受 IPv4/IPv6 单地址或 CIDR，拒绝带 `%接口` 的 IPv6 地址。渲染时补全单地址掩码并归一化网段，Mihomo 使用 `SRC-IP-CIDR`（含 IPv6），sing-box 使用 `source_ip_cidr` 数组，同条规则多值为 OR。沿用自定义规则顺序及启用状态，应用专用出口优先；Direct/Global 模式、DNS 劫持、内置私网直连的既有行为不变。只影响已进入核心且保留来源 IP 的连接，不增加热点接管或修改监听地址；热点客户端地址变化需更新规则。
- DNS：fake-ip 模式下大陆域名走直连 DNS，其余返回 fake-ip；真实 IP 模式下其余走经代理 DoH。节点域名用直连 DNS 解析。DNS 随运行模式切换：sing-box 用 `clash_mode` DNS 规则（直连模式全部直连解析，全局模式全部经代理解析）；Mihomo 由 `respect-rules` 保证 DNS 连接本身随模式走代理或直连，但服务器选择（`nameserver`/`nameserver-policy`）不随模式改变：直连模式下非大陆域名仍向“代理 DNS”服务器直连查询，在该类服务器被封锁的网络中可能解析失败（已知限制）。sing-box 只使用第一个 IP 形式的直连 DNS 与第一个代理 DNS，其余在启动告警中列出。

## 10. 订阅

- 支持格式：Base64/明文分享链接（ss、vmess、vless、trojan、hysteria2、tuic、anytls、socks、http、wireguard）、Clash/Mihomo YAML、sing-box JSON。
- Clash YAML 单独限制 4 MiB，在建立 yaml.Node 树前进行保守的结构分隔符预算检查，随后仍限制解析深度与别名展开计数。支持 SIP003 未编码分号、SS Base64 百分号编码、WireGuard 原始加号，以及 sing-box ALPN/server_ports 的单字符串或数组写法。
- `dialer-proxy`/`detour`：解析时记录节点在原文中的名称与所指向的名称，待节点 ID 确定后（订阅为过滤并分配稳定 ID 之后，粘贴导入为生成 ID 之后）转换为 `upstream`。只接受指向同一份内容中可导入节点的引用；指向代理组、不存在/已跳过/被过滤的节点、名称重复无法确定、形成环路或超过 3 层的节点整体跳过并提示，不静默删除前置关系。校验规则与配置校验一致，因此通过的节点其整条链路也都通过。`smux`/`multiplex` 未导入时显示兼容性告警。
- 提交时订阅自带的前置优先；订阅未指定前置的节点保留用户先前设置的前置。若保留的前置（或其他节点指向本订阅节点的前置）与订阅新给出的链路合起来形成环路或超过层数，切断非订阅提供的那一段并在结果中提示（自动更新写入日志），避免整个订阅此后无法提交。预览把“订阅自带前置与已保存的不同”计为变更。已知限制：订阅取消某节点的前置后，已保存的前置无法与用户手动设置区分，会继续保留。
- 拉取：HTTP(S)（界面提示建议 https）、大小上限 8 MiB、可指定 User-Agent、可直连或经代理；读取 `subscription-userinfo` 头保存流量与到期信息。错误信息入库与返回前去除订阅地址与令牌。解析到内网地址的非本地主机被拒绝（包括经代理与重定向）。
- 预览：给出新增/删除/变更名单与解析告警；提交时按“订阅 + 节点名”保持节点 ID 稳定，从而保留组内选择。
- 自动更新：按订阅设置的间隔在后台执行并直接提交；失败按 10/20/40/80/160/320 分钟退避，封顶 6 小时；变更影响运行配置时标记“待应用”，纯元数据不干扰修订号与预览。

## 11. 核心与规则集下载

- 核心：通过 GitHub API 列出 `MetaCubeX/mihomo`、`SagerNet/sing-box` 发布，按 ABI 选择资产（`android-arm64` / `android-amd64`），必须带 `digest`（SHA-256）并在下载后核验；可选镜像前缀只用于资产下载。
- 本地导入：仅 root Unix 桥接允许；支持 `.gz`、`.tar.gz`、`.zip`、裸 ELF。按允许目录逐级 `openat(O_NOFOLLOW)`，对已打开文件 fstat、限长复制，阻止校验后替换符号链接或 FIFO。解包限制大小与条目类型，忽略共享库（如 libcronet.so）；ELF 机器类型须匹配；在独立进程组中执行版本命令（先 `-v` 后 `version`，输出限长、超时整组结束）识别引擎与版本。
- 规则集：来自 `MetaCubeX/meta-rules-dat` 的 `meta`（mrs）与 `sing`（srs）分支，按需下载，可每周自动更新。
- 下载方式：自动（先直连，失败且核心运行时改为经代理）、仅直连、仅经代理。每条路径分别解析、验证全部地址并钉住 IP；代理路径的 DNS 也通过认证核心，用固定双栈地址引导 Cloudflare DoH，失败后尝试其他地址和 Google DoH。直连 DNS 返回污染地址时可改由代理独立重验，但私网结果、重定向私网及 NAT64/6to4/Teredo 隧道前缀始终拒绝。不会为代理下载回退到本地 DNS。
- 超时：版本列表 1 分钟、订阅与规则集 5 分钟；核心资产（数十 MB）不设总时长，连续 60 秒未收到数据才判定停滞，慢速网络也能下完。

## 12. 管理 API

- 传输：Unix 套接字 `run/api.sock`（0600，视为 root 可信）；可选 TCP `127.0.0.1:<端口>`，要求 `Authorization: Bearer <密钥>`、校验 Host 与 Origin，对失败认证限速（正确密钥不受限速影响）。密钥只在用户点击“生成密钥”时产生并显示一次，未生成密钥时不监听。
- 生命周期操作使用守护进程级 context，客户端断开不会中断启动/停止。
- 资源：`status`、`core/{start,stop,restart}`、`settings`、`nodes`、`groups`、`proxies`、`subscriptions`、`routing`、`dns`、`apps`、`cores`、`rulesets`、`tasks`、`logs`、`traffic`、`connections`、`backup`（含 `backup/export` 写入 Download 目录、`backup/files`、`backup/restore` 支持文件/自动备份/文档）、`system`、`diagnostics`。
- 长任务（下载、订阅刷新）返回任务 ID，前端轮询进度，可取消。
- 统一错误格式：`{"error":{"code","message","field"}}`；列表字段始终为数组（不返回 null）。
- 浏览器 TCP 禁止本地核心导入与按路径恢复；令牌仍有修改配置、恢复文档及下载官方核心的管理权限，不是只读密钥。

## 13. WebUI

- 纯静态 ES 模块，无打包步骤；所有资源与模块导入的查询串 `?v=` 由构建脚本替换为 versionCode，升级后不会命中旧缓存。
- 传输层自动选择：存在 `window.ksu` 时使用桥接（命令参数只含固定方法、`/api/v1/` 前缀且字符集受限的路径和 Base64 正文，单个参数远小于 128 KiB，大正文分块；Unix 套接字本身按 root 可信，故不再逐路由白名单）；否则使用 HTTP + 令牌。管理服务未运行时自动启动一次（桥接用 `code` 区分“服务未运行”与请求自身无效）。
- 备份导出/导入经守护进程读写内部存储 Download 目录（管理器 WebView 不支持文件下载/选择）。
- 页面：概览、节点与代理组、订阅、分流与 DNS、应用、核心与规则集、连接、日志、设置。
- 所有动态文本经转义或 `textContent` 输出；严格 CSP，无内联脚本。
- 分流与 DNS 分别保留各自读取时的修订号。合法 ID 中的连续点可通过桥接，实际 `.`/`..` 路径段及编码后的路径穿越仍拒绝。桥接区分未连接、超时和响应中断，结果未知的写操作不会因误报服务未运行而自动重发。

## 14. 模块脚本

| 脚本 | 行为 |
|---|---|
| `customize.sh` | 按主 ABI 选择 `bin/arm64-v8a` 或 `bin/x86_64`（其余中止）并删除其他架构，校验安装路径与文件完整性，设置权限；不联网、不触碰用户数据 |
| `service.sh` | 后台等待开机完成后启动守护进程；失败时按 5/15 秒重试两次，输出记录到 `logs/service.log` |
| `action.sh` | 切换核心运行状态并打印状态 |
| `uninstall.sh` | 若存在“卸载时删除数据”标记则安全删除数据目录（拒绝符号链接），否则保留；在开机早期运行，不调用任何可能阻塞的命令 |
| `proxyctl` | 命令行与 WebUI 入口，转发到 `bin/<abi>/proxyctl` |

### 14.1 在线更新

- `module.prop` 的 `updateJson` 固定为 `https://github.com/<owner>/<repo>/releases/latest/download/update.json`。检查与下载由 KernelSU / Magisk / APatch 管理器完成，守护进程不参与，也不新增任何联网行为；守护进程改写 `description` 时保留该行。
- 构建脚本由 `module.prop` 与 `CHANGELOG.md` 生成 `dist/update.json`（`version`、`versionCode`、`zipUrl`、`changelog`）和 `dist/changelog.md`（当前版本一节），两者与安装包一起作为标签 `v<版本号>` 的 Release 附件发布。下载地址带版本标签，更新信息取“最新正式 Release”：只有 Release 发布后更新才可见，不存在提示更新而安装包尚未上传的窗口；草稿与预发布不推送。
- 门禁：`versionCode` 必须等于 主×10000 + 次×100 + 修订（管理器仅在其增大时提示更新）、`updateJson` 符合上述格式、`CHANGELOG.md` 有当前版本的小节、`update.json` 指向的文件名与实际安装包一致；任一不满足则构建失败，`make test` 也执行其中不依赖安装包的检查。
- 安装包的完整性依赖 GitHub 的 HTTPS 与管理器自身的安装流程，`update.json` 不带摘要（各管理器的格式没有该字段）；`release-manifest.json` 的 `zipSha256` 供人工核对。没有 `updateJson` 的旧版本（≤ 2.0.3）需要手动升级一次。

## 15. 安全设计要点

- 所有外部输入（API 正文、订阅内容、归档、发布元数据）有大小上限与结构校验；YAML 别名按展开后计入节点数上限并限制深度；发布标签与资产名须为安全文件名。
- 子进程只用参数数组执行，不经 shell；`proxyctl` 桥接只接受固定方法与 `/api/v1/` 前缀路径；daemon 在 Android 上不继承调用者的 `PATH`。
- 日志写入前脱敏（URL 凭据、密码、令牌、UUID 形式的凭据字段），并精确替换当前与上一份运行配置中的全部凭据字面量；核心自检失败的输出按候选配置凭据脱敏后才返回。
- 发信号前核验进程身份；不按名称杀进程。

## 16. 日志与诊断

- 守护进程日志与核心日志分别写入文件（1 MiB 轮转）并保留内存环形缓冲供 API 增量读取。
- 诊断接口给出：内核特性（uidrange、TUN）、当前规则/路由快照、私人 DNS 设置（会绕过 DNS 劫持）、规则集状态、最近错误。

## 17. 测试策略

| 层级 | 内容 |
|---|---|
| 单元测试 | 配置校验与迁移、订阅解析、渲染映射、UID 区间计算、对账计划、API 鉴权与路由、日志脱敏 |
| 真实核心校验 | 对代表性配置分别执行 `mihomo -t`、`sing-box check`（1.13 与 1.14） |
| 网络命名空间集成 | 在 `unshare -rn` 中创建 TUN、执行对账、验证规则/路由、清理与自愈 |
| 端到端 | 守护进程 + 真实 Mihomo / sing-box 1.14 / sing-box 1.13 在命名空间内导入（归档与裸文件）、启动、接管、代理请求、模式与选择切换、应用名单热更新、崩溃重启、挂起重启、失败关闭、停止与退出清理、孤儿回收 |
| WebUI | jsdom 加载真实 WebUI，经模拟的 `ksu.exec` 调用真实 proxyctl 与守护进程，覆盖各页面主要操作与分块上传 |
| 脚本与发布 | `sh -n`、安装脚本模拟执行、在线更新信息检查、发布门禁 |

## 18. 已知限制

- 需要内核支持 `uidrange` 策略路由（4.10+）与 `/dev/net/tun`。
- 开启“私人 DNS”时系统 DNS 走 853 端口加密连接，DNS 劫持与 fake-ip 不生效（诊断页会提示）。
- 热点共享客户端的 DNS 由系统解析，依赖核心嗅探识别域名。
- 浏览器访问模式为明文 HTTP，仅监听 127.0.0.1。
