# terc 与 WebSocket：调研结论与分阶段计划

- 状态：阶段 0、2、3、4 已完成，另加“保护长连接”一批改动（§2.8），并按集成后的审查意见做了修正（§11）。阶段 1（实测）待用户完成。分支 `claude/websocket-groundwork`（PR #4），最初基线 `7975ab3`。
- 日期：2026-10-20
- Mihomo 源码出处：`MetaCubeX/mihomo` 的 `Meta` 分支，commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`
  （2026-09-30 +0800 提交）。下文 Mihomo 的行号都以这个 commit 为准。
  初稿用的是 2026-10-20 抓取的单个原始文件，没有记录 SHA；按 `88dcbf7` 重新核对后改正了 §2.2，其余行号也已对齐。
- 文档出处：`MetaCubeX/Meta-Docs`（`docs/config/general.md`、`docs/config/proxies/transport.md`、`docs/api/index.md`），
  地址为 `https://raw.githubusercontent.com/MetaCubeX/Meta-Docs/main/docs/...`。
- 下文结论都来自读源码，还没有在真实环境里验证（原因见 §9）。需要实测的地方都标了“待实测”。
- terc 的行号以本分支当前代码为准（已按审查修正后的代码重新核对）。

## 0. 结论速览

“WebSocket 支持”有三种不同的含义，优先级如下：

| 含义 | 是什么 | 对用户的价值 | 本分支做了什么 | 状态 |
| --- | --- | --- | --- | --- |
| A | AI 工具的流量（`wss://`）经 Mihomo 转发 | 最高：断线就等于对话中断 | 连接视图（时长、速率、AI 标记、断开记录）；不必要的重载不再发生；会断线的操作先确认 | 阶段 2 完成，§2.8 完成 |
| B | 代理节点使用 WebSocket 传输（`network: ws`） | 中：订阅里的节点能不能用 | 链接转换、`httpupgrade` 规范化、表单支持 Host / HTTPUpgrade / 早期数据 | 阶段 4 完成，剩余缺口见 §3.4 |
| C | terc 自己用 WebSocket 读控制器流 | 低：现有的 chunked HTTP 已经能用 | std-only 的 `src/ws.rs` 读取 `/connections` 推送，失败时自动回退到轮询，设置里可关闭 | 阶段 3 完成，见 §4 |

一句话：**对 Mihomo 来说，`wss://` 只是一条存活很久的 TLS/TCP 连接，它不解析 WebSocket 帧。**
所以 A 的核心问题是“长连接会不会被重载、切节点、TUN 重建打断”，以及“terc 能不能把长连接显示出来”，
而不是 WebSocket 协议本身。

按 `88dcbf7` 的源码，最容易被忽视的一点是：**每次重载配置都会断开经 `proxy-providers:` 节点转发的所有连接**（§2.2 第 2 条）。
订阅通常就是 provider，所以对 AI 会话来说，“少重载”比“重载更快”重要得多。

## 1. 三种含义怎么区分

- **A：业务流量是 WebSocket。** 例如 OpenAI Realtime 一类的 `wss://` 接口、IDE 或浏览器里的 AI 应用长连接。
  SSE、HTTP/2 长流式响应在代理层面的表现相同，都是长时间不结束的 TCP 连接。
- **B：节点的传输层是 WebSocket。** vmess / vless / trojan 节点配置 `network: ws`，
  把代理协议包进 WebSocket（常配合 CDN）。这与用户访问什么网站无关。
- **C：控制器 API 走 WebSocket。** Mihomo 的 `/traffic`、`/memory`、`/logs`、`/connections`
  同时支持 chunked HTTP 和 WebSocket。terc 目前用的是 chunked HTTP。

## 2. A：AI 工具的 WebSocket 流量经过 Mihomo

### 2.1 入站路径

- 系统代理或 `HTTPS_PROXY` 方式：客户端对 mixed-port 发 `CONNECT host:443`
  （`listener/http/proxy.go:68`），之后 Mihomo 只转发 TLS 字节流。
- 明文 `ws://` 经 HTTP 代理：Mihomo 识别 `Upgrade` 请求并转发
  （`listener/http/proxy.go:86` → `listener/http/upgrade.go:29`）。
- TUN 方式：按普通 TCP 连接处理。很多 CLI 和 Node 程序不读 macOS 或 GNOME 的系统代理，
  只认环境变量，或者只能靠 TUN 接管。这一点由用户决定（§8）。

### 2.2 重载配置会不会断开已建立的连接

terc 保存配置后会调用 `install_config`（`src/mihomo.rs:2326`），再由 `reload_config`
发送 `PUT /configs?force=true`（`src/mihomo.rs:3023`）。在 Mihomo 端：

1. `updateConfigs` 读取 `force`，解析配置后调用 `executor.ApplyConfig(cfg, force)`
   （`hub/route/configs.go:401`–`450`，`hub/executor/executor.go:84`–`123`）。
2. `ApplyConfig` 自己不遍历连接表，`updateProxies` 也只是替换代理表（`tunnel/tunnel.go:230`–`235`）。
   **但是**它会调用 `loadProvider`（`executor.go:115`）→ `proxySetProvider.Initial()`，
   而 `Initial()` 最后执行 `closeAllConnections()`（`adapter/provider/provider.go:152`–`165`），
   **关闭所有 `providerChains` 里含有该 provider 名字的连接**（`provider.go:167`–`177`）。
   这在启动时和**每一次**重载时都会发生，http 和 file 类型的 provider 都一样。
   顶层 `proxies:` 里的节点（provider 名为空）不受影响。
   定时或手动更新 provider 走的是 `setProxies`（`provider.go:103`–`112`），**不会**关闭连接。
   所以除了 `DELETE /connections`（`hub/route/connections.go:73`–`87`），重载也是一个关闭者。
3. 重载期间隧道先进入 `OnSuspend`（`executor.go:89`），再进入 `OnInnerLoading`（`:112`），
   直到 `OnRunning`（`:119`）才恢复。这段时间里非内部（non-INNER）的**新**连接会被直接关闭
   （`tunnel.go:270`–`273`、`:502`–`506`）。窗口包含 provider 的初次加载：
   有缓存文件时只读本地（`component/resource/fetcher.go:56`–`71`），没有缓存时同步下载（`fetcher.go:100`–`101`），
   窗口会被拉长。WebSocket 恰好在这段时间重连会失败，需要应用自己重试。
4. 监听器（HTTP、SOCKS、mixed 等）只在 `genAddr(bind-address, port, allow-lan)` 与 `RawAddress()` 不同时才重建
   （`listener/listener.go:107`–`128`、`:443`–`478`、`:709`–`718`）；`PUT` 只有带 `force=true` 时才会重建经典监听器
   （`executor.go:186`–`208`）。重建时 `Close` 只关闭监听 socket（`listener/mixed/mixed.go:43`–`46`），
   已接受的连接在各自的 goroutine 里继续运行（`mixed.go:124`–`141`）。
   **所以改端口或 `allow-lan` 不会断开已建立的连接**，只是旧地址上的新连接会失败。
   具名 `listeners:` 无论是否 force 都会按差异处理，变化或删除的会被关闭（`listener.go:627`–`654`）。
5. TUN：每次重载都会调用 `ReCreateTun`（`executor.go:108`、`:210`–`212`）。配置不变时只调用 `OnReload()`
   （`listener.go:515`–`519`）；配置变了就执行 `closeTunListener()`（`:522`、`:720`–`724`），
   关闭 tun 栈和网卡（`listener/sing_tun/server.go:670`–`688`）。**TUN 一旦重建，经 TUN 转发的连接全部中断。**
   terc 的 TUN 开关（`set_tun_enabled`，`src/mihomo.rs:2966`）走 `PATCH /configs` → `ReCreateTun`（`configs.go:377`），效果相同。
   macOS 上非 root 内核开启 TUN 时，terc 会改写配置并重启内核（`src/privilege.rs:386`–`443`），所有连接都会断开。
6. `PATCH /configs`（`configs.go:330`–`399`）先调用 `SetAllowLan` / `SetBindAddress`，再用当前或新值调用各个 `ReCreate*`
   （`:371`–`380`），只重建真正变化的部分。`allow-lan`、各端口、`tcp-concurrent`、`find-process-mode`、`log-level`
   都在这里实时生效，**不挂起隧道，也不重新初始化 provider**。改 TUN（包括开关）会重建 TUN（`:377`）。
7. 用 `PATCH /configs` 切换模式只是 `mode = m`（`tunnel.go:256`–`258`），不关闭连接。

结论：

- 经顶层 `proxies:` 节点、且不走 TUN 的连接：只要 TUN 配置不变，重载**应当**保留，代价是重载窗口内的新连接会失败。
- 经 `proxy-providers:` 节点的连接：**每次重载都会被关闭**。机场订阅一般是 provider，所以这是 AI 会话最常见的断线原因之一。
- 经 TUN 的连接：TUN 配置变化或开关时全部中断。
- 以上仍是读源码的结论，**待实测**（§6 阶段 1、§10）。

terc 自己的行为：在分组里选节点（`src/main.rs:1273` → `src/mihomo.rs:1669`）不会关闭连接。
用户在连接视图里主动关闭时（`src/main.rs:2468` 单条、`:2481` 全部）、重载配置时（provider 节点）、
切换 TUN 时和停止内核时会关闭。§2.8 说明 terc 怎样减少和提示这些情况。

### 2.3 选节点与 url-test 自动切换

- `Selector.Set` 只修改 `selected`（`adapter/outboundgroup/selector.go:83`–`92`），
  `PUT /proxies/:name` 也只调用 `Set` 并缓存选择（`hub/route/proxies.go:74`–`104`）。
- `URLTest.DialContext` 只在**拨号时**调用 `fast()` 选择最快节点（`adapter/outboundgroup/urltest.go:57`–`77`）。
  当前最快节点只有在缺失、失效或延迟超过“最佳值 + tolerance”时才会被替换（`urltest.go:138`–`141`），
  选择结果由 singledo 缓存 10 秒（`urltest.go:213`）。
- Fallback 在拨号时选第一个存活的节点，固定的 `selected` 失效后会被清除（`adapter/outboundgroup/fallback.go:32`、`:105`–`124`）。
  拨号失败累计到 `maxFailedTimes`（默认 5，`groupbase.go:97`–`98`）会提前触发健康检查（`groupbase.go:265`–`300`）。
  这些都只影响新连接。
- `lazy` 默认是 `true`（`adapter/outboundgroup/parser.go:51`–`52`）：分组在一个 interval 内没有被用到时跳过定时健康检查
  （`adapter/provider/healthcheck.go:45`–`61`）。闲置分组的延迟可能是旧的，但不会因此关闭连接。
- 所以分组切换不会断开已建立的 WebSocket。但如果是**节点本身**故障导致切换，连接早已断了，
  重连可能换到新节点（url-test 或 fallback），出口 IP 随之变化。部分服务可能因此要求重新认证或触发风控（可能，不确定）。
  fallback，或者调大 url-test 的 tolerance，出口会更稳定。
- terc 默认的 AI 组是 `url-test`、`interval: 300`、`tolerance: 50`（`src/compose.rs:1209`–`1218`），
  AUTO 组也是 url-test（`src/compose.rs:1256`–`1264`）。
  如果更在意出口稳定，用户可以在 `rules.conf` 的 `[ai]` 里设置 `type = fallback`，或者固定成员。
  本分支**不改默认值**，由用户决定（§8）。

### 2.4 TCP keep-alive

- 配置键是 `keep-alive-interval`、`keep-alive-idle`、`disable-keep-alive`
  （`config/config.go:447`–`449`），重载时生效（`executor.go:406`–`408`）。
- 实现（`component/keepalive/tcp_keepalive_go123.go:13`–`25`）：值为 0 时交给 Go 的默认值。
  按 Go `net.KeepAliveConfig` 的语义，Idle 和 Interval 默认都是 15 秒
  （<https://pkg.go.dev/net#KeepAliveConfig>）。Meta-Docs 示例同样写 15/15，
  并说明调大是为了减少移动设备耗电。Android 上会强制禁用
  （`component/keepalive/tcp_keepalive.go` 中的 `SetDisableKeepAlive`）。
- 它们是 TCP 层的探测，作用是让 Mihomo 到节点这一段的 NAT 和防火墙状态保持活跃。
  它们**不能**代替应用层的 WebSocket ping，因为 Mihomo 不碰 WebSocket 帧。
- terc 的模板不写这些键（`src/compose.rs:659` `template_base`），所以使用默认值 15 秒，已经足够积极。
  建议：默认不改，更不要禁用。

### 2.5 TUN 与 NAT 的空闲超时

- TUN 的 `udp-timeout`（`config/config.go:314`）只作用于 UDP（例如 QUIC），与 WebSocket 无关。
  中继本身没有 TCP 空闲超时（`common/net/sing.go:69`–`80`）；UDP 有 60 秒读超时（`tunnel/tunnel.go:63`，`tunnel/connection.go:163`、`:177`）。
- 家用路由器和运营商 NAT 对空闲 TCP 的超时各不相同。Mihomo 到节点这一段有 15 秒的 keep-alive 兜底；
  节点到目标站点这一段在远端，terc 控制不了。应用层心跳由应用自己负责。
- 睡眠、切换网络、VPN 冲突会让所有连接断开，这在代理层面无法避免。

### 2.6 嗅探（sniffer）

terc 模板默认关闭嗅探（`src/compose.rs:678`）。开启后，TLS 嗅探只读取 SNI，
HTTP 嗅探读取 `Host`。两者都不会改动 WebSocket 的内容，风险很低。
唯一的副作用是 `override-destination: true` 可能让规则按嗅探到的域名重新匹配。

### 2.7 terc 的可观测性（阶段 2，已完成）

Mihomo 不提供任何断开原因：`Manager.Leave` 只删除 id（`tunnel/statistic/manager.go:44`–`46`），
快照里也没有已关闭列表。唯一的间接信号是 `/logs` 里的拨号失败（warning，`tunnel.go:629`、`:631`），
拆除连接从不记日志。所以 terc 只能对比相邻快照，并结合自己的操作推断原因。

已完成（`src/conns.rs`）：

1. “时长”列：用当前时间减去 `start`，`parse_rfc3339_ms` 只依赖 std，接受 Go `RFC3339Nano` 的输出
   （0–9 位小数、`Z` 或 `±hh:mm`）。Go 零时间不显示时长。
2. 单连接速率：`Tracker::observe` 按连接 id 对相邻快照求差，间隔不足 500 毫秒的快照不更新速率。
3. 存活 60 秒以上的连接标为“长连接”；目标、嗅探域名或 `AI` 分组命中 AI 预设规则时标为 AI。
   `o` 在字节数、时长、速率三种排序之间切换，`f` 只看长连接和 AI 连接。
   列宽不够时按优先级取舍：先显示当前排序的数值（字节或速率的合计），再依次加进程、规则、上下行分开、入站，
   每加一列都要给目标地址留够 18 格，剩下的宽度归目标地址（最多 48 格），不再留空白（`src/panels.rs` `draw_connections`）。
4. 长连接或 AI 连接消失时，记入断开记录（`d` 查看，最多 50 条）并写一行日志，包括 host、链路、provider、存活时长和字节数。
   AI 连接只有存活满 10 秒，或者是被 terc 的操作断开时才记录；1 秒的普通请求、正常结束的 keep-alive 不算（`AI_SESSION_SECS`）。
   原因来自 terc 自己的操作：单条断开、全部断开、内核停止或重启，以及 §2.8 的配置重载和 TUN 重建；
   同一次观察里有 3 条以上没有原因的断开时，提示可能是网络切换、睡眠或节点故障。
   AI 连接无故断开时会弹出一次安静的提示（30 秒内不重复）。
   断开记录在没有右侧详情栏的窄窗口里优先显示原因；Enter 打开整条记录；新记录插到前面时光标仍停在原来那一条。
5. `providerChains` 已解析，详情里显示 provider，§2.8 用它判断哪些连接会被重载断开。
6. “内核停止”的判定：一次 `GET /version` 超过 700 毫秒或失败，快照也会是 `running: false`
   （`fetch_core_snapshot`，以及线程崩溃时 `SendOnDrop` 发出的默认快照）。所以 `accept_snapshot`（`src/main.rs:1038`）
   连续两次轮询都没看到内核、并且没有 `/connections` 推送时才清空列表；推送正常时轮询怎么说都不清空。
   代价是真正的停止晚一个轮询周期（2.2 秒）才记入断开记录。
   另外，Mihomo 的 `uploadTotal` / `downloadTotal` 在同一进程里只增不减；变小说明内核在两次观察之间重启过
   （例如被 launchd 或 systemd 秒级拉起），这次观察里的断开记为“内核已停止或重启”（`Tracker::note_totals`）。

### 2.8 保护长连接（已完成）

1. **不做不必要的重载。** `regenerate_routing`（`src/mihomo.rs:2175`）生成配置后，先按运行时模式得到最终文本；
   如果和当前 `config.yaml` 完全相同，就跳过 `mihomo -t` 和 `PUT /configs`，但照常写订阅缓存、分流选择和
   `generated/<profile>.yaml`，结果提示“配置未变化，未重载，现有连接不受影响”。判断在 `reload_needed`
   （`src/mihomo.rs:3078`）。上一次重载没有得到明确答复时（`RELOAD_UNCERTAIN`），下一次即使内容相同也会重载。
   用户手动“重载配置”仍然总是重载。
2. **能实时改的设置用 `PATCH`。** 内核运行时，`allow-lan`、`port`、`socks-port`、`mixed-port`、`tcp-concurrent`、
   `find-process-mode`、`log-level` 先用 `mihomo -t` 校验并保存（`install_config_keep_mode`，`src/mihomo.rs:3084`），
   再 `PATCH /configs` 并读回 `GET /configs` 核对（`patch_config_value`，`src/mihomo.rs:3093`）。
   PATCH 失败、读回不一致，或者模块覆盖了这个键时，退回完整重载（`apply_core_setting`，`src/settings.rs:459`）。
   这次退回的重载也失败时，文件已是新值而内核可能还是旧值，所以设置 `RELOAD_UNCERTAIN`，下一次重新生成一定重载。
3. **会断线的操作先确认**（`src/guard.rs`）。全部断开、关闭 TUN、macOS 上会重启内核的开启 TUN、停止内核，
   以及重载配置（切换配置或分流方案、重载、DNS / 模块开关、手动更新订阅、修改当前订阅地址）在会影响长连接或 AI 连接时，
   先弹出一行提示，说明会断开多少条、其中 AI 多少条；6 秒内再按一次才执行。
   重载只统计经 provider 节点的连接，关闭 TUN 只统计 TUN 入站的连接。没有受影响的连接、内核未运行或在首次设置流程里时不提示。
   重载可能因为内容不变而被跳过，所以重载的提示写“可能断开”。
4. **原因只记在真正被断开的连接上。** 确认时只记“内核停止”（全部断开由 `X` 自己记）。重载和 TUN 改动由执行它的
   `run_action` 线程在发出请求的前一刻通知界面（`announce_disruption`，`src/mihomo.rs:3069`，经线程局部的发送端
   `report_disruptions`，`:3063`）：`reload_config` 发 `PUT` 之前记“配置重载”，只给经 provider 节点的连接；
   `set_tun_enabled` 发 `PATCH` 之前记“TUN 重建”，只给 TUN 入站的连接；macOS 为开启 TUN 重启内核之前记给所有连接。
   内容不变而跳过重载、`mihomo -t` 拒绝、没有 DNS 块等提前失败的情况都不会发通知，也就不会把同时自然结束的连接算到重载头上。

## 3. B：使用 WebSocket 传输的节点

### 3.1 Mihomo 的字段

字段定义见 Meta-Docs `transport.md` 和 `adapter/outbound/vmess.go:165`–`172`（`WSOptions`，vmess、vless、trojan 共用，`trojan.go:66`）：

```yaml
network: ws
ws-opts:
  path: /path
  headers: { Host: example.com }
  max-early-data: 2048
  early-data-header-name: Sec-WebSocket-Protocol
  v2ray-http-upgrade: false
  v2ray-http-upgrade-fast-open: false
```

补充说明：

- 运行时会自动把路径里的 `?ed=N` 解析成早期数据设置（`transport/vmess/websocket.go:492`–`503`）。
  `max-early-data > 0` 时走早期数据路径（`:505`–`507`）；`early-data-header-name` 为空时早期数据拼在路径里（`:428`–`432`）。
- `headers.Host` 覆盖 HTTP 的 Host（`websocket.go:404`–`411`）；vmess 和 vless 开启 TLS 但没写 servername 时也用作 SNI
  （`vmess.go:197`–`203`、`vless.go:179`–`182`）。**trojan 不会**：`sni` 为空时取 `server`（`trojan.go:286`–`287`），
  ws 的 TLS 用的就是这个 SNI（`trojan.go:135`）。所以经 CDN 的 trojan ws 节点要同时填写 `sni`。
- 开启 `v2ray-http-upgrade` 时不发送 `Sec-WebSocket-Key` 和 `Version`，收到 101 后直接返回原始连接
  （`websocket.go:414`–`425`、`:471`–`473`）；`fast-open` 推迟读取 101（`:446`–`458`）。
- **Mihomo 没有 `network: httpupgrade`。** vmess 只认 ws/http/h2/grpc/mekya（`vmess.go:175`–`283`，默认分支 `:278`–`281`），
  vless 只认 ws/http/h2/grpc/xhttp（`vless.go:156`–`262`），trojan 只认 ws/grpc（`trojan.go:79`–`155`）。
  构造时不校验这个值，未知值**静默**退化为普通 TCP（加 TLS），最多由服务端拒绝握手。
  HTTPUpgrade 的正确写法是 `network: ws` 加上 `v2ray-http-upgrade: true`。
- 上游自带的转换器会写出 `network: httpupgrade`（`common/convert/v.go:67`–`77`），只在有 `ed` 时加 `fast-open`
  （`v.go:110`–`133`；vmess JSON 见 `converter.go:308`–`316`、`:356`–`388`），从不设置 `v2ray-http-upgrade: true`，
  所以它自己的 httpupgrade 输出会退化为 TCP。terc 把这种写法规范化为 `ws` + `v2ray-http-upgrade`（§3.2）是有依据的。

### 3.2 terc 的覆盖情况

| 输入 | 位置 | 处理 |
| --- | --- | --- |
| Clash YAML 订阅 | `src/subconv.rs:134` 原样透传；生成配置时 `normalize_httpupgrade_items`（`src/compose.rs:742`，`compose_profile_reserving` `:2077` 调用） | 其他字段保留；`network: httpupgrade` 原地改写为 `network: ws` + `ws-opts.v2ray-http-upgrade: true`，块和单行 flow 两种写法都处理，注释和其他键不变；`ws-opts: ~` / `null` 换成带这个键的映射；已有的 `v2ray-http-upgrade: false` 改为 `true`；flow 末尾有逗号时不会写出 `,,`；原始订阅缓存不改；结果里列出被改写的节点 |
| 粘贴的 JSON / Clash 节点、手动节点、节点列表 | `normalize_ws_network`（`src/subconv.rs:1445`） | 同上（`false` 同样改为 `true`），并把非标准的 `httpupgrade-opts {path, host}` 并入 `ws-opts` |
| vless / trojan 链接 `type=ws` | `src/subconv.rs:1349` `transport()` | `path`、`host`；`ed` → `max-early-data` + `Sec-WebSocket-Protocol`，`eh` 覆盖头名 |
| vless / trojan 链接 `type=httpupgrade` | 同上 | `network: ws` + `v2ray-http-upgrade`；带 `ed` 时加 `fast-open` |
| vmess JSON `net: ws` / `net: httpupgrade` | `src/subconv.rs:1789` `parse_vmess` | 与上游转换器一致，从路径中取出 `ed` 并写入字段；httpupgrade 同 vless 的处理 |
| Surge `ws=true` | `src/subconv.rs:858` | `ws-path`、`ws-headers`（`A:b\|C:d`）（Surge 没有早期数据，也没有 HTTPUpgrade） |
| 手动表单 | `src/proxy_form.rs` | “传输”在 TCP / WebSocket / HTTPUpgrade 之间切换，并显示路径、Host 头，以及早期数据（WebSocket）或 Fast open（HTTPUpgrade）。保存时只改表单管理的键，自定义头和未知 `ws-opts` 键保留；早期数据的大小没改时不补 `early-data-header-name`（没有头名就是拼在路径里的早期数据），改了或新填时才补 `Sec-WebSocket-Protocol`；Host 头的提示对 trojan 单独说明它不会当作 SNI；在 vmess、vless、trojan 之间切换时保留 `ws-opts`。已保存的 `network: httpupgrade` 节点按 HTTPUpgrade 打开，按 Mihomo 的 ws 写法保存。其他传输方式（grpc、h2 等）进入原始编辑器 |

公共逻辑在 `ws_transport()`（`src/subconv.rs:1380`）和 `split_path_ed()`（`:1421`）。
测试：`websocket_early_data_and_http_upgrade_links`（`src/subconv.rs:2374`）；
`httpupgrade_block_items_are_rewritten_in_place`、`httpupgrade_flow_items_are_rewritten_in_place`、
`compose_rewrites_httpupgrade_proxies_and_names_them`（`src/compose.rs:1838`、`:1944`、`:1990`）；
`ws_form_edits_only_the_keys_it_manages`、`http_upgrade_mode_saves_mihomo_keys`、
`legacy_httpupgrade_nodes_open_in_the_structured_form`、`edit_keeps_transports_the_form_cannot_show`、
`trojan_host_hint_asks_for_sni`（`src/proxy_form.rs:947`、`:1020`、`:1045`、`:854`、`:1203`）。
`ed` 不是数字时，与上游 `v.go:118`–`121` 一样直接报错。

### 3.3 已修复的问题

1. 链接里的 `type=httpupgrade` 之前会被跳过，现在能转换。
2. `ed` 和 `eh` 之前被忽略，现在会写入早期数据设置（与上游转换器一致）。
3. vmess JSON 的 `net: httpupgrade` 现在能转换。
4. 表单编辑 grpc 或 h2 节点时不再静默改成 TCP（这类节点进入原始编辑器）。
5. 其他工具写出的 `network: httpupgrade`（Clash YAML 订阅、粘贴的节点）在生成配置时改写为 Mihomo 能用的 ws 写法。
6. 表单可以填写 Host 头，切换 HTTPUpgrade，设置早期数据或 Fast open。
7. 审查后修正：表单原样保存时不再把路径式早期数据改成头部式；trojan 的 Host 提示不再说会用作 SNI；
   `ws-opts: null`、显式 `v2ray-http-upgrade: false` 和 flow 末尾逗号三种写法都能正确改写。

### 3.4 剩余缺口

1. 不加随机 `User-Agent`。上游转换器会为 ws 节点加一个（`v.go:113`、`converter.go:197`），
   有些 CDN 或 WAF 可能在意这一点（不确定）。需要时再加。
2. 不属于 ws 但相邻的缺口：vless / trojan 的 `type=h2|http|xhttp`、vmess 的 `net: http`
   仍然报“unsupported”（`src/subconv.rs:1372`、`:1866`）；trojan 链接的 `alpn` 没有解析。
3. 表单不能编辑自定义头（Host 以外）和早期数据的头名，这两项只会被保留。

## 4. C：terc 的控制器客户端改用 WebSocket

- 状态：**已接入**（批次 `ws-stream`）。`/connections` 默认走 WebSocket 推送，失败时自动回退到 HTTP 轮询；
  设置 → 排查工具 →“连接实时推送”可以关闭。
- 本节的 Mihomo 行号都对应 `MetaCubeX/mihomo` `Meta` 分支的 commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`
  （2026-09-30），只读源码，没有实测。

### 4.1 Mihomo 端的现状（88dcbf7）

- `/traffic`、`/memory`、`/logs` 同时支持 chunked HTTP 和 WebSocket（`hub/route/server.go` 中各自的处理函数）。
  前两个在两种模式下都是每秒推送一次，**改用 WebSocket 不会更快**，所以继续用 chunked。
- `/connections` 只有在请求头**恰好是小写的** `Upgrade: websocket` 时才走 WebSocket，比较区分大小写
  （`hub/route/connections.go:25`）；否则返回一次完整的 JSON。`src/ws.rs` 发送的正是这个写法。
- `interval`：用 `strconv.Atoi` 解析，默认 1000 毫秒（`connections.go:36`–`47`）。
  **必须是正整数**：非整数会在写出 101 之后才报错，客户端只会收到 101 然后一片沉默（`:31`、`:39`–`43`）；
  `<= 0` 会先发出第一份快照（`:60`），随后 `time.NewTicker` 因非正间隔而 panic（`:64`）。
  terc 固定请求 `/connections?interval=1000`。
- 认证（`server.go:336`–`365`）：`?token=` 只在 `Upgrade` 恰好是 `websocket` 时才被读取（`:340`），专为浏览器准备；
  `Authorization: Bearer` 对 WebSocket 同样有效（`:351`–`361`）。**terc 只用请求头，从不把 secret 写进 URL**，
  这样它不会出现在 URL 和日志里。
- 握手要求（`hub/route/common.go:33`–`129`）：GET、HTTP/1.1 及以上、非空 `Host`、`Connection` 含 `upgrade`
  （不区分大小写）、24 字符的 `Sec-WebSocket-Key`、`Sec-WebSocket-Version: 13`（否则 426）。不协商子协议和扩展。
  响应头经 Go 的 `http.Header` 规范化为 `Sec-Websocket-Accept`（`common.go:119`–`125`），客户端按不区分大小写比对。
- 消息：每个 tick 发送一份**完整快照**，不是增量；连接建立后立即发一份，之后每个 interval 一份（`connections.go:49`–`70`）。
  形如 `{downloadTotal, uploadTotal, connections, memory}`（`tunnel/statistic/manager.go:124`–`129`），以 `\n` 结尾。
  没有连接时 `connections` 是 JSON `null` 而不是 `[]`（`manager.go:85`）；端口字段是字符串（`constant/metadata.go:199`–`202`）。
  已关闭的连接只是从下一份快照里消失。
- 帧：每条消息一个不分片、不加掩码、FIN 置位的 text 帧，长度用 7/16/64 位（`common.go:132`–`169`），
  **服务端没有大小上限**（`:151`–`154`）。
- 服务端握手后**只写不读**（`connections.go:31` 丢弃了读端）：从不回复 ping，不回 close，也不发 close。
  循环只在写失败时结束（`:66`–`69`），即客户端断开 TCP 之后。写超时已被清除（`common.go:117`）。

### 4.2 terc 的实现

- `/traffic`、`/memory`、`/logs` 仍由 `stream_json_lines`（`src/mihomo.rs:405`）读 chunked 的按行 JSON。
- `spawn_stream_workers`（`src/mihomo.rs:335`）多启动一个线程 `stream_connections`（`:555`）：
  - 用 `ws::connect` 连 `ws://{控制器}/connections?interval=1000`，secret 非空时带 `Authorization: Bearer …`。
    连接超时 1.5 秒，读超时 2 秒。
  - 每个 text 帧用 serde_json 解析，交给 `connections_from_snapshot_json`（`:726`，轮询也用它），
    以 `BackendEvent::Connections` 发给界面。界面和轮询走同一个 `install_connections`，
    所以连接时长、单连接速率、长连接与关闭记录都不变，只是采样变成每秒一次、间隔更稳。
  - 会话在这些情况下结束，结束时直接丢掉 socket，**不发 close、不等 pong 或 close**：
    连续 3 次读超时（推送间隔 1 秒，6 秒没有消息）；连续 3 条无法解析的消息；收到 close；任何其他错误；
    开关被关闭；程序退出。ping 由 `ws.rs` 自动回复，binary / pong 忽略。
  - 重连间隔：会话收到过快照后断开 → 1 秒；连接或握手失败 → 2、4、8、16、30 秒（封顶）；
    帧或消息超过 `ws.rs` 的上限（`WsError::TooLarge`）→ 暂停 5 分钟，期间由 HTTP 轮询负责。
    所有等待都以 100 毫秒为步长检查退出标志和开关，关掉再打开开关等于立即重试。
  - 日志只在状态变化时写一行：变为不可用时一条 `warning`
    “terc: /connections WebSocket 不可用，改用 HTTP 轮询 / unavailable, polling over HTTP: 原因”，
    从不可用恢复时一条 `info`“… 已连接 / connected”。重复的相同失败不再刷屏。
    TCP 连接被拒绝（内核没在运行）不算 WebSocket 故障，不写日志，只按退避重试。
    收到过快照之后遇到 EOF、连接重置或 close 帧，是内核停止或重启时的样子，也不写日志（`SessionEnd::Ended`）：
    内核没起来时下一次连接会被拒绝，同样不写；之后的其他失败照常写。推送卡住（6 秒没有快照）或内容无法解析仍然写。
- 界面（`src/main.rs`）：
  - `stream_live()`（`:1031`）= 开关打开且最近一次推送在 3 秒以内。
  - `tick` 在推送正常时调用 `fetch_snapshot_with(cfg, false)`，跳过 `/connections` 的 GET；
    这样得到的快照 `connections_ok == false`，`accept_snapshot` 会保留当前列表。
    推送超过 3 秒没来，下一次 2.2 秒的轮询就自动带上 `/connections`。
  - `accept_snapshot` 在推送正常时把任何轮询快照都当作 `connections_ok == false`：
    在推送到达之前就已发出的轮询，不能覆盖更新的推送数据，也不能制造假的“连接已关闭”。
  - 推送事件即使在其他操作进行中（`action_busy`）也会被接受。
- 设置：`connections_stream`，默认开启；`#[serde(default = "default_true")]` 保证旧的 config.json 照常加载，
  不会因缺字段回落到默认配置并覆盖用户文件。设置行显示 `OFF`、`ON · WebSocket`（推送正常）或
  `ON · HTTP`（已开启但正在回退）。
- 已知限制：和 `/traffic` 等线程一样，控制器地址和 secret 在启动时确定，修改后需要重启 terc。
- 测试（`src/mihomo.rs` 的 `mod stream_tests`，只连 `127.0.0.1:0` 上的模拟控制器，时间按毫秒缩放）：
  两份快照（含 `connections: null` 和字符串端口）、404 握手只警告一次并按退避重试、
  超大帧触发长暂停、静默 3 次读超时后重连并记录恢复、退出标志和开关能及时结束线程、
  退避序列、内核停止再重启不写日志，以及 `connections_from_snapshot_json` 与原轮询解析结果一致。
  `src/main.rs` 的 `polls_skip_the_connections_get_only_while_pushes_arrive` 用一个记录请求路径的模拟控制器驱动 `tick()`，
  确认推送正常时轮询不请求 `/connections`，推送中断后会请求。

### 4.3 收益与成本

- 收益：省掉每 2.2 秒一次的建连和完整 GET，只保留一条本地长连接；采样间隔稳定在 1 秒，
  单连接速率（§2.7）更准，AI 长连接的断开也更早出现在连接视图和日志里。
- 成本：多一条代码路径和一个线程。回退是自动且即时的，所以默认开启。
- 风险控制：超大快照不报错而是暂停推送；任何错误都丢弃整条连接再重连，不复用可能已错位的流。

### 4.4 `src/ws.rs`

- 只依赖 std，基于 `std::net::TcpStream`。SHA-1 在文件内实现；base64 复用已有的
  `crate::subconv::encode_base64`，没有再写一份。
- 握手：随机 16 字节 nonce，用 `RandomState` 的 SipHash 生成；校验 101 状态码、
  `Upgrade`、`Connection` 和 `Sec-WebSocket-Accept`，头名不区分大小写；
  拒绝没有请求过的扩展或子协议；拒绝请求行和头里的 CR/LF（防注入）；
  101 响应后面紧跟的帧会保留在缓冲区里。
- 帧：客户端帧全部加掩码；支持 7 位、16 位、64 位三种长度；支持 text、binary、ping、pong、close；
  收发都支持分片，分片之间允许插入控制帧。
- 防护：只读到帧头就检查单帧上限（默认 16 MiB），超限时不会先缓冲数据；
  消息总长另有上限（默认 32 MiB）。RSV 位、带掩码的服务端帧、未知 opcode、
  分片或超过 125 字节的控制帧、非法 close 码、非 UTF-8 文本都会按 RFC 6455 §7.4.1
  以 1002、1007 或 1009 关闭连接。
- 读超时（`WouldBlock` / `TimedOut`）不丢数据，下次调用接着从缓冲区读。
- 测试：RFC 示例 key `dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`、
  SHA-1 和 base64 的标准向量、RFC §5.7 的掩码示例，以及一个本地 `TcpListener` 模拟控制器。
  模拟控制器像 Mihomo 一样，101 响应与首帧一起写出，并且不回复 close。
- 模块级的 `#![allow(dead_code)]` 已删除。应用从不向 Mihomo 发消息，所以 `send`、`send_fragmented`、
  `is_closed` 只在测试里用，各自标了 `#[cfg_attr(not(test), allow(dead_code))]`；没有用处的 `get_mut` 已删除。

## 5. 推荐范围

- **已完成：** `src/ws.rs`；§3.3 的转换修复和规范化；表单的 Host / HTTPUpgrade / 早期数据；
  §2.7 的连接视图；§2.8 的保护长连接；`/connections` 推送（阶段 3，见 §4）；§11 的审查修正；本文档和使用说明。
- **下一步：** 阶段 1 的实测，用来确认 §2.2 的结论，尤其是 provider 节点在重载时断开这一条。
  实测时可以顺便看断开记录：经 provider 节点的连接应标为“配置重载”，顶层节点和 DIRECT 的连接不应被标上。
- **可以再做：** 新增或保存代理（`save_source_record`，表单的 Ctrl+S 和导入）在内核运行时也会重载，目前不提示，
  因为表单在调用前就进入“提交中”状态，需要先改这一流程；相关断开仍会正确标为“配置重载”。
- **不做：** 默认修改 keep-alive；切换节点时自动关闭连接；任何系统代理相关的自动操作。

## 6. 分阶段计划

| 阶段 | 内容 | 验收 | 状态 |
| --- | --- | --- | --- |
| 0 | `ws.rs`、ws 和 httpupgrade 转换、表单保留传输方式、本文档 | `cargo test --all-targets --locked` 通过；clippy 不新增警告 | 完成 |
| 1（用户实测） | 按 §10 的清单验证重载、选节点、TUN 开关对已有 WebSocket 的影响 | 把结果写回本文 §2.2，去掉“待实测” | 待做 |
| 2 | 连接视图：时长列、单连接速率、长连接和 AI 标记、按时长排序、断开记录（§2.7） | 只用 std 解析 RFC 3339 并有单元测试；面板保持 `Panel` 风格和三套配色 | 完成 |
| 3 | `/connections?interval=1000` 改用 `ws.rs` 推送；失败时回退到现有轮询；设置里提供开关（§4） | 用模拟服务端测试回退和重连；不依赖 pong | 完成（`ai/ws-stream` 批次） |
| 4 | 表单增加 Host 和 HTTPUpgrade；规范化 `network: httpupgrade`（§3.2） | 有转换测试；用 `mihomo -t` 校验（已有的 ignored 测试） | 完成 |
| 2.8 | 跳过内容不变的重载；实时设置走 `PATCH`；会断线的操作先确认 | 用模拟控制器测试 PATCH 读回和回退；不运行真实 mihomo | 完成 |
| 审查修正 | §11 列出的问题 | 每项有测试（`apply_core_setting` 的回退除外，见 §11）；`cargo test`、`clippy`、`fmt --check` 通过 | 完成 |
| 5（可选） | 在高级设置里提供 keep-alive；AI 组的稳定性选项（fallback 或固定节点）做成可见的设置 | 默认值不变，由用户选择 | 未做 |

## 7. 风险

- **结论来自读源码。** §2.2 和 §2.3 都需要在用户机器上验证；Mihomo 的版本差异也可能改变行为。
  本文以 `88dcbf7` 为准，更早或更晚的版本可能不同。
- **跳过重载靠文本比较。** 只有生成结果与 `config.yaml` 逐字相同时才跳过。内核停止时写入的文件，
  在内核运行时第一次重新生成通常还会重载一次（运行时模式的写法不同），之后才会命中。
  这是偏保守的方向：宁可多重载一次，也不让运行中的配置与文件不一致。
- **PATCH 读回只能确认字段值。** 端口被占用时 Mihomo 可能只在日志里报错；旧版本内核不返回某个字段时按“已确认”处理。
- **原因通知走线程局部变量。** 只有 `run_action` 的线程设置了发送端；别的线程里调用 `reload_config` 不会通知，
  断开会显示为原因未知，而不是错误的原因。`PUT` 被拒绝时通知已经发出，6 秒宽限期内自然结束的 provider 连接可能被误标。
- **内核停止要连续两次轮询确认。** 真正的停止晚 2.2 秒才进入断开记录；这期间面板已显示内核未运行，连接列表仍是上一份。
- **确认提示基于上一次快照。** 计数可能落后一个轮询周期；macOS 开启 TUN 时无法提前知道内核是否以 root 运行，所以总是按“会重启”提示。
- **`ws.rs` 接入后的风险：** 写超时可能写出半个帧，导致流错位，遇到写错误时应该直接重连。
  大型 `/connections` 快照（上千条连接）可能有几 MB，超过上限时应该回退到 HTTP，而不是报错。
  Mihomo 不回 close，关闭时不要等待。
- **掩码随机性：** 掩码来自 `RandomState`，对本地控制器足够。RFC 要求掩码不可预测，
  目的是防止中间代理的缓存投毒；本地回环上不存在这种中间代理。
- **修改 AI 组的类型会改变路由行为**，必须由用户决定。
- **实测会碰到真实路由：** 必须遵守 AGENTS.md（§9）。

## 8. 由用户控制的部分

- AI 组的类型、成员和过滤规则（`rules.conf` 的 `[ai]`），以及其他分组选哪个节点。
- 是否开启 TUN，是否设置系统代理，是否给 CLI 配置 `HTTPS_PROXY` / `ALL_PROXY`。
- 手动关闭连接（连接视图），以及在确认提示后是否继续会断线的操作。
- keep-alive：terc 模板不写这些键（`src/compose.rs:659`）；重新生成配置时只沿用 TUN、嗅探、DNS、IPv6
  的开关和路由模式（`src/compose.rs:1418` `carry_runtime_state`）。手写的 `keep-alive-*` 在重新生成后能否保留，需要另外确认或实现。
- 阶段 1 的实测由用户在自己的机器上完成，不在 AI 代理会话里做。

## 9. AGENTS.md 合规

- 没有新增依赖，`Cargo.toml` 和 `Cargo.lock` 都没改。`thiserror` 本来就在依赖里。
  不用 `tokio`、`reqwest`、`openssl`，网络只用 `std::net::TcpStream`。
- 没有运行 `networksetup` 或 `gsettings`，没有修改系统代理，没有启动真实的 mihomo，没有做实时路由测试。
  测试里按键会走真实的操作线程，线程结束时会读一次快照；`detect_sysproxy` 在 `cfg(test)` 下直接返回“没有系统代理”，
  所以测试也不会去调用这两个工具。
  WebSocket 和 PATCH 测试只连接 `127.0.0.1:0` 上的本地模拟服务端；跳过重载的测试用一个假的 `mihomo -t` 脚本。
- 需要 mihomo 或修改 `HOME` 的测试仍然标着 `#[ignore]`。
- 新增的提示复用现有的通知框，面板组件、圆角边框和三套配色都没动；文字有 zh / en / ja 三种。

## 10. 阶段 1 实测清单（给用户）

请在没有 AI 代理会话运行的时候做。如果只测重载，可以先把 Mihomo 切到 `Direct` 模式：
DIRECT 出站同样会被 Mihomo 记录为一条连接，足以观察重载的影响。

1. 用任意 WebSocket 客户端经 terc 管理的 Mihomo 连接一个 `wss://` echo 服务，
   每隔几秒发一条消息。
2. 在 terc 的连接视图里找到这条连接，记下时长、provider 和字节数。
3. 在设置里执行“重载配置”，出现确认提示时再按一次（会触发 `PUT /configs?force=true`）。
   预期：经顶层 `proxies:` 节点或 DIRECT 的连接还在；经 provider 节点的连接断开，断开记录里标为“配置重载”（§2.2 第 2 条）。
4. 修改 `allow-lan` 或 mixed-port。预期：提示“设置已实时生效，未重载”，连接还在（§2.2 第 4、6 条）。
5. 在该连接所在的分组里换一个节点（需要 Rule 或 Global 模式）。
   预期：旧连接不受影响，新连接走新节点。
6. 如果连接经 TUN 转发，切换 TUN 开关。预期：连接断开，断开记录里标为“TUN 重建”（§2.2 第 5 条）。
7. 把每一步的结果和 Mihomo 版本号（`/version`）记录到本文 §2.2。

## 11. 集成后的审查修正

按集成后（`42ee19d`）的审查意见逐条核对，下面是确认后修正的问题，每条都有单独的提交和测试。

| 问题 | 修正 |
| --- | --- |
| 一次 `/version` 超时或失败就被当作内核停止：所有长连接记为“内核已停止”，下一次又当作新连接，真正断开时再记一次 | 连续两次轮询都没看到内核、且没有推送时才清空（§2.7 第 6 条） |
| 1 秒的 AI 请求也算会话：弹出“AI 长连接已断开”，写 warning，三条同时结束被说成网络切换 | AI 连接自己结束时要存活满 10 秒才记录；被 terc 断开的照记（§2.7 第 4 条） |
| 连接列表在 80 列看不到字节和速率，120 列看不到进程和规则，却留着空白 | 按优先级加列，余下宽度给目标地址（§2.7 第 3 条） |
| 重载和 TUN 的原因记在所有连接上，而且在没有重载时也记 | 原因带范围，由真正发出请求的代码在发请求前通知（§2.8 第 4 条） |
| trojan 的 Host 提示说会用作 SNI | trojan 单独提示要填 SNI（§3.1） |
| 表单原样保存会补上 `early-data-header-name`，把路径式早期数据改成头部式 | 只在大小新填或改动时补（§3.2） |
| 窄窗口的断开记录看不到原因，Enter 无效，底栏写着用不了的键；新记录插入后光标指向别的条目 | 窄窗口先显示原因，Enter 打开整条，底栏换成断开记录的按键，光标跟着原条目（§2.7 第 4 条） |
| 秒级重启（launchd / systemd）不会被识别为内核重启 | 总流量变小时记为“内核已停止或重启”（§2.7 第 6 条） |
| flow 末尾逗号写出 `,,`；`ws-opts: null` 不改写；显式 `false` 变成普通 WebSocket | 三种写法都正确改写（§3.2） |
| 主动停止或重启内核时日志里出现 WebSocket 不可用和已连接两行 | EOF / close 不写日志（§4.2） |
| 设置的退回重载被拒绝后，文件和内核不一致，之后内容相同的生成被跳过 | 任何退回失败都设置 `RELOAD_UNCERTAIN`（§2.8 第 2 条） |
| 日文确认提示在 42×12 被截掉最后一个字 | 缩短日文文案，渲染测试加上 42×12 和两位数计数 |
| 修改当前订阅地址会重载却不提示 | 先确认，输入框保持打开，再按 Enter 执行 |
| 缺少测试：`x` 是否断开高亮那一行；推送正常时轮询是否跳过 `/connections` | 已补测试（§4.2） |
| 本文的 terc 行号在合并后过期 | 已按当前代码更新 |

没有改的：

- `apply_core_setting` 新分支的端到端测试和 `unchanged_regeneration_skips_the_check_and_the_reload` 仍然是 `#[ignore]`：
  它们要改 `HOME` 或写真实的 `config.json`，在默认测试里跑会动到用户文件。退回逻辑的改动只有一行，没有加测试。
- 设置开关 `connections_stream` 的按键路径没有加测试：它会调用 `save_preferences` 写真实的配置文件。
- 新增或保存代理时的重载仍不提示（§5）。

