# terc 与 WebSocket：调研结论与分阶段计划

- 状态：草案，WebSocket 支持的前期准备（分支 `claude/websocket-groundwork`，基线 `7975ab3`）
- 日期：2026-10-20
- Mihomo 源码出处：`MetaCubeX/mihomo` 的 `Meta` 分支，原始文件来自
  `https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/<路径>`，于 2026-10-20 抓取。
  本会话无法调用 GitHub API，没有记录确切的 commit SHA；下文行号以抓取当天为准，上游改动后可能偏移。
- 文档出处：`MetaCubeX/Meta-Docs`（`docs/config/general.md`、`docs/config/proxies/transport.md`、`docs/api/index.md`），
  地址为 `https://raw.githubusercontent.com/MetaCubeX/Meta-Docs/main/docs/...`。
- 下文结论都来自读源码，还没有在真实环境里验证（原因见 §9）。需要实测的地方都标了“待实测”。

## 0. 结论速览

“WebSocket 支持”有三种不同的含义，优先级如下：

| 含义 | 是什么 | 对用户的价值 | 本分支做了什么 | 建议 |
| --- | --- | --- | --- | --- |
| A | AI 工具的流量（`wss://`）经 Mihomo 转发 | 最高：断线就等于对话中断 | 调研 + 本文档 | 先做“看得见”（连接时长、速率），再做“不打断” |
| B | 代理节点使用 WebSocket 传输（`network: ws`） | 中：订阅里的节点能不能用 | 修了转换缺口，补了测试 | 剩余缺口见 §3.4 |
| C | terc 自己用 WebSocket 读控制器流 | 低：现有的 chunked HTTP 已经能用 | 写好了 std-only 的 `src/ws.rs`，还没接入 | 只在 `/connections` 推送上有意义，放到后面 |

一句话：**对 Mihomo 来说，`wss://` 只是一条存活很久的 TLS/TCP 连接，它不解析 WebSocket 帧。**
所以 A 的核心问题是“长连接会不会被重载、切节点、TUN 重建打断”，以及“terc 能不能把长连接显示出来”，
而不是 WebSocket 协议本身。

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

terc 保存配置后会调用 `install_config`（`src/mihomo.rs:1414`），再由 `reload_config`
发送 `PUT /configs?force=true`（`src/mihomo.rs:1860`）。在 Mihomo 端：

1. `updateConfigs` 读取 `force`（`hub/route/configs.go:401`、`:412`），然后调用
   `executor.ApplyConfig(cfg, force)`（`configs.go:448`，`hub/executor/executor.go:84`）。
2. `ApplyConfig` **不会遍历、也不会关闭**连接表里的连接。只有显式的
   `DELETE /connections` 才会关闭连接（`hub/route/connections.go:73`、`:81`）。
3. 重载期间隧道先进入 `Suspend`（`executor.go:89`，`tunnel/tunnel.go:136`）。
   这段时间里**新进来的** TCP 连接会被直接关闭（`tunnel.go:503`）。
   如果 WebSocket 恰好在重载窗口里断线重连，这次重连会失败，需要应用自己重试。
4. `updateProxies` 只是替换代理表（`executor.go:100`，`tunnel.go:230`）。
   已建立的连接仍然持有旧的出站连接，按源码会继续传输。
5. 即使带了 `force`，监听器也只在地址变化时才重建（`listener/listener.go:158` 等处比较 `RawAddress()`）。
6. TUN 的处理：配置不变时只调用 `OnReload()`（`listener.go:515`–`519`）；
   配置变了就执行 `closeTunListener()`（`listener.go:522`、`:720`）。
   **TUN 一旦重建，经 TUN 转发的连接会中断。** terc 的 TUN 开关
   （`set_tun_enabled`，`src/mihomo.rs:1821`）走的是 `PATCH /configs`
   → `ReCreateTun`（`configs.go:377`），效果相同。这是预期行为。
7. 用 `PATCH /configs` 切换模式（`configs.go:383`）不会关闭连接。

结论：只要 TUN 配置不变，重载**应当**保留已建立的 WebSocket，代价是重载期间新连接会失败。**待实测**（§6 阶段 1）。

terc 自己的行为：在分组里选节点（`src/main.rs:1000` → `src/mihomo.rs:872`）不会关闭连接。
只有用户在连接视图里主动关闭时才会关（`src/main.rs:2090`、`:2097`）。

### 2.3 选节点与 url-test 自动切换

- `Selector.Set` 只修改 `selected`（`adapter/outboundgroup/selector.go:83`）。
- `URLTest.DialContext` 只在**拨号时**调用 `fast()` 选择最快节点
  （`adapter/outboundgroup/urltest.go:57`、`:103`，容差判断在 `:139`）。
- 所以 url-test 切换只影响新连接，已建立的 WebSocket 不会因切换而断开。
  但如果是**节点本身**故障导致切换，连接早已断了，重连会换到新节点，出口 IP 随之变化。
  部分服务可能因此要求重新认证或触发风控（可能，不确定）。
- terc 默认的 AI 组是 `url-test`、`interval: 300`、`tolerance: 50`
  （`src/compose.rs:283`、`:929`），AUTO 组也是 url-test（`src/compose.rs:975`）。
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
- terc 的模板不写这些键（`src/compose.rs:642` `template_base`），所以使用默认值 15 秒，已经足够积极。
  建议：默认不改，更不要禁用。

### 2.5 TUN 与 NAT 的空闲超时

- TUN 的 `udp-timeout`（`config/config.go:314`）只作用于 UDP（例如 QUIC），与 WebSocket 无关。
- 家用路由器和运营商 NAT 对空闲 TCP 的超时各不相同。Mihomo 到节点这一段有 15 秒的 keep-alive 兜底；
  节点到目标站点这一段在远端，terc 控制不了。应用层心跳由应用自己负责。
- 睡眠、切换网络、VPN 冲突会让所有连接断开，这在代理层面无法避免。

### 2.6 嗅探（sniffer）

terc 模板默认关闭嗅探（`src/compose.rs:661`）。开启后，TLS 嗅探只读取 SNI，
HTTP 嗅探读取 `Host`。两者都不会改动 WebSocket 的内容，风险很低。
唯一的副作用是 `override-destination: true` 可能让规则按嗅探到的域名重新匹配。

### 2.7 terc 的可观测性缺口

现状：

- `/connections` 每 2.2 秒完整 GET 一次（`src/main.rs:873`，`src/mihomo.rs:620`），按累计字节数排序（`src/mihomo.rs:684`）。
- 详情里只显示 `start` 时间戳（`src/panels.rs:815`）。
- 没有“已存活多久”列，没有单连接的实时速率，也看不到连接什么时候、因为什么消失。

Mihomo 提供的字段：`start`（`tunnel/statistic/tracker.go:29`）、`upload`、`download`、`chains`、
`providerChains`（`tracker.go:31`，terc 目前不解析）。

建议（阶段 2）：

1. 增加“时长”列：用当前时间减去 `start`，自己写一个只依赖 std 的 RFC 3339 解析。
2. 按连接 id 对相邻两次快照求差，得到单连接的上下行速率。
3. 存活 60 秒以上的连接标为“长连接”，并提供按时长排序。
4. 连接消失时在日志里记一行，内容包括 host、链路、存活时长、总字节数。
   用户遇到“AI 对话突然断了”时，可以据此判断断开是不是发生在 Mihomo 这一层。

## 3. B：使用 WebSocket 传输的节点

### 3.1 Mihomo 的字段

字段定义见 Meta-Docs `transport.md` 和 `adapter/outbound/vmess.go:165`–`172`（`WSOptions`）：

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
- 开启 TLS 但没写 servername 时，会用 `headers.Host` 作为 SNI（`adapter/outbound/vless.go` 的 ws 分支）。
- **Mihomo 没有 `network: httpupgrade`。** vless 的出站只认 `case "ws"`，其他值会落入默认分支，
  按普通 TCP 处理（`adapter/outbound/vless.go:157`、`:258`–`259`）。
  HTTPUpgrade 的正确写法是 `network: ws` 加上 `v2ray-http-upgrade: true`。
- 上游自带的转换器（`common/convert/v.go:77`、`:110`；`converter.go:316`、`:356`）
  会原样写出 `network: httpupgrade`。按上面的出站代码，这样的节点看起来会退化为 TCP（待实测）。
  terc 使用自己的转换器，不受影响，但其他工具生成的 Clash YAML 里可能带有这个值（§3.4）。

### 3.2 terc 的覆盖情况

| 输入 | 位置 | 本分支之前 | 现在 |
| --- | --- | --- | --- |
| Clash YAML 订阅 | `src/subconv.rs:137` 原样透传 | 所有字段保留 | 不变 |
| vless / trojan 链接 `type=ws` | `src/subconv.rs:1348` `transport()` | 只处理 `path`、`host`；忽略 `ed`/`eh` | 处理 `ed` → `max-early-data` + `Sec-WebSocket-Protocol`，`eh` 覆盖头名 |
| vless / trojan 链接 `type=httpupgrade` | 同上 | 报“transport unsupported”，节点被跳过 | `network: ws` + `v2ray-http-upgrade`；带 `ed` 时加 `fast-open` |
| vmess JSON `net: ws` | `src/subconv.rs:1752` `parse_vmess` | 只处理 `path`、`host`（`?ed=` 留在路径里，运行时也能识别） | 与上游转换器一致：从路径中取出 `ed` 并写入字段 |
| vmess JSON `net: httpupgrade` | 同上 | 报错跳过 | 同 vless 的处理 |
| Surge `ws=true` | `src/subconv.rs:857` | `ws-path`、`ws-headers`（`A:b\|C:d`） | 不变（Surge 没有早期数据，也没有 HTTPUpgrade） |
| 手动表单 | `src/proxy_form.rs` | TCP 或 WebSocket 加路径；编辑时保留原有 `ws-opts` 的其他字段。**但 grpc / h2 节点编辑后会被改成 TCP** | 表单无法表示的传输方式显示为“保持不变”，保存时不覆盖 |

公共逻辑在 `ws_transport()`（`src/subconv.rs:1379`）和 `split_path_ed()`（`:1420`）。
测试：`websocket_early_data_and_http_upgrade_links`（`src/subconv.rs:2337`）、
`editing_keeps_transports_the_form_cannot_show`（`src/proxy_form.rs:670`）。
`ed` 不是数字时，与上游 `v.go:118`–`121` 一样直接报错。

### 3.3 本分支修复的问题

1. 链接里的 `type=httpupgrade` 之前会被跳过，现在能转换。
2. `ed` 和 `eh` 之前被忽略，现在会写入早期数据设置（与上游转换器一致）。
3. vmess JSON 的 `net: httpupgrade` 现在能转换。
4. 表单编辑 grpc 或 h2 节点时不再静默改成 TCP。在“传输”上按一次切到 TCP，
   再按就在 TCP 和 WebSocket 之间切换。改换协议后，原来的传输设置不再沿用。

### 3.4 剩余缺口（本分支未修）

1. **表单不能填写 `Host` 头，没有 HTTPUpgrade 开关，也不能设置早期数据。**
   节点地址是 IP、走 CDN 的 ws 节点需要 `Host`，现在只能粘贴链接或直接编辑 YAML。
   改起来是 UI 工作量，放在阶段 4。
2. **Clash YAML 透传不做规范化。** 其他转换器写出的 `network: httpupgrade` 会原样进入配置，
   按 §3.1 的分析可能退化为 TCP。可以在阶段 4 把它改写成 `ws` + `v2ray-http-upgrade`；
   这会改动用户的 YAML，需要单独评估。
3. 不加随机 `User-Agent`。上游转换器会为 ws 节点加一个（`v.go:113`、`converter.go:197`），
   有些 CDN 或 WAF 可能在意这一点（不确定）。需要时再加。
4. 不属于 ws 但相邻的缺口：vless / trojan 的 `type=h2|http|xhttp`、vmess 的 `net: http`
   仍然报“unsupported”（`src/subconv.rs:1371`、`:1829`）；trojan 链接的 `alpn` 没有解析。

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

- `/traffic`、`/memory`、`/logs` 仍由 `stream_json_lines`（`src/mihomo.rs:399`）读 chunked 的按行 JSON。
- `spawn_stream_workers`（`src/mihomo.rs:329`）多启动一个线程 `stream_connections`（`:545`）：
  - 用 `ws::connect` 连 `ws://{控制器}/connections?interval=1000`，secret 非空时带 `Authorization: Bearer …`。
    连接超时 1.5 秒，读超时 2 秒。
  - 每个 text 帧用 serde_json 解析，交给 `connections_from_snapshot_json`（`:702`，轮询也用它），
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
- 界面（`src/main.rs`）：
  - `stream_live()`（`:1023`）= 开关打开且最近一次推送在 3 秒以内。
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
  退避序列，以及 `connections_from_snapshot_json` 与原轮询解析结果一致。

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

- **本分支（已完成）：** `src/ws.rs`、§3.3 的转换修复、本文档。不改变任何运行时行为，
  只是表单里多了一种“保持不变”的显示。
- **下一步：** 先做阶段 1 的实测，再做阶段 2 的连接视图。这是对“AI 对话断线”最直接的帮助。
- **之后：** 阶段 3，`/connections` 改用 WebSocket 推送，同时保留 HTTP 轮询作为回退。
- **不做：** 默认修改 keep-alive；切换节点时自动关闭连接；任何系统代理相关的自动操作。

## 6. 分阶段计划

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| 0（本分支） | `ws.rs`、ws 和 httpupgrade 转换、表单保留传输方式、本文档 | `cargo test --all-targets --locked` 通过；clippy 不新增警告 |
| 1（用户实测） | 按 §10 的清单验证重载、选节点、TUN 开关对已有 WebSocket 的影响 | 把结果写回本文 §2.2，去掉“待实测” |
| 2 | 连接视图：时长列、单连接速率、长连接标记和按时长排序、连接消失日志 | 只用 std 解析 RFC 3339 并有单元测试；面板保持 `Panel` 风格和三套配色 |
| 3 | `/connections?interval=1000` 改用 `ws.rs` 推送；失败时回退到现有轮询；设置里提供开关 | 用模拟服务端测试回退和重连；不依赖 pong |
| 4 | 表单增加 Host 和 HTTPUpgrade；评估是否规范化 Clash YAML 里的 `network: httpupgrade` | 有转换测试；用 `mihomo -t` 校验（已有的 ignored 测试） |
| 5（可选） | 在高级设置里提供 keep-alive；AI 组的稳定性选项（fallback 或固定节点）做成可见的设置 | 默认值不变，由用户选择 |

## 7. 风险

- **结论来自读源码。** §2.2 和 §2.3 都需要在用户机器上验证；Mihomo 的版本差异也可能改变行为。
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
- 手动关闭连接（连接视图）。
- keep-alive：terc 模板不写这些键（`src/compose.rs:642`）；重新生成配置时只沿用 TUN、嗅探、DNS、IPv6
  的开关（`src/compose.rs:1128`）。手写的 `keep-alive-*` 在重新生成后能否保留，需要另外确认或实现。
- 阶段 1 的实测由用户在自己的机器上完成，不在 AI 代理会话里做。

## 9. AGENTS.md 合规

- 没有新增依赖，`Cargo.toml` 和 `Cargo.lock` 都没改。`thiserror` 本来就在依赖里。
  不用 `tokio`、`reqwest`、`openssl`，网络只用 `std::net::TcpStream`。
- 没有运行 `networksetup` 或 `gsettings`，没有修改系统代理，没有启动真实的 mihomo，没有做实时路由测试。
  WebSocket 测试只连接 `127.0.0.1:0` 上的本地模拟服务端。
- 需要 mihomo 的测试仍然标着 `#[ignore]`，本分支没有运行它们。
- UI 只改了表单“传输”一栏的显示文字。面板组件、圆角边框和配色都没动。

## 10. 阶段 1 实测清单（给用户）

请在没有 AI 代理会话运行的时候做。如果只测重载，可以先把 Mihomo 切到 `Direct` 模式：
DIRECT 出站同样会被 Mihomo 记录为一条连接，足以观察重载的影响。

1. 用任意 WebSocket 客户端经 terc 管理的 Mihomo 连接一个 `wss://` echo 服务，
   每隔几秒发一条消息。
2. 在 terc 的连接视图里找到这条连接，记下 `start` 和字节数。
3. 修改一个**不涉及 TUN** 的设置并保存（会触发 `PUT /configs?force=true`）。
   预期：连接还在，消息继续往返。
4. 在该连接所在的分组里换一个节点（需要 Rule 或 Global 模式）。
   预期：旧连接不受影响，新连接走新节点。
5. 如果连接经 TUN 转发，切换 TUN 开关。预期：连接断开（§2.2 第 6 条）。
6. 把每一步的结果和 Mihomo 版本号（`/version`）记录到本文 §2.2。
