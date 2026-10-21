# Changelog

All notable changes to terc. 中文在前，English follows each section.

## v0.2.0

### 中文

**升级须知**

从 v0.1.0 升级后，下面这些会在第一次启动或第一次重新生成配置时自动发生：

- **第一次启动改写 `config.json`**：旧的默认测速地址 `http://www.gstatic.com/generate_204` 改为 `https://…`（自己设的地址不动）；测速超时上限为 32767 ms，更大的值会被压到这个上限，设置里的范围也改为 500–32767；控制器密钥为空（v0.1.0 的默认值）时换成随机密钥。用第三方面板（如 metacubexd）连 127.0.0.1:9090 时需要填这个密钥，它在 `~/.config/terc/config.json` 的 `controller.secret` 里。
- **配置迁移**：旧的 `profiles/`、`nodes.conf`、`subscription.cache` 迁移到 `~/.config/terc/sources/`，原文件保留。v0.1.0 最后切换到的已保存配置（`active_profile`）如果仍是正在运行的配置，就成为当前来源；全局订阅地址另存为 `imported-001`，不再覆盖它。
- **第一次重新生成配置会重载一次**，因为 terc 会补上订阅没写的默认值：`tcp-concurrent: true`（带 `# terc default` 标记）；没写 `tolerance` 的 url-test 组补 `tolerance: 50`，订阅自己的组和分流方案里的组都会补，所以自动选择的节点可能和以前不同；缺 `client-fingerprint` 的 TLS 节点补上（Reality 节点一定补）；Linux 上块格式的 `tun:` 补 `gso: true`。
- **Linux 开着 TUN 时**，补 `tun.gso` 的那次重载会重建 TUN，断开所有经 TUN 的连接。经过确认的重载（`u`、切换来源或分流方案、「重载配置」、DNS 和片段开关、在表单里保存来源）会先提示；自建节点、规则编辑以及 AI 规则键 `p`/`y`/`b`/`c` 触发的重新生成不提示。建议升级后先按 `u`，在没有重要连接时完成这次重建。
- **测速**：默认地址改为 HTTPS，延迟数字会比以前的 HTTP 测速高一些。url-test / fallback 组按组自己的 `url`、`expected-status` 和 `timeout:` 测速。
- **DNS 预热**：每次重载或启动内核后，terc 通过 `/dns/query` 解析各组当前节点的服务器域名（最多 16 个，共 10 秒）。`dns.enable` 关闭或写了 `proxy-server-nameserver` 时跳过。
- **节点选择**：在 url-test / fallback 组上按 Enter 会固定（pin）该节点，节点不可用时组会自动切换；`a` 优选在这类组上一定以固定结束；`x` 取消固定。
- **分流方案的地区组**：terc 写的地区 `filter` 旁边带 `empty-fallback: REJECT`，没有匹配节点时拒绝连接，不会直连。select 组默认选第一个成员，所以把这种地区组排在第一位的 select 组，在你手动换成别的成员之前会拒绝它的流量；结果提示会列出这些组。
- **内核版本**：新写入的键需要较新的 Mihomo。运行中的内核低于 v1.19.27 时 terc 会提示一次，运行详情里也会标出。设置 → 排查工具 → 下载 / 更新内核 下载的是最新版；Homebrew 用 `brew upgrade mihomo`。

| 功能 | 最低 Mihomo 版本 | 更旧的内核上 |
| --- | --- | --- |
| 地区组的 `empty-fallback: REJECT` | v1.19.27 | 这个键被忽略，没有匹配节点时组会直连（`COMPATIBLE`），而且 `mihomo -t` 检查不出来 |
| 节点级 `client-fingerprint`（替代顶层 `global-client-fingerprint`） | v1.19.27 起内核不再读顶层值 | 旧内核两者都读，不受影响 |
| Snell v4 / v5 | v1.19.26 | 配置被拒绝 |
| Hysteria2 `hop-interval` 的 `a-b` 范围（Surge `port-hopping-interval=10-30`） | v1.19.24 | 整个配置被拒绝：`cannot parse 'hop-interval' as int`，terc 会在错误后提示内核太旧 |

**不兼容变更**

- 代理来源改存到 `~/.config/terc/sources/<编号>/{source.json,subscription.yaml}`，旁边是 `routing/` 和 `generated/`。旧的 `profiles/`、`nodes.conf`、`subscription.cache` 会自动迁移，原文件保留在磁盘上（ef2ef5a、7975ab3、b0c65b5）。
- 面板上的 K、T、n、i、D、u、t 等快捷键已移除，功能移到设置。设置现在有四个分类：内核与代理、视觉与主题、订阅与分流、排查工具；DNS、规则、远程资源、片段、探测、运行详情都在「排查工具」里。
- 内核运行时由内核自己校验重载（`PUT /configs?force=true`，携带配置内容）；只有内核未运行或缺少 geodata 时才运行 `mihomo -t`（b82c9da）。
- 可热更新的设置走 `PATCH /configs`，不重载（507505d、b090d43）；重新生成后内容没变的配置不重载（9973938）。

**新增**

- 统一的订阅 / 代理新增与编辑表单（SS、Trojan、VMess、VLESS、SOCKS5、HTTP、Hysteria2、TUIC）；链接导入；可跨来源复用的分流方案；初始设置可直接粘贴节点。
- 编辑 WebSocket 与 HTTPUpgrade 传输，并把 `network: httpupgrade` 改写为 Mihomo 的 ws 写法（d850995、7f09c0e、287b35c、abc57aa、e6ab311、6d35356）。
- 连接页：时长、单连接速率、AI 标记、排序与筛选，以及带推断原因的最近断开列表（f618f41、ef6f2a6、3d76924、b7630f7、32080be）。
- `/connections` 走 WebSocket，失败时回退 HTTP 轮询，设置里可开关（907645e、541488d、bcab470）。
- 会断开长连接或 AI 会话的操作先确认（a118070、b1b4cb8）。
- 内核支持时片段开关实时生效（b66170d、da30045、d7cb6f2）。
- 来源列表按 `u`：订阅内容没变时改为刷新 HTTP 代理源（4f5982d）。
- **配置注入**：生成配置时补上订阅没写的安全默认值，订阅写了的值（哪怕是 Mihomo 的默认值）一律不改：`tcp-concurrent: true`、url-test `tolerance: 50`、TLS 节点的 `client-fingerprint`、Linux 上的 `tun.gso: true`；TUIC 转换时没写 `congestion-controller` 的默认用 `bbr`（d7c1e67、95fe509、7aaf3fe）。
- **配置检查**：生成后检查内核实际加载的配置（分流方案和片段都已应用），在结果提示里计数，按 `!` 看详情：直连的境外 DNS（`fallback`、`nameserver-policy`、全是境外服务器的 `nameserver` / `proxy-server-nameserver`）、第一条让内核本地解析的订阅规则、没开 `udp` 的节点（内核运行时以 `/proxies` 为准）。分流方案去掉订阅的 `rule-providers` 时，DNS 和 sniffer 里引用它们的 `rule-set:` 一并删除，避免 `not found rule-set`（3d2abfa、7aaf3fe）。
- **DNS 预热**：重载或启动内核后，通过 `/dns/query` 预先解析各组当前节点、中转和 `dialer-proxy` 的服务器域名，规则用到的组优先，同时预热 AAAA，`hosts` 里固定的域名不查（a45856b、7aaf3fe）。
- **Surge 转换**：`port-hopping-interval` 转成 Hysteria2 `hop-interval`（秒数或 `a-b` 范围），无效值在订阅里跳过并列出，手动粘贴的节点直接报错；`[General]` 的 `proxy-test-url` 用作没写 `url=` 的测速组地址，已知 generate_204 主机不带端口时升级为 HTTPS；`ws-headers` 去掉引号（98c504c、d3cb4e1、f3299fe、7aaf3fe）。
- **测速**：url-test / fallback 组按组自己的 `url`、`expected-status` 和 `timeout:`（也读 `<<: *锚点` 合并来的值）测速，节点列表显示该地址的延迟；与这类组同地址的 Selector 测速、`t` 和单节点测速也用同样的超时和状态码（4dda4f6、14f473a）。
- **优选（`a`）**：先测全部候选，再把领先的 5 个加上当前节点复测两轮，按三次的中位数比较；当前节点与最快的相差不超过 max(30 ms, 15%) 时保留；测速期间手动换了节点就取消，不覆盖用户的选择（540cfbd、14f473a）。
- **固定节点**：url-test / fallback 组上的固定节点标 `◆`，固定节点失效、组已改用别的节点时标 `◇` 并提示；Enter 固定，`x` 取消固定，`a` 在这类组上一定以固定结束（6fffce4、14f473a）。
- **分流方案的地区组**：保存方案时，只列了某国节点的组改成按国旗、国家名和独立代码筛选的 `filter`，带 `empty-fallback: REJECT`；用了订阅提供者的组不加筛选；`<<: *锚点` 在保存时展开（143a73b、14f473a）。
- 运行中的内核低于 v1.19.27 时提示一次，并在运行详情里标出。

**变更**

- 新配置使用 `log-level: warning`（ae0f488）。
- 配置里没有 `geox-url` 时补上 jsDelivr 镜像（364fe92）。
- 内置 DNS 片段改为适合中国大陆网络并监听 127.0.0.1:1053，另加境外版本；开着旧片段的用户会看到一次提示（9e96fba）。
- Surge 转换：url-test 组默认 `tolerance: 50`；RULE-SET 缓存按链接区分（b1098af）。现在所有生成的配置（包括 Clash 订阅和分流方案）里没写 `tolerance` 的 url-test 组都会补上。
- 默认测速地址改为 `https://www.gstatic.com/generate_204`，只迁移原来的 http 默认值；测速超时上限 32767 ms（Mihomo 按 int16 解析）（4dda4f6）。
- 内核下载读 `version.txt`，x86_64 用 `-v1` 版本，支持断点续传，并优先经内核自己的本地端口下载（a7eef7b）。
- 订阅下载允许 gzip，遇到临时错误会重试（7d39cd2）。
- `config.json` 一定带控制器密钥：新建的生成随机密钥，从 v0.1.0 升级时空密钥换成随机密钥，无法解析的 `config.json` 被移开后沿用其中能读出的密钥，读不出就生成新的。此前密钥为空时，Mihomo 不做鉴权，而它默认的 CORS 允许任意网页访问 127.0.0.1:9090。已设置的密钥保持不变。
- 在添加 / 编辑表单里保存来源（会切换来源并重载）也和其他重载一样，会断开长连接或 AI 连接时先确认。
- 停止内核时只关闭仍指向 127.0.0.1 上 terc 端口的系统代理，公司代理等其他设置保持不变。

**性能**

- 只在画面可能变化时重绘；只订阅点击和滚轮鼠标事件；同步更新标记改为排队输出（dec0bf4、c5d5451、6e02168）。
- `/connections` 解析为类型化结构；减少响应体拷贝；WebSocket 帧按 64 KiB 读取；规则和远程资源只在显示时轮询；轮询之间复用主机查询结果；操作后不再重复轮询（d75b9d5、3b9e8c7、fb1feea、8d12272、6aa0161、7ccfce6）。
- 远程资源每次刷新 4 个（0d8dfb3）。

**修复**

- 迁移不再因一行坏节点中止；代理表单保留 grpc / h2 传输（b0c65b5）。
- 第一次生成的配置再次生成时保持不变（93c4ce9）。
- 设置回退重载失败时标记内核可能未同步（a70d946）。
- 单元测试不再调用 networksetup 或 gsettings（f0bc799）；修改系统代理的函数在测试中直接拒绝执行。
- 性能合并后的评审修复（9480fb1）。
- 无法解析的 `config.json` 不再被默认值静默覆盖，而是改名为 `config.json.broken-<时间戳>`，并在通知里显示错误。
- 发生 panic 或启动早期出错时，终端会恢复（raw mode、备用屏幕、鼠标上报）。
- 无法解析的控制器地址会报错，不再悄悄回退到 127.0.0.1:9090；之前内核监听的端口和 terc 探测的端口可能不同。
- 首次安装时，初始设置把订阅或节点保存为 `sources/` 下的新来源，「订阅与分流」里马上能看到。
- 面板标题不再显示失效的快捷键；页脚和帮助按所选语言显示，并补全中 / 英 / 日；新增 MIT `LICENSE` 文件。
- 从 v0.1.0 升级时沿用 `active_profile`：最后切换到的已保存配置仍在运行时成为当前来源，第一次更新或编辑不再用全局订阅覆盖它。迁移来的配置显示原文件名和实际节点数（以前显示「代理 work  0 个节点」），来源类型按界面语言显示。
- 初始设置粘贴的节点行无效时（例如 `port-hopping-interval` 写错）显示具体原因，不再只说「需要 http(s) 订阅链接」；日语提示也说明可以粘贴节点。
- 没有 GNOME `gsettings` 时，Space 显示完整的说明，不再显示 `sysproxy_unavailable`。
- 后台线程 panic 时不再把消息打在界面上：消息显示在失败提示里，退出 terc 后打印到终端。
- 分流方案套用到别的来源时，地区组因没有匹配节点被去掉筛选，或靠订阅提供者、没有匹配时会拒绝连接，结果提示都会写明；套用了方案时提示写「已套用分流方案」，不再写「保留来源分流」。
- 优选的进度和组类型提示补上日语；来源页英文提示的 `e` 改为「编辑选中项」；内核下载损坏的提示指向设置里的下载入口；README 写明 x86_64 下载的是 `-v1` 版本。

**已知问题**

- GNOME：Space 关闭系统代理时写入 `mode 'none'`，原来的 `'auto'`（PAC）设置不会恢复。
- Linux 开着 TUN 时，升级后第一次由自建节点、规则编辑或 AI 规则键（`p`/`y`/`b`/`c`）触发的重新生成会补 `tun.gso`、重建 TUN，事先不确认（事后断开原因记为「TUN 重建」）。先按 `u` 可以在确认后完成这次重建。
- 配置生成和重载的结果提示（节点数、`udp`、配置提示等）只有中文和英文，日语界面显示英文。
- 内核刚启动时，DNS 预热可能早于内核恢复上次选中的节点，预热的是默认节点的域名；重载不受影响。
- 套用分流方案时，地区组的零匹配检查无法评估从来源组复制来的 `exclude-filter` / `exclude-type`（不加正则依赖做不到）：筛选可能被保留而组里实际没有节点，这时由 `empty-fallback: REJECT` 拒绝连接（需要 Mihomo v1.19.27 或更新）。
- 分流方案删除规则集引用时只处理单行的流式 `dns: {...}`，跨多行的不处理；DNS 片段无法叠加到一行写法的 `dns:`，会明确报错。

### English

**Upgrade notes**

After upgrading from v0.1.0, the following happens on the first start or the first regenerated config:

- **`config.json` is rewritten on the first start.** The old default test URL `http://www.gstatic.com/generate_204` becomes `https://…` (a URL you set is kept). Delay test timeouts are capped at 32767 ms, and the Settings range is now 500–32767. An empty controller secret, the v0.1.0 default, is replaced with a random one. A third-party dashboard such as metacubexd needs this secret to reach 127.0.0.1:9090; it is `controller.secret` in `~/.config/terc/config.json`.
- **Migration.** Old `profiles/`, `nodes.conf` and `subscription.cache` move to `~/.config/terc/sources/`, and the originals stay on disk. The saved profile v0.1.0 last switched to (`active_profile`) becomes the active source while it is still the running config; the global subscription URL is imported as `imported-001` and no longer replaces it.
- **The first regenerated config reloads once**, because terc fills in defaults the subscription left out: `tcp-concurrent: true` (marked `# terc default`); `tolerance: 50` on url-test groups without one, both the subscription's own groups and those of routing plans, so the automatically chosen node may change; `client-fingerprint` on TLS nodes that lack it (always on Reality nodes); and `gso: true` in a block-style `tun:` on Linux.
- **On Linux with TUN on**, the reload that adds `tun.gso` rebuilds TUN and closes every connection through it. Guarded reloads (`u`, a source or routing switch, Reload, DNS and snippet toggles, saving a source in the form) ask first; regeneration after own-node or rule edits and the AI rule keys `p`/`y`/`b`/`c` does not. Press `u` first after upgrading, at a moment when no important connection is open.
- **Delay tests** default to HTTPS, so the numbers are somewhat higher than the old HTTP tests. url-test and fallback groups are tested with their own `url`, `expected-status` and `timeout:`.
- **DNS pre-warm.** After every reload or core start, terc resolves the server hostnames of each group's current node through `/dns/query` (at most 16, 10 s in total). It is skipped when `dns.enable` is off or `proxy-server-nameserver` is set.
- **Node selection.** Enter on a url-test or fallback group pins the node, and the group still fails over when the node is down; `a` on such a group always ends with a pin; `x` clears the pin.
- **Region groups in routing plans.** The region `filter` terc writes comes with `empty-fallback: REJECT`, so a group with no matching node rejects connections instead of going DIRECT. A select group defaults to its first member, so a select group that lists such a region group first rejects its traffic until you pick another member; the result notice names these groups.
- **Core version.** Newly written keys need a recent Mihomo. terc warns once when the running core is older than v1.19.27 and marks it in Runtime. Settings → Diagnostics → Download / update core fetches the latest release; with Homebrew, run `brew upgrade mihomo`.

| Feature | Minimum Mihomo | On an older core |
| --- | --- | --- |
| `empty-fallback: REJECT` on region groups | v1.19.27 | The key is ignored and a group with no matching node dials DIRECT (`COMPATIBLE`); `mihomo -t` does not catch it |
| Per-node `client-fingerprint` (instead of the top-level `global-client-fingerprint`) | The core stops reading the top-level value in v1.19.27 | Older cores read both; no change |
| Snell v4 / v5 | v1.19.26 | The config is refused |
| Hysteria2 `hop-interval` `a-b` ranges (Surge `port-hopping-interval=10-30`) | v1.19.24 | The whole config is refused with `cannot parse 'hop-interval' as int`; terc adds a hint that the core is too old |

**Breaking**

- Proxy sources now live in `~/.config/terc/sources/<id>/{source.json,subscription.yaml}`, with `routing/` and `generated/` beside them. Old `profiles/`, `nodes.conf` and `subscription.cache` are migrated automatically and kept on disk (ef2ef5a, 7975ab3, b0c65b5).
- Dashboard keys K, T, n, i, D, u, t and others are gone. Their functions moved to Settings, which now has four tabs: Core & Proxy, Appearance, Sources & Routing, Diagnostics. DNS, Rules, Providers, Snippets, Probe and Runtime are under Diagnostics.
- The running core validates reloads (`PUT /configs?force=true` with the config payload); `mihomo -t` runs only when the core is stopped or geodata is missing (b82c9da).
- Live settings go through `PATCH /configs` with no reload (507505d, b090d43). A regenerated config that hasn't changed is not reloaded (9973938).

**Added**

- One form to add or edit subscriptions and proxies (SS, Trojan, VMess, VLESS, SOCKS5, HTTP, Hysteria2, TUIC); link import; routing plans you can reuse across sources; Setup accepts a pasted node.
- Editing WebSocket and HTTPUpgrade transports, and rewriting `network: httpupgrade` to Mihomo's ws form (d850995, 7f09c0e, 287b35c, abc57aa, e6ab311, 6d35356).
- Connections view: age, per-connection rates, AI tags, sort and filter, and a recently-closed list with the inferred cause (f618f41, ef6f2a6, 3d76924, b7630f7, 32080be).
- `/connections` over WebSocket with HTTP fallback, plus a Settings toggle (907645e, 541488d, bcab470).
- A confirmation before actions that cut long-lived or AI sessions (a118070, b1b4cb8).
- Snippet toggles applied live when the core can take them (b66170d, da30045, d7cb6f2).
- `u` in the sources list refreshes HTTP proxy providers when the subscription is unchanged (4f5982d).
- **Config injection:** generated configs get safe defaults the subscription left out, and a value the subscription sets (even Mihomo's default) is never changed: `tcp-concurrent: true`, url-test `tolerance: 50`, `client-fingerprint` on TLS nodes, and `tun.gso: true` on Linux. Converted TUIC nodes without `congestion-controller` default to `bbr` (d7c1e67, 95fe509, 7aaf3fe).
- **Config checks:** after generating, terc checks the config the core will load (routing plan and snippets applied), counts the findings in the result notice and lists them under `!`: foreign DNS dialed direct (`fallback`, `nameserver-policy`, or a `nameserver` / `proxy-server-nameserver` list with only foreign servers), the first subscription rule that makes the core resolve locally, and nodes without `udp` (from `/proxies` while the core runs). When a routing plan drops the subscription's `rule-providers`, `rule-set:` references to them in DNS and the sniffer are removed too, so the core no longer refuses the config with `not found rule-set` (3d2abfa, 7aaf3fe).
- **DNS pre-warm:** after a reload or core start, the server hostnames of each group's current node, relay hops and `dialer-proxy` are resolved through `/dns/query`; groups the rules use go first, AAAA is warmed too, and names pinned in `hosts` are skipped (a45856b, 7aaf3fe).
- **Surge conversion:** `port-hopping-interval` becomes Hysteria2 `hop-interval` (seconds or an `a-b` range); an invalid value is skipped and listed for subscriptions and refused for a pasted node. `[General]` `proxy-test-url` is used for test groups without `url=`, upgraded to HTTPS for known generate_204 hosts without a port. Quotes are removed from `ws-headers` values (98c504c, d3cb4e1, f3299fe, 7aaf3fe).
- **Delay tests:** url-test and fallback groups are tested with their own `url`, `expected-status` and `timeout:` (merged through `<<: *anchor` too), and the node list shows the delay for that URL. Selector rounds, `t` and single-node tests on the same URL use the same timeout and expected status (4dda4f6, 14f473a).
- **Best pick (`a`):** every candidate is tested, then the five leaders plus the current node get two more rounds and are ranked by the median of three. The current node stays when it is within max(30 ms, 15%) of the best. A manual switch during the test cancels the pick instead of being overridden (540cfbd, 14f473a).
- **Pins:** a pinned node in a url-test or fallback group is marked `◆`, and `◇` with a notice when the pin failed and the group moved on. Enter pins, `x` clears the pin, and `a` on such groups always ends with a pin (6fffce4, 14f473a).
- **Region groups in routing plans:** when a plan is saved, a group that listed only one country's nodes gets a `filter` on flags, country names and standalone codes, plus `empty-fallback: REJECT`. Groups that drew on proxy providers get no filter. `<<: *anchor` is expanded when the plan is saved (143a73b, 14f473a).
- terc warns once when the running core is older than v1.19.27 and marks it in Runtime.

**Changed**

- New configs use `log-level: warning` (ae0f488).
- A jsDelivr `geox-url` is added when the config has none (364fe92).
- The built-in DNS snippet is mainland-safe and listens on 127.0.0.1:1053; a global variant was added, and users who had the old one on see a one-time notice (9e96fba).
- Surge conversion: url-test groups default to `tolerance: 50`; RULE-SET caches are keyed by URL (b1098af). Every generated config, Clash subscriptions and routing plans included, now gives url-test groups without `tolerance` the same default.
- The default test URL is `https://www.gstatic.com/generate_204`; only the old http default is migrated. Delay test timeouts are capped at 32767 ms, which Mihomo parses as int16 (4dda4f6).
- Core download reads `version.txt`, uses the `-v1` build on x86_64, resumes partial files and tries the core's own listener first (a7eef7b).
- Subscription download allows gzip and retries transient errors (7d39cd2).
- `config.json` always carries a controller secret: a new one gets a random secret, an empty secret from v0.1.0 is replaced with a random one, and after a `config.json` that fails to parse is moved aside, the secret that can still be read from it is kept, or a new one is generated. With an empty secret Mihomo installs no auth, and its default CORS lets any web page reach 127.0.0.1:9090. A secret you set is kept.
- Saving a source in the Add/Edit form, which switches source and reloads, asks first like every other reload when long-lived or AI connections would drop.
- Stopping the core turns off only a system proxy that still points at terc's port on 127.0.0.1; a corporate or other proxy is left on.

**Performance**

- Redraw only when the screen can change; ask for click and wheel mouse reports only; queue the synchronized-update markers (dec0bf4, c5d5451, 6e02168).
- Parse `/connections` into typed structs; fewer body copies; read WebSocket frames in 64 KiB steps; poll rules and providers only where shown; reuse host lookups between polls; skip the duplicate poll after an action (d75b9d5, 3b9e8c7, fb1feea, 8d12272, 6aa0161, 7ccfce6).
- Refresh providers 4 at a time (0d8dfb3).

**Fixed**

- Migration no longer aborts on a bad node line; the proxy form keeps grpc/h2 transports (b0c65b5).
- The first generated config is a fixed point (93c4ce9).
- A failed settings fallback reload marks the core as possibly out of step (a70d946).
- Unit tests never run networksetup or gsettings (f0bc799), and the system proxy setters refuse to run under test.
- Review fixes from the perf merges (9480fb1).
- A `config.json` that fails to parse is renamed to `config.json.broken-<timestamp>` and the error is shown, instead of being overwritten with defaults.
- A panic or an early startup error restores the terminal (raw mode, alternate screen, mouse reporting).
- A controller address that does not resolve is reported as an error instead of silently falling back to 127.0.0.1:9090, where terc could reach a different core than the one it started.
- On a fresh install, Setup saves the subscription or node as a new source under `sources/`, so it shows up in Sources & Routing right away.
- Panel titles no longer show dead hotkeys; footers and help follow the selected language, with zh/en/ja throughout. Added the MIT `LICENSE` file.
- Upgrading from v0.1.0 keeps `active_profile`: the saved profile last switched to becomes the active source while it is still running, and the first update or edit no longer replaces it with the global subscription. Migrated profiles show their file name and real node count (they showed "代理 work  0 个节点"), and source kinds follow the UI language.
- Setup shows why a pasted node line was refused (a bad `port-hopping-interval`, say) instead of only asking for an http(s) link; the Japanese hint now mentions node lines.
- Without GNOME `gsettings`, Space shows the full explanation instead of `sysproxy_unavailable`.
- A worker-thread panic no longer prints over the TUI: the message goes into the failure notice and is printed on the terminal after terc exits.
- When a routing plan is applied to another source, the result notice says when a region group lost its filter because no node matched, or relies on proxy providers and rejects connections when none match. With a plan applied, the headline says "Routing plan applied" instead of "Source routing preserved".
- Japanese for the best-pick progress and group-type notices; the English Sources hint says `e` edits the selected source; the damaged-download error points at the Settings download entry; the README names the `-v1` builds downloaded on x86_64.

**Known issues**

- GNOME: turning the system proxy off with Space writes `mode 'none'`, so an earlier `'auto'` (PAC) setting is not restored.
- On Linux with TUN on, the first regeneration after the upgrade that comes from an own-node or rule edit or the AI rule keys (`p`/`y`/`b`/`c`) adds `tun.gso` and rebuilds TUN without asking (the drops are recorded as "TUN rebuilt" afterwards). Press `u` first to do that rebuild behind the prompt.
- Regeneration and reload result notices (node counts, `udp`, config notes) are Chinese and English only; the Japanese UI shows English.
- Right after the core starts, the DNS pre-warm can run before the core restores the last selected nodes, so it warms the default nodes' hostnames; reloads are not affected.
- When a routing plan is applied, the zero-match check of a region group cannot evaluate an `exclude-filter` or `exclude-type` copied from the source group (not without a regex crate): the filter may be kept while no node is left, and `empty-fallback: REJECT` then rejects connections (Mihomo v1.19.27 or newer).
- Removing rule-set references for a routing plan handles one-line `dns: {...}` maps only; a DNS snippet cannot be overlaid on a one-line `dns:` and says so.

## v0.1.0

First release.
