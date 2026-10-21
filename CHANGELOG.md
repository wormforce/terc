# Changelog

All notable changes to terc. 中文在前，English follows each section.

## v0.2.0 (unreleased)

> **待定 / Pending:** the two network pull requests, config injection and node selection, will be added here if they merge before the tag. 配置注入与节点选择这两个网络相关的 PR 若在打 tag 前合并，会补进本节。

### 中文

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

**变更**

- 新配置使用 `log-level: warning`（ae0f488）。
- 配置里没有 `geox-url` 时补上 jsDelivr 镜像（364fe92）。
- 内置 DNS 片段改为适合中国大陆网络并监听 127.0.0.1:1053，另加境外版本；开着旧片段的用户会看到一次提示（9e96fba）。
- Surge 转换：url-test 组默认 `tolerance: 50`；RULE-SET 缓存按链接区分（b1098af）。
- 内核下载读 `version.txt`，x86_64 用 `-v1` 版本，支持断点续传，并优先经内核自己的本地端口下载（a7eef7b）。
- 订阅下载允许 gzip，遇到临时错误会重试（7d39cd2）。
- 新生成的 `config.json` 带随机控制器密钥。此前密钥为空时，Mihomo 不做鉴权，而它默认的 CORS 允许任意网页访问 127.0.0.1:9090。已有配置保留原密钥。
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

**已知问题**

- 从 v0.1.0 升级时，旧的 `active_profile` 会被忽略，当前来源变为由 `subscription.cache` 生成的 `imported-001`。
- GNOME：Space 关闭系统代理时写入 `mode 'none'`，原来的 `'auto'`（PAC）设置不会恢复。

### English

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

**Changed**

- New configs use `log-level: warning` (ae0f488).
- A jsDelivr `geox-url` is added when the config has none (364fe92).
- The built-in DNS snippet is mainland-safe and listens on 127.0.0.1:1053; a global variant was added, and users who had the old one on see a one-time notice (9e96fba).
- Surge conversion: url-test groups default to `tolerance: 50`; RULE-SET caches are keyed by URL (b1098af).
- Core download reads `version.txt`, uses the `-v1` build on x86_64, resumes partial files and tries the core's own listener first (a7eef7b).
- Subscription download allows gzip and retries transient errors (7d39cd2).
- A new `config.json` gets a random controller secret. With an empty secret Mihomo installs no auth, and its default CORS lets any web page reach 127.0.0.1:9090. Existing configs keep their secret.
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

**Known issues**

- Upgrading from v0.1.0 ignores the old `active_profile`; the active source becomes `imported-001`, built from `subscription.cache`.
- GNOME: turning the system proxy off with Space writes `mode 'none'`, so an earlier `'auto'` (PAC) setting is not restored.

## v0.1.0

First release.
