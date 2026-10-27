# terc

English companion to [使用说明](使用说明.md). The interface defaults to Chinese.

`terc` is a terminal controller for Mihomo (Clash.Meta) on **macOS** and **Linux**. It opens on the dashboard. An existing config does not pass through a startup menu.

First launch opens Setup only when three things are all true: no subscription URL is saved, the core is not running, and `config.yaml` is missing. Paste the airport subscription URL and press Enter, or paste one of your own nodes (a Surge proxy line or an `ss://`-style link) if you have no airport. `Ctrl+D` downloads the matching official binary into `~/.config/terc/core/mihomo`:

| Host | Asset |
| --- | --- |
| macOS Apple silicon | `mihomo-darwin-arm64` |
| macOS Intel | `mihomo-darwin-amd64-v1` |
| Linux arm64 | `mihomo-linux-arm64` |
| Linux x86_64 | `mihomo-linux-amd64-v1` |

There is no Windows build. The system proxy is never turned on by Setup. What Setup is given is saved as a new source under `sources/`, so it shows up in Settings → Sources & Routing right away. Esc dismisses Setup for this run; afterwards add sources with `a` in Settings → Sources & Routing and download the core from Settings → Diagnostics → Download / update core. On x86_64 terc takes the `-v1` baseline build: the plain `amd64` asset needs AVX2 and does not start on older CPUs and some VMs.

The download reads the latest release's `version.txt` and then fetches that exact file, without api.github.com and its 60-requests-per-hour limit. An attempt is abandoned only after 60 s below 1 KB/s; the next one resumes the partial file, so a slow but moving link always finishes. A failure shows curl's reason. While the core is running without TUN, terc first downloads through the core's own local listener (the mixed or HTTP port on `127.0.0.1`) and falls back to a direct download; this applies to that curl only and never touches the system proxy. Stable releases ship no `checksums.txt`, so integrity rests on GitHub's TLS.

## Subscription URL and Providers

The airport subscription is the single URL you paste. It is fetched with gzip allowed and one attempt may take 60 s as before, so a panel or converter that spends half a minute building the file still finishes. A 5xx, 429 or timeout within the first 20 s is retried, at most twice; an attempt that ran the full 60 s is not repeated. In Settings → Sources & Routing, `u` downloads the active subscription, combines it with the source's attached nodes in `config.yaml`, preserving source routing, and hands it to the core to validate and load. Set the source URL in Settings first.

Settings → Diagnostics opens **订阅源 / Providers**. That page is `proxy-providers` and `rule-providers` inside the Mihomo config: extra URLs the core uses to refresh a node list or a rule list. It is not the airport URL. Refreshing a provider does not replace the subscription link in `~/.config/terc/config.json`.

On that page, Enter refreshes the selected provider, `F` refreshes all of them, and `H` health-checks a proxy provider. Rule providers have no latency check.

`F` refreshes four providers at a time. When updating the subscription leaves the config unchanged, so nothing reloads, terc refreshes the HTTP proxy providers through the controller instead (also four at a time, skipping `default` and file providers) and adds how many were updated and failed to the notice. That fetches new nodes without closing connections through the providers.

Providers and rules can be large, so background refreshes read them only where needed: on the Providers page every refresh reads the providers, elsewhere every 30 s (provider nodes' protocol and delay come from there too); rules are read only on the Rules tab. After the core starts, or after a refresh that could not reach it, the next one reads everything.

## Subscription formats

The format is detected automatically:

- **Clash / Mihomo YAML** (`proxies:` or `proxy-providers:`): nodes and settings such as DNS, TUN and ports are kept.
- **Surge** (`[Proxy]`, `[Proxy Group]`, `[Rule]`, or bare `Name = ss, …` lines): converted line by line.
- **URI lists**, plain or base64: `ss://` `trojan://` `vless://` `vmess://` `hysteria2://`/`hy2://` `tuic://` `anytls://` `socks5://`.

Surge proxies converted: `ss` (obfs, shadow-tls, 2022 ciphers), `trojan` (ws), `vmess` (ws, tls), `http`/`https`, `socks5`/`socks5-tls`, `snell` v1–v5 (`reuse`, `obfs`, `shadow-tls`), `hysteria2`, `tuic`/`tuic-v5`, `anytls`, `wireguard` (reads the `[WireGuard name]` section: `private-key`, `self-ip`/`self-ip-v6`, `dns-server`, `mtu`, one or more `peer`s with `preshared-key`, `keepalive`, `client-id`), `ssh` (password, or a `[Keystore]` private key; `server-fingerprint` becomes host-key pinning), keeping `udp-relay`, `tfo`, `sni`, `skip-cert-verify`, `underlying-proxy`. Groups: `select`, `url-test`, `fallback`, `load-balance` (`smart` becomes `url-test`) with `url`, `interval`, `tolerance`, `timeout`, `include-all-proxies`, `policy-regex-filter`, `include-other-group`; a `url-test` or `smart` group without `tolerance` gets `tolerance: 50`, because Mihomo's default of 0 switches nodes, and the exit IP of new connections, whenever another node was faster by any margin. Rules: domain, IP, GEOIP, process, port, `SRC-IP`, `PROTOCOL`, `AND`/`OR`/`NOT`, remote `RULE-SET`/`DOMAIN-SET` (as rule providers cached per URL; a repeated URL of the same kind shares one), `FINAL` → `MATCH`.

Snell v4/v5 needs Mihomo v1.19.26 or newer (`Ctrl+D` fetches the latest). Mihomo speaks v5 as the v4 wire protocol; Surge's QUIC Proxy Mode is not available.

Skipped, never fatal: `external`, snell v6, listen-only WireGuard sections (`listen-port` with peers lacking `endpoint`), `ssid`/`subnet` groups, `policy-path`, `USER-AGENT`, `URL-REGEX`, `RULE-SET,SYSTEM`/`LAN`, rules pointing at unknown policies, unsupported ciphers. The result toast says "N skipped"; press `!` for the list (names and types only, never secrets). Only a recognizable download replaces the source's cache, `~/.config/terc/sources/<id>/subscription.yaml`.

## Defaults and checks in generated configs

When terc generates `config.yaml` it fills in only what the subscription leaves out. A value the subscription sets, even Mihomo's default, is kept:

| Added | When | Why |
| --- | --- | --- |
| `tcp-concurrent: true` | The subscription does not set it | When a node or direct host resolves to several IPs, all are dialed at once and the first to connect wins; otherwise they are tried in turn, and a dead first IP uses up the 5 s dial deadline. The line carries a `# terc default` comment: an explicit value the subscription adds later wins, and a value changed in Settings is kept |
| `tun.gso: true` | Linux only; a block-style `tun:` without `gso`, including the `tun:` block the TUN switch writes; the built-in TUN snippet has it too | Batched TUN reads and writes, which cost less CPU per byte under bulk traffic. Not written on macOS, where it would only rebuild TUN for nothing |
| `tolerance: 50` | A `url-test` group without `tolerance` that uses no anchor or merge key; routing plans and routing from other sources get it too | As for Surge above |
| `client-fingerprint` | vmess, vless and trojan TLS nodes. Mihomo no longer reads the top-level `global-client-fingerprint`: a valid global value goes onto TLS nodes that set none, and a Reality node whose value is missing, `none` or invalid always gets one (the global value, else `chrome`). `none` on a plain TLS node is the provider's choice and stays | Reality cannot connect without a uTLS fingerprint |
| TUIC `congestion-controller: bbr` | Surge `tuic` and `tuic://` links that set none or an empty one; editing a node in the form keeps its value | Without it quic-go uses NewReno, which backs off hard on lossy long-haul paths |

Surge `port-hopping-interval` becomes Hysteria2 `hop-interval` (seconds or an `a-b` range; a range needs Mihomo v1.19.24 or newer, and older cores reject the whole config with `cannot parse 'hop-interval' as int`). An invalid value in a subscription is skipped and listed under skipped; a pasted node is refused so you can fix the line. Surge `[General]` `proxy-test-url` is used for test groups without `url=` (or with an empty one); `http://…/generate_204` without a port on `www.gstatic.com`, `connectivitycheck.gstatic.com`, `www.google.com` or `cp.cloudflare.com` becomes HTTPS, any other URL is kept as written. Quoted `ws-headers` values lose their quotes.

The first config generated after an upgrade reloads once because of these additions. On Linux with TUN on, the reload that adds `tun.gso` rebuilds TUN and closes every connection through it, so the reload prompt of a guarded reload (`u`, a source or routing switch, Reload, DNS and snippet toggles) also counts TUN connections and says "TUN is rebuilt". Own-node and rule edits regenerate without a prompt, so on Linux with TUN on, make `u` the first thing you do after upgrading.

After generating, terc checks the config the core will load (with the routing plan and snippets applied), counts the findings in the result notice, and lists them under `!`:

- Foreign DNS dialed direct: a foreign server in `fallback`, a `nameserver-policy` entry pointing at one, or a `nameserver` or `proxy-server-nameserver` list with only foreign servers. From mainland China these lookups are often blocked and wait for the timeout every time. With `respect-rules` on, only `proxy-server-nameserver` is checked, because node hostnames are always resolved direct.
- The first subscription rule that makes the core resolve locally (an IP rule without `no-resolve`, an ipcidr rule set and so on): from there on every connection no earlier rule matched pays a DNS lookup. Checked only with the subscription's own routing.
- Nodes without `udp`: ss, vmess, vless, trojan and others do not relay UDP by default, so UDP from TUN or SOCKS5 falls through to later rules or DIRECT. While the core runs its own report is used, which covers proxy-provider nodes too; smux nodes count as UDP-capable; traffic and expiry entries are left out.
- Removed rule-set references: when a routing plan drops the subscription's `rule-providers`, `rule-set:` references to them (any case, block style or a one-line `dns: {...}`) are removed from `dns.nameserver-policy`, `fake-ip-filter` and the sniffer's domain and address lists, because the core would refuse the config with `not found rule-set`.

## Proxy subscriptions and routing plans

Press `s` → Sources & Routing to see the named proxy list directly. Tab switches between proxies and routing plans. Rows show name, type, stable ID and active state; the selected row is highlighted.

Press `a` for the unified Add proxy form. Choose Subscription, Single proxy, or Import links/configuration. Enter a name and the relevant URL or server, port, credentials, cipher and TLS/SNI fields. Supported form protocols: SS, Trojan, VMess, VLESS, SOCKS5, HTTP, Hysteria2 and TUIC. Other supported protocols can be imported. Arrows/Tab select fields, left/right cycle options, Enter edits, Ctrl+S saves and uses the entry. Passwords are masked. `e` edits the selected entry, `n` renames, `u` updates the active subscription, and `v` manages attached nodes. Failed saves restore the old source record and configuration.

WebSocket and HTTPUpgrade nodes: for VMess, VLESS and Trojan, Transport cycles through TCP, WebSocket and HTTPUpgrade. Both show Path and an optional Host header; when the server is an IP or sits behind a CDN, put your domain in Host. VMess and VLESS also use Host as SNI when TLS is on and SNI is empty; Trojan does not, so fill in SNI as well behind a CDN. WebSocket adds optional Early data (bytes), HTTPUpgrade adds Fast open. Saving changes only these keys; other `ws-opts` such as custom headers or the early-data header name are kept, and a rename or port change leaves the early-data mode alone. `network: httpupgrade` written by other tools is rewritten to Mihomo's `network: ws` plus `v2ray-http-upgrade: true` when the config is generated, and the result names the nodes it changed; the raw subscription cache is not touched. Other transports (grpc, h2 and so on) open in the raw editor.

Routing lists subscription routing, Proxy all, routing cached by each source and named saved plans. Enter assigns a plan to the active proxy; `c` saves current routing for reuse. Nodes always come from the active source.

A plan keeps no node names: a group that listed nodes draws on every node of the active source instead. A regional group (a url-test / fallback / load-balance that listed only US nodes, say, or a select group whose own name names the country) gets a `filter` on flags, country names and standalone codes, so it does not rank every country's nodes. A group that also drew on proxy providers (`use`, `include-all-providers`) gets no filter, since nothing says which nodes the providers added. When the plan is applied to a source without proxy providers, the filter is checked there and dropped if no node matches, so the group takes every node. With providers the nodes are only known after the reload, so the filter stays together with `empty-fallback: REJECT`: if nothing matches, the group rejects connections instead of falling back to Mihomo's default `COMPATIBLE`, which dials directly, so AI traffic never leaves from your own address. This needs Mihomo v1.19.27 or newer: older cores ignore `empty-fallback` and still dial directly, and terc warns when the running core is older. A select group defaults to its first member, so a select group that lists such a region group first rejects its traffic until you pick another member; the result notice names these groups. When a filter is dropped because no node matches, the notice says so too. Group settings shared through `<<: *anchor` in the source config are expanded when the plan is saved, so such plans apply to other sources as well.

For example, source A can use its own routing and manual source B can use a shared plan. Switching restores each assignment. Updating B's nodes keeps its routing and never imports A's nodes. Original source caches remain separate. Validation failures keep the current configuration and routing assignment. Previous local snapshots remain selectable as policy only. Built-in custom routing presets remain paused; additive manual overrides are available under Settings → Sources & Routing → `r` Manual rules.

## Manual rule overrides

Settings → Sources & Routing → `r` Manual rules adds rules before the selected routing plan. For example, `anime1.me,DIRECT` becomes `DOMAIN-SUFFIX,anime1.me,DIRECT`, covering the domain and its subdomains. Source rules, rule providers and policy groups remain in place. Overrides are global, stored separately in `~/.config/terc/rules.conf` under `[rules]`, and survive subscription updates and plan switches. Only this list is used; old AI and China-direct preset options in that file stay inactive.

Press `a` to add, `d` to delete, `J` / `K` to reorder, or `t` to cycle DIRECT, REJECT and the current groups. A target name must exist in the selected plan; DIRECT and REJECT always work. Edits validate and reload automatically; a failed validation keeps the previous active configuration. After editing the file by hand, open this window and press Enter to apply. Rule mode must be selected for these rules to match; Global and Direct modes bypass rule matching. Existing connections keep their route until they reconnect.

## Common settings

Settings has four tabs: Core & Proxy, Appearance, Sources & Routing and Diagnostics (Tab / Shift+Tab or 1–4).

**Multiple core instances:** Settings → Core & Proxy → Core instances: `a` adds, `e` edits, `d` deletes (press twice to confirm). Enter a name, controller address, config directory and secret; leave the secret empty for an unauthenticated controller. `c` checks controller authentication and directory status and notes when the file declares a different controller (launch arguments may override it). This does not test proxy outbound or prove process ownership. Enter selects an instance and exits; run `terc` again to connect. Existing instances and their subscription choices remain available. On first connection to a new instance, terc creates a separate source record and copies the selected directory's configuration if available; it does not rewrite that file. The list is saved in the current user's `~/.config/terc/config.json`; terc does not scan or take over other users' cores. New users default to `127.0.0.1:9090`; saved addresses, directories and empty secrets are retained. The CLI uses the same configuration and has no controller override arguments.

Proxy settings include mixed / HTTP / SOCKS ports, LAN access, TUN, DNS, IPv6, sniffing, concurrent TCP, process matching, the test URL and controller timeout. Port values range from 0 to 65535; 0 disables a listener. A mixed port supports both HTTP and SOCKS and must not duplicate another listener. Turn off system proxy before changing ports, then enable it again after saving.

The test URL defaults to `https://www.gstatic.com/generate_204`, Mihomo's own default. The old saved default `http://www.gstatic.com/generate_204` moves to https on start; a URL you set yourself is kept. Over http some providers answer generate_204 at the entry relay, which reports a low delay that says nothing about the route. The timeout takes 500–32767 ms, the limit of Mihomo's delay route; a larger value saved earlier is sent as 32767. Mihomo records per test URL whether each node is alive, and url-test / fallback groups choose by that record; such a group without a `url` checks the default URL. So when the test URL is one a url-test / fallback group checks, terc tests with that group's timeout and `expected-status`, and never marks dead a node the group still uses.

Process matching has a cost: Mihomo looks up the process behind each new connection synchronously before dialling, with no cache. The default `strict` mode looks it up only when rule matching reaches a process rule such as `PROCESS-NAME`; the Process name snippet (`find-process-mode: always`) looks it up for every TCP connection and every new UDP session. On Linux one lookup measured about 1–15 ms: the core scans `/proc/*/fd` of the same user's processes, so it slows with open files and is slowest for a late-started program (about 1.6 µs per file, which extrapolates to 10–30 ms with many more). On macOS it reads the whole TCP connection table, estimated at 0.3–2 ms and not measured. Private rules come before the AI preset and subscription rules, so one `PROCESS-NAME` rule makes every connection that no earlier private rule matched pay this cost, AI traffic included. Prefer a domain rule where one fits, and enable the Process name snippet only to see process names in Connections.

Appearance includes theme, graph style, UI refresh rate, graph interval, language, top panels and the shortcut footer. The graph interval stays in Settings rather than cluttering the traffic graph.

The UI refresh rate is a redraw cap, not a fixed frame rate: keys and mouse clicks redraw at once (no faster than the cap), background data such as connections and rates at most every 100 ms, and an unchanged screen only once a second. A higher rate only makes input feel quicker; it costs no CPU while idle.

Diagnostics contains the log level, core download, snippets, probe, runtime details, rules, providers and Live connection stream. Startup errors include a core-log excerpt. The Logs view reads both `terc-core.log` and terc's `terc-events.log`; the preceding unprivileged startup log is kept as `terc-core.previous.log`. The event log records start and stop requests, TUN changes and core exits confirmed by two consecutive probes. It does not record subscription secrets or config contents. New configs set `log-level: warning`, so `terc-core.log` no longer gets a line per new connection; the Logs view always subscribes at info and shows the same lines as before. A subscription's own `log-level` is kept. An occupied controller or an unresponsive managed process blocks another launch. A startup timeout cleans up the newly launched process.

While the core runs, a new config is sent as `PUT /configs?force=true`, so the running core validates and loads it; a rejected config leaves the file unchanged. `mihomo -t` validates first only when the core is stopped or the config needs GeoIP / GeoSite data that is not on disk yet. A regenerated config that has not changed is not reloaded.

## Geodata

The core downloads the files behind GEOIP, GEOSITE and IP-ASN rules the first time it needs them, waits 90 s per file, and fails validation when a download fails. Mihomo's defaults are GitHub release URLs. When the generated config has no `geox-url`, terc adds the jsDelivr mirror (`testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/` for `geoip.dat`, `geosite.dat`, `country.mmdb` and `GeoLite2-ASN.mmdb`). A subscription's own `geox-url`, even one with a single key, is kept as written.

## Sniffer

Settings → Core & Proxy toggles the Mihomo sniffer. Many flows arrive with only an IP. The sniffer reads the HTTP Host, TLS SNI, or QUIC name from the start of the flow and fills the domain back in, so domain rules can match. The connections view shows that sniffed host. It does not store page contents, and it is not a packet capture.

## DNS snippets

Settings → Diagnostics → Config snippets has two built-in DNS overlays for configs without a usable `dns` block:

| Snippet | Resolvers | Notes |
| --- | --- | --- |
| Fake-IP DNS | `doh.pub` and `dns.alidns.com` DoH, bootstrapped by `223.5.5.5` / `119.29.29.29` | Same as terc's template; suited to mainland China |
| Fake-IP DNS (global) | `dns.google` and `cloudflare-dns.com` DoH, dialed through the rules (`respect-rules`) | Node hostnames still use mainland DoH. In Direct mode the DoH goes direct too, which fails from mainland China, so direct domains stop resolving; turn it off there before switching to Direct |

Both listen on `127.0.0.1:1053` only, so the LAN cannot use them as a resolver, carry no `fallback`, and keep `*.lan`, `+.local` and `localhost` out of fake-ip. A list the snippet names (`nameserver`, `fallback`, `fake-ip-filter` and so on) replaces the source's list as a whole; keys it does not name stay as the source wrote them. TUN DNS hijacking does not need the listener.

The previous Fake-IP DNS snippet used foreign DoH with a fallback and listened on `0.0.0.0:1053`. If it was on, terc says so once at the first start after the upgrade; the new body applies from the next generated config. Enable Fake-IP DNS (global) to keep foreign DoH.

Every reload or core start leaves Mihomo with an empty DNS cache, so the first connection through each node would wait for its hostname lookup. After terc reloads or starts the core (including the macOS restart that enables TUN) it resolves, in the background, the server hostnames of each group's selected node (with relay and `dialer-proxy` hops; provider nodes are read from the provider's cached file) through the controller's `/dns/query`, at most 16 names. Groups the rules use come first and `GLOBAL` last (first in global mode); names pinned in `hosts` are not queried; unless the config sets `ipv6: false`, AAAA is warmed along with A, because Mihomo enables IPv6 by default and a dial waits for AAAA too. This is skipped when `dns.enable` is off, and when the config sets `proxy-server-nameserver` (in any list style), because node hostnames then use a separate cache the query cannot reach; both built-in snippets set it.

A subscription's one-line `dns: {...}` or `tun: {...}` now generates fine, and the switches edit that line in place; the DNS snippets still need a block-style `dns:`.

## Nodes

Groups are on the left and nodes on the right. Enter on a node switches to it.

- `r` tests the current group. url-test / fallback groups test with their own `url`, `expected-status` and `timeout` (5000 ms by default), and the node list shows the delay the group ranks on: a node whose status misses `expected-status` shows as timed out, even though the delay route returned a number.
- `a` chooses all countries or the connected node's country, then tests and switches to the fastest node. After all candidates, the five leaders (plus the current node) are tested twice more and compared by the median of three, so one timeout or one spike does not decide. The current node is kept when it is within 30 ms or 15% of the fastest, and the toast says so. Choosing a node by hand during the test cancels the pick instead of overriding you. Works on Selector, url-test and fallback groups.
- On url-test / fallback groups, Enter and `a` pin the node: Mihomo uses it for as long as it is alive for the group's test URL, fails over to another node when it dies, and returns when it recovers. On these groups `a` always ends with a pin, also when it keeps the current node; otherwise url-test's next check could move the exit. A pinned node is marked `◆`; `◇` marks a pin that is down while the group uses another node, and the Nodes title reads "pin down, failed over".
- `x` unpins a url-test / fallback group. It is sent even when no pin is shown: a fallback forgets a dead pin only in memory, and the saved one returns at the next reload.

## Connections

Press `c`. Each row shows the connection's age, in bold once it has been open 60 s (long-lived). Connections to AI services are tagged `AI`: the destination or sniffed host matches the AI preset rules, or the chain passes through the `AI` group. When the pane is narrow, columns appear in this order: the current sort value (total bytes or total rate), process, rule, separate up/down, inbound. The host gets the rest.

- `o` cycles sorting by bytes, age and rate
- `f` shows only long-lived and AI connections; press again for all
- `x` closes the selected row, `X` closes all
- Enter opens full details (process, path, inbound, rule, chain, provider, age, rate), also in a narrow terminal
- `d` lists recently closed long-lived and AI connections (up to 50), with how long ago, lifetime, bytes and the inferred cause. Enter opens one entry; `d` returns to the live list

Mihomo reports no close reason, so terc infers it from its own actions: closed in terc, closed all, core stopped or restarted, config reload (only connections through proxy-provider nodes), TUN rebuilt (only connections that entered through TUN). A regeneration that leaves the config unchanged is not reloaded and is not blamed. Three or more unexplained closures in one refresh suggest a network change, sleep or node failure. An AI request that ends on its own within 10 s is not recorded. An unexplained AI closure shows one quiet toast, at most every 30 s.

Close all, TUN off, enabling TUN where macOS must restart the core, stopping the core, and reloads (switching a profile or routing plan, Reload, updating a subscription, editing the active subscription URL, saving a source from the Add/Edit form, DNS and snippet toggles) first show how many long-lived and AI connections would drop; press the same key again within 6 s to go ahead. A reload counts only proxy-provider connections, plus TUN connections on Linux when TUN is on and the reload adds `gso` to `tun`; it may be skipped when nothing changed, so its prompt says "may drop". Settings Mihomo applies live (LAN access, ports, concurrent TCP, process matching, log level) are sent with `PATCH /configs` without a reload, so existing connections stay.

The core pushes the connection list over WebSocket once a second. If the push is unavailable, terc falls back to polling every 2.2 s and logs one line, and another when it recovers; a core stop or restart logs nothing. Settings → Diagnostics → Live connection stream turns the push off and shows `OFF`, `ON · WebSocket` or `ON · HTTP` (on, but polling). A changed controller address or secret applies to the push after restarting terc.

## Other views

| Key | View |
| --- | --- |
| Settings → Core & Proxy | TUN, DNS, IPv6, sniffer, core service |
| Settings → Sources & Routing | Sources and manual nodes; separate Routing plans entry |
| Settings → Diagnostics | DNS lookup, effective rules, providers, snippets, probe, runtime, logs and core download |
| `s` / `?` | Settings and help. Esc returns to the dashboard |
| `q` | Quit the UI. The core keeps running. Settings → Core & Proxy → Core service starts or stops it |
| Esc | From a subview, return to proxies. From proxies, stay on the dashboard; q quits |

## Linux and macOS

System proxy on macOS uses `networksetup` on the active network service. Stopping the core turns off only proxy entries that still point at terc's port on `127.0.0.1`; another proxy, such as a corporate one, stays on. On Linux it uses GNOME `gsettings` (`org.gnome.system.proxy`) when that schema is present, and otherwise does nothing and says so. Linux never calls `networksetup`. Neither platform enables the proxy on its own.

Local control is `TcpStream` to `127.0.0.1:9090`. Remote downloads use the system `curl`.

## Storage

Under `~/.config/terc/`, `sources/<id>/source.json` stores the source name, kind, URL, structured nodes and routing assignment. `subscription.yaml` beside it holds the original subscription. `routing/` holds reusable plans; `generated/` holds derived core configurations. Startup imports legacy records while retaining their original files. It does not start a core or enable the system proxy.
