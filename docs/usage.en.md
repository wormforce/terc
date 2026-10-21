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

## Proxy subscriptions and routing plans

Press `s` → Sources & Routing to see the named proxy list directly. Tab switches between proxies and routing plans. Rows show name, type, stable ID and active state; the selected row is highlighted.

Press `a` for the unified Add proxy form. Choose Subscription, Single proxy, or Import links/configuration. Enter a name and the relevant URL or server, port, credentials, cipher and TLS/SNI fields. Supported form protocols: SS, Trojan, VMess, VLESS, SOCKS5, HTTP, Hysteria2 and TUIC. Other supported protocols can be imported. Arrows/Tab select fields, left/right cycle options, Enter edits, Ctrl+S saves and uses the entry. Passwords are masked. `e` edits the selected entry, `n` renames, `u` updates the active subscription, and `v` manages attached nodes. Failed saves restore the old source record and configuration.

WebSocket and HTTPUpgrade nodes: for VMess, VLESS and Trojan, Transport cycles through TCP, WebSocket and HTTPUpgrade. Both show Path and an optional Host header; when the server is an IP or sits behind a CDN, put your domain in Host. VMess and VLESS also use Host as SNI when TLS is on and SNI is empty; Trojan does not, so fill in SNI as well behind a CDN. WebSocket adds optional Early data (bytes), HTTPUpgrade adds Fast open. Saving changes only these keys; other `ws-opts` such as custom headers or the early-data header name are kept, and a rename or port change leaves the early-data mode alone. `network: httpupgrade` written by other tools is rewritten to Mihomo's `network: ws` plus `v2ray-http-upgrade: true` when the config is generated, and the result names the nodes it changed; the raw subscription cache is not touched. Other transports (grpc, h2 and so on) open in the raw editor.

Routing lists subscription routing, Proxy all, routing cached by each source and named saved plans. Enter assigns a plan to the active proxy; `c` saves current routing for reuse. Nodes always come from the active source.

For example, source A can use its own routing and manual source B can use a shared plan. Switching restores each assignment. Updating B's nodes keeps its routing and never imports A's nodes. Original source caches remain separate. Validation failures keep the current configuration and routing assignment. Previous local snapshots remain selectable as policy only. Custom rule editing is still paused.

## Common settings

Settings has four tabs: Core & Proxy, Appearance, Sources & Routing and Diagnostics (Tab / Shift+Tab or 1–4).

Proxy settings include mixed / HTTP / SOCKS ports, LAN access, TUN, DNS, IPv6, sniffing, concurrent TCP, process matching, the test URL and controller timeout. Port values range from 0 to 65535; 0 disables a listener. A mixed port supports both HTTP and SOCKS and must not duplicate another listener. Turn off system proxy before changing ports, then enable it again after saving.

Appearance includes theme, graph style, UI refresh rate, graph interval, language, top panels and the shortcut footer. The graph interval stays in Settings rather than cluttering the traffic graph.

The UI refresh rate is a redraw cap, not a fixed frame rate: keys and mouse clicks redraw at once (no faster than the cap), background data such as connections and rates at most every 100 ms, and an unchanged screen only once a second. A higher rate only makes input feel quicker; it costs no CPU while idle.

Diagnostics contains the log level, core download, snippets, probe, runtime details, rules, providers and Live connection stream. Startup errors include a core-log excerpt. The Logs view also reads `terc-core.log`; the preceding startup log is kept as `terc-core.previous.log`. New configs set `log-level: warning`, so `terc-core.log` no longer gets a line per new connection; the Logs view always subscribes at info and shows the same lines as before. A subscription's own `log-level` is kept. An occupied controller or an unresponsive managed process blocks another launch. A startup timeout cleans up the newly launched process.

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

## Connections

Press `c`. Each row shows the connection's age, in bold once it has been open 60 s (long-lived). Connections to AI services are tagged `AI`: the destination or sniffed host matches the AI preset rules, or the chain passes through the `AI` group. When the pane is narrow, columns appear in this order: the current sort value (total bytes or total rate), process, rule, separate up/down, inbound. The host gets the rest.

- `o` cycles sorting by bytes, age and rate
- `f` shows only long-lived and AI connections; press again for all
- `x` closes the selected row, `X` closes all
- Enter opens full details (process, path, inbound, rule, chain, provider, age, rate), also in a narrow terminal
- `d` lists recently closed long-lived and AI connections (up to 50), with how long ago, lifetime, bytes and the inferred cause. Enter opens one entry; `d` returns to the live list

Mihomo reports no close reason, so terc infers it from its own actions: closed in terc, closed all, core stopped or restarted, config reload (only connections through proxy-provider nodes), TUN rebuilt (only connections that entered through TUN). A regeneration that leaves the config unchanged is not reloaded and is not blamed. Three or more unexplained closures in one refresh suggest a network change, sleep or node failure. An AI request that ends on its own within 10 s is not recorded. An unexplained AI closure shows one quiet toast, at most every 30 s.

Close all, TUN off, enabling TUN where macOS must restart the core, stopping the core, and reloads (switching a profile or routing plan, Reload, updating a subscription, editing the active subscription URL, DNS and snippet toggles) first show how many long-lived and AI connections would drop; press the same key again within 6 s to go ahead. A reload counts only proxy-provider connections and may be skipped when nothing changed, so its prompt says "may drop". Settings Mihomo applies live (LAN access, ports, concurrent TCP, process matching, log level) are sent with `PATCH /configs` without a reload, so existing connections stay.

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
