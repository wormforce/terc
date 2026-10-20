# terc

English companion to [使用说明](使用说明.md). The interface defaults to Chinese.

`terc` is a terminal controller for Mihomo (Clash.Meta) on **macOS** and **Linux**. It opens on the dashboard. An existing config does not pass through a startup menu.

First launch opens Setup only when three things are all true: no subscription URL is saved, the core is not running, and `config.yaml` is missing. Paste the airport subscription URL and press Enter, or paste one of your own nodes (a Surge proxy line or an `ss://`-style link) if you have no airport. `Ctrl+D` downloads the matching official binary into `~/.config/terc/core/mihomo`:

| Host | Asset |
| --- | --- |
| macOS Apple silicon | `mihomo-darwin-arm64` |
| macOS Intel | `mihomo-darwin-amd64` |
| Linux arm64 | `mihomo-linux-arm64` |
| Linux x86_64 | `mihomo-linux-amd64` |

There is no Windows build. The system proxy is never turned on by Setup.

## Subscription URL and Providers

The airport subscription is the single URL you paste. Settings → Proxy subscriptions → Update subscription downloads it, combines it with the active profile’s manual nodes in `config.yaml`, preserving source routing, validates, and hot-reloads the core. Set the source URL in Settings first.

Settings → Tools opens **订阅源 / Providers**. That page is `proxy-providers` and `rule-providers` inside the Mihomo config: extra URLs the core uses to refresh a node list or a rule list. It is not the airport URL. Refreshing a provider does not replace the subscription link in `~/.config/terc/config.json`.

On that page, Enter refreshes the selected provider, `F` refreshes all of them, and `H` health-checks a proxy provider. Rule providers have no latency check.

## Subscription formats

The format is detected automatically:

- **Clash / Mihomo YAML** (`proxies:` or `proxy-providers:`): nodes and settings such as DNS, TUN and ports are kept.
- **Surge** (`[Proxy]`, `[Proxy Group]`, `[Rule]`, or bare `Name = ss, …` lines): converted line by line.
- **URI lists**, plain or base64: `ss://` `trojan://` `vless://` `vmess://` `hysteria2://`/`hy2://` `tuic://` `anytls://` `socks5://`.

Surge proxies converted: `ss` (obfs, shadow-tls, 2022 ciphers), `trojan` (ws), `vmess` (ws, tls), `http`/`https`, `socks5`/`socks5-tls`, `snell` v1–v5 (`reuse`, `obfs`, `shadow-tls`), `hysteria2`, `tuic`/`tuic-v5`, `anytls`, `wireguard` (reads the `[WireGuard name]` section: `private-key`, `self-ip`/`self-ip-v6`, `dns-server`, `mtu`, one or more `peer`s with `preshared-key`, `keepalive`, `client-id`), `ssh` (password, or a `[Keystore]` private key; `server-fingerprint` becomes host-key pinning), keeping `udp-relay`, `tfo`, `sni`, `skip-cert-verify`, `underlying-proxy`. Groups: `select`, `url-test`, `fallback`, `load-balance` (`smart` becomes `url-test`) with `url`, `interval`, `tolerance`, `timeout`, `include-all-proxies`, `policy-regex-filter`, `include-other-group`. Rules: domain, IP, GEOIP, process, port, `SRC-IP`, `PROTOCOL`, `AND`/`OR`/`NOT`, remote `RULE-SET`/`DOMAIN-SET` (as rule providers), `FINAL` → `MATCH`.

Snell v4/v5 needs Mihomo v1.19.26 or newer (`Ctrl+D` fetches the latest). Mihomo speaks v5 as the v4 wire protocol; Surge's QUIC Proxy Mode is not available.

Skipped, never fatal: `external`, snell v6, listen-only WireGuard sections (`listen-port` with peers lacking `endpoint`), `ssid`/`subnet` groups, `policy-path`, `USER-AGENT`, `URL-REGEX`, `RULE-SET,SYSTEM`/`LAN`, rules pointing at unknown policies, unsupported ciphers. The result toast says "N skipped"; press `!` for the list (names and types only, never secrets). Only a recognizable download replaces `~/.config/terc/subscription.cache`.

## Proxy subscriptions and routing plans

Press `s` → Sources & Routing to see the named proxy list directly. Tab switches between proxies and routing plans. Rows show name, type, stable ID and active state; the selected row is highlighted.

Press `a` for the unified Add proxy form. Choose Subscription, Single proxy, or Import links/configuration. Enter a name and the relevant URL or server, port, credentials, cipher and TLS/SNI fields. Supported form protocols: SS, Trojan, VMess, VLESS, SOCKS5, HTTP, Hysteria2 and TUIC. Other supported protocols can be imported. Arrows/Tab select fields, left/right cycle options, Enter edits, Ctrl+S saves and uses the entry. Passwords are masked. `e` edits the selected entry, `n` renames, `u` updates the active subscription, and `v` manages attached nodes. Failed saves restore the old source record and configuration.

Routing lists subscription routing, Proxy all, routing cached by each source and named saved plans. Enter assigns a plan to the active proxy; `c` saves current routing for reuse. Nodes always come from the active source.

For example, source A can use its own routing and manual source B can use a shared plan. Switching restores each assignment. Updating B's nodes keeps its routing and never imports A's nodes. Original source caches remain separate. Validation failures keep the current configuration and routing assignment. Previous local snapshots remain selectable as policy only. Custom rule editing is still paused.

## Common settings

Settings has four tabs: Proxy, Appearance, Sources & Routing and Diagnostics (Tab / Shift+Tab or 1–4).

Proxy settings include mixed / HTTP / SOCKS ports, LAN access, TUN, DNS, IPv6, sniffing, concurrent TCP, process matching, the test URL and controller timeout. Port values range from 0 to 65535; 0 disables a listener. A mixed port supports both HTTP and SOCKS and must not duplicate another listener. Turn off system proxy before changing ports, then enable it again after saving.

Appearance includes theme, graph style, UI refresh rate, graph interval, language, top panels and the shortcut footer. The graph interval stays in Settings rather than cluttering the traffic graph.

Diagnostics contains the log level, core download, snippets, probe, runtime details, rules and providers. Startup errors include a core-log excerpt. The Logs view also reads `terc-core.log`; the preceding startup log is kept as `terc-core.previous.log`. An occupied controller or an unresponsive managed process blocks another launch. A startup timeout cleans up the newly launched process.

## Sniffer

Settings → Proxy toggles the Mihomo sniffer. Many flows arrive with only an IP. The sniffer reads the HTTP Host, TLS SNI, or QUIC name from the start of the flow and fills the domain back in, so domain rules can match. The connections view shows that sniffed host. It does not store page contents, and it is not a packet capture.

## Other views

| Key | View |
| --- | --- |
| Settings → Proxy | TUN, DNS, IPv6, sniffer, core service |
| Settings → Proxy subscriptions | Sources and manual nodes; separate Routing plans entry |
| Settings → Tools | DNS lookup, effective rules, providers, snippets, probe and runtime |
| `s` / `?` | Settings and help. Esc returns to the dashboard |
| `q` | Quit the UI. The core keeps running. Settings → Proxy → Core service starts or stops it |
| Esc | From a subview, return to proxies. From proxies, stay on the dashboard; q quits |

## Linux and macOS

System proxy on macOS uses `networksetup` on the active network service. On Linux it uses GNOME `gsettings` (`org.gnome.system.proxy`) when that schema is present, and otherwise does nothing and says so. Linux never calls `networksetup`. Neither platform enables the proxy on its own.

Local control is `TcpStream` to `127.0.0.1:9090`. Remote downloads use the system `curl`.

## Storage

Under `~/.config/terc/`, `sources/<id>/source.json` stores the source name, kind, URL, structured nodes and routing assignment. `subscription.yaml` beside it holds the original subscription. `routing/` holds reusable plans; `generated/` holds derived core configurations. Startup imports legacy records while retaining their original files. It does not start a core or enable the system proxy.
