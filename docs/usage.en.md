# terc

English companion to [使用说明](使用说明.md). The interface defaults to Chinese.

`terc` is a terminal controller for Mihomo (Clash.Meta) on **macOS** and **Linux**. It opens on the dashboard. An existing config does not pass through a startup menu.

First launch opens Setup only when three things are all true: no subscription URL is saved, the core is not running, and `config.yaml` is missing. Paste the airport subscription URL and press Enter. `Ctrl+D` downloads the matching official binary into `~/.config/terc/core/mihomo`:

| Host | Asset |
| --- | --- |
| macOS Apple silicon | `mihomo-darwin-arm64` |
| macOS Intel | `mihomo-darwin-amd64` |
| Linux arm64 | `mihomo-linux-arm64` |
| Linux x86_64 | `mihomo-linux-amd64` |

There is no Windows build. The system proxy is never turned on by Setup.

## Subscription URL and Providers

The airport subscription is the single URL you paste. `u` downloads that YAML into `config.yaml` and hot-reloads the core. If no URL is saved, `u` opens Setup again.

`v` opens **订阅源 / Providers**. That page is `proxy-providers` and `rule-providers` inside the Mihomo config: extra URLs the core uses to refresh a node list or a rule list. It is not the airport URL. Refreshing a provider does not replace the subscription link in `~/.config/terc/config.json`.

On that page, Enter refreshes the selected provider, `F` refreshes all of them, and `H` health-checks a proxy provider. Rule providers have no latency check.

## Sniffer

`n` toggles the Mihomo sniffer. Many flows arrive with only an IP. The sniffer reads the HTTP Host, TLS SNI, or QUIC name from the start of the flow and fills the domain back in, so domain rules can match. The connections view shows that sniffed host. It does not store page contents, and it is not a packet capture.

## Other views

| Key | View |
| --- | --- |
| `T` / Space / `D` / `i` / `m` | TUN, system proxy, `dns.enable`, IPv6, routing mode |
| `d` | DNS lookup. `F` flushes DNS and Fake-IP. `[` `]` change the record type |
| `g` | Rules. `/` explains a target, `x` disables the selected rule |
| `o` | Snippets appended to the config (`~/.config/terc/modules`) |
| `f` | Profiles (`~/.config/terc/profiles`). Enter switches, `c` saves a copy |
| `b` | Probe: DNS plus a delay test of the selected node |
| `w` | Runtime: TUN device and WireGuard / Tailscale outbounds |
| `s` / `?` | Settings and help. Esc returns to the dashboard |
| `q` | Quit the UI. The core keeps running. `K` starts or stops it |
| Esc | From a subview, return to proxies. From proxies, quit |

## Linux and macOS

System proxy on macOS uses `networksetup` on the active network service. On Linux it uses GNOME `gsettings` (`org.gnome.system.proxy`) when that schema is present, and otherwise does nothing and says so. Linux never calls `networksetup`. Neither platform enables the proxy on its own.

Local control is `TcpStream` to `127.0.0.1:9090`. Remote downloads use the system `curl`.
