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

The airport subscription is the single URL you paste. `u` downloads it, composes it with your own nodes and private rules into `config.yaml` (below), validates, and hot-reloads the core. If no URL is saved, `u` opens Setup again.

`v` opens **订阅源 / Providers**. That page is `proxy-providers` and `rule-providers` inside the Mihomo config: extra URLs the core uses to refresh a node list or a rule list. It is not the airport URL. Refreshing a provider does not replace the subscription link in `~/.config/terc/config.json`.

On that page, Enter refreshes the selected provider, `F` refreshes all of them, and `H` health-checks a proxy provider. Rule providers have no latency check.

## Subscription formats

The format is detected automatically:

- **Clash / Mihomo YAML** (`proxies:` or `proxy-providers:`): nodes and settings such as DNS, TUN and ports are kept.
- **Surge** (`[Proxy]`, `[Proxy Group]`, `[Rule]`, or bare `Name = ss, …` lines): converted line by line.
- **URI lists**, plain or base64: `ss://` `trojan://` `vless://` `vmess://` `hysteria2://`/`hy2://` `tuic://` `anytls://` `socks5://`.

Surge proxies converted: `ss` (obfs, shadow-tls, 2022 ciphers), `trojan` (ws), `vmess` (ws, tls), `http`/`https`, `socks5`/`socks5-tls`, `snell` v1–v3, `hysteria2`, `tuic`/`tuic-v5`, `anytls`, keeping `udp-relay`, `tfo`, `sni`, `skip-cert-verify`, `underlying-proxy`. Groups: `select`, `url-test`, `fallback`, `load-balance` (`smart` becomes `url-test`) with `url`, `interval`, `tolerance`, `timeout`, `include-all-proxies`, `policy-regex-filter`, `include-other-group`. Rules: domain, IP, GEOIP, process, port, `SRC-IP`, `PROTOCOL`, `AND`/`OR`/`NOT`, remote `RULE-SET`/`DOMAIN-SET` (as rule providers), `FINAL` → `MATCH`.

Skipped, never fatal: `wireguard`, `ssh`, `external`, snell v4/v5, `ssid`/`subnet` groups, `policy-path`, `USER-AGENT`, `URL-REGEX`, `RULE-SET,SYSTEM`/`LAN`, rules pointing at unknown policies, unsupported ciphers. The result toast says "N skipped"; press `!` for the list (names and types only, never secrets). Only a recognizable download replaces `~/.config/terc/subscription.cache`.

## terc composes the config

`config.yaml` is generated from subscription nodes + your own nodes (`nodes.conf`) + terc rules. Airport groups and rules are not used unless you turn them on. Groups:

| Group | Type | Members |
| --- | --- | --- |
| `PROXY` | select | `AUTO`, `AI`, all nodes, `DIRECT`; the final `MATCH` |
| `AUTO` | url-test | all nodes |
| `AI` | url-test or fallback | US / JP / SG / TW nodes, Hong Kong excluded |

Info pseudo-nodes ("remaining traffic", "expires") are left out. If a name is taken, terc uses `terc-PROXY` etc.; `PROXY` in rules still points at it. Every regeneration runs `mihomo -t` first and keeps the old file on failure. TUN, sniffer, IPv6 and DNS switches and enabled snippets survive regeneration. Do not hand-edit the generated `config.yaml` (its first line is `# terc-generated`).

## Private rules and AI routing (R)

Press `R`. Changes are saved to `~/.config/terc/rules.conf`, then the config is regenerated and hot-reloaded.

| Key | Action |
| --- | --- |
| `a` | Add a rule below the selection |
| `d` / Delete | Delete |
| `J` / `K` or Shift+↓ / Shift+↑ | Move down / up (higher matches first) |
| `t` | Cycle target `PROXY` → `AI` → `AUTO` → `DIRECT` → `REJECT` |
| `p` | AI preset on / off |
| `y` | AI group `url-test` ↔ `fallback` |
| `m` | Pick AI members: Space toggles, `c` clears (= auto), Enter saves |
| `b` | Append airport groups and rules |
| `c` | China direct (`DOMAIN-SUFFIX,cn`, `GEOIP,CN`) |
| Enter | Re-read `rules.conf` and apply |
| Esc / `q` / `R` | Close |

Rule input is `TYPE,VALUE,TARGET`: `DOMAIN-SUFFIX,example.com,AI`, `DOMAIN-KEYWORD,steam,DIRECT`, `IP-CIDR,10.8.0.0/16,DIRECT` (gets `no-resolve`), `GEOIP,JP,AUTO`, `PROCESS-NAME,Cursor,AI`. `example.com` alone means `DOMAIN-SUFFIX,example.com,PROXY`. Targets can also be any node or group name; unknown names are skipped with a note.

Order: private rules → AI preset → LAN direct → airport rules (if `b`) → China direct → `MATCH,PROXY`.

The AI preset covers OpenAI / ChatGPT / Sora, Anthropic / Claude, Google Gemini / AI Studio / NotebookLM, xAI / Grok, Perplexity, Cursor, GitHub Copilot, Microsoft Copilot / Bing, Midjourney, Hugging Face, Poe, Meta AI, Mistral, Cohere, Groq, OpenRouter, Together, Replicate, Windsurf / Codeium, v0, Character.AI, Suno, ElevenLabs and Runway (`AI_PRESET` in `src/compose.rs`). By default the AI group picks nodes whose names look like US, Japan, Singapore or Taiwan and excludes Hong Kong; `members`, `filter` and `exclude` in `rules.conf` change that.

```ini
[ai]
enabled = true
type = url-test
members =                 # empty = auto; or names separated by |
filter = (?i)(🇺🇸|🇯🇵|…)
exclude = (?i)(🇭🇰|港|…)

[options]
subscription-rules = false
cn-direct = true

[rules]
DOMAIN-SUFFIX,example.com,AI
```

`[rules]` accepts any Mihomo rule. After editing by hand, press `R` then Enter. Saving from the TUI rewrites the file in canonical form.

## Own nodes / VPS (N)

Press `N`. `a` pastes a node (several lines at once are fine), `d` deletes, `r` / Enter tests the selected node, `A` tests all, Esc closes. Accepted: a Surge proxy line such as `My VPS = ss, 1.2.3.4, 8388, encrypt-method=2022-blake3-aes-128-gcm, password=…, udp-relay=true, tfo=true`, or an `ss://` `trojan://` `vless://` (Reality) `vmess://` `hysteria2://` `tuic://` `anytls://` `socks5://` `http(s)://` link. Bad ciphers, wrong SS2022 key lengths and bad ports are rejected on the spot.

Nodes live in `~/.config/terc/nodes.conf` (one per line, mode 600, local only); you can edit it by hand and press `R`, Enter or `u` to regenerate. The list shows name, protocol and server, never the password. Own nodes join `PROXY` and `AUTO`, and `AI` when their names look US/JP/SG/TW; a clash with a subscription name becomes `Name (2)`. They work without any subscription.

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
| `N` / `R` | Own nodes / private rules and AI routing |
| `s` / `?` | Settings and help. Esc returns to the dashboard |
| `q` | Quit the UI. The core keeps running. `K` starts or stops it |
| Esc | From a subview, return to proxies. From proxies, quit |

## Linux and macOS

System proxy on macOS uses `networksetup` on the active network service. On Linux it uses GNOME `gsettings` (`org.gnome.system.proxy`) when that schema is present, and otherwise does nothing and says so. Linux never calls `networksetup`. Neither platform enables the proxy on its own.

Local control is `TcpStream` to `127.0.0.1:9090`. Remote downloads use the system `curl`.
