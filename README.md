<h1 align="center">terc</h1>

<p align="center">
  <strong>简体中文</strong> &nbsp; / &nbsp; <a href="README.en.md">English</a>
</p>

<p align="center">
  <strong>国内开发者的终极 tui 代理软件</strong>
</p>

<p align="center">
  <code>terc</code> 采纳了现有各个 gui、非 gui 的 Clash 系软件，并对开发者、ai 工具进行了功能增强，致力做到远程友好、内存友好、界面友好、省事。
</p>

<p align="center">
  <img src="https://img.shields.io/badge/macOS-14%2B-20252B?style=flat-square" alt="macOS 14+">
  &nbsp;
  <img src="https://img.shields.io/badge/Linux-x86__64%20%7C%20arm64-20252B?style=flat-square" alt="Linux x86_64 / arm64">
  &nbsp;
  <img src="https://img.shields.io/badge/Rust-stable-20252B?style=flat-square" alt="Rust stable">
  &nbsp;
  <img src="https://img.shields.io/badge/TUI-Ratatui-FFA4A4?style=flat-square&amp;labelColor=20252B" alt="Ratatui TUI">
  &nbsp;
  <img src="https://img.shields.io/badge/Core-Mihomo-BADFDB?style=flat-square&amp;labelColor=20252B" alt="Mihomo core">
</p>

<p align="center">
  <a href="#快速开始"><strong>开始使用</strong></a> &nbsp; / &nbsp;
  <a href="docs/使用说明.md">使用说明</a> &nbsp; / &nbsp;
  <a href="#显示内容">功能一览</a> &nbsp; / &nbsp;
  <a href="#快捷键">快捷键</a>
</p>

<br>

<p align="center">
  <img src="assets/terc-hero.svg" alt="复古终端里的 terc：圆角标题切口、盲文上下行速率图、开关条和节点列表" width="100%">
</p>

<p align="center">
  <a href="https://ghostty.org"><img src="https://raw.githubusercontent.com/ghostty-org/ghostty/main/images/icons/icon_128.png" alt="Ghostty" width="28" height="28"></a><br>
  <sub>与 <a href="https://ghostty.org"><strong>Ghostty</strong></a> 搭配体验最佳</sub>
</p>

---

## 快速开始

**需要：** macOS 14 或更新版本，或 Linux（x86_64 / arm64）、Rust 稳定版，以及 `mihomo` 内核。macOS 可用 `brew install mihomo`；两边都可以在设置里下载与本机匹配的官方内核。日常用法见 [使用说明](docs/使用说明.md)。

```bash
git clone https://github.com/wormforce/terc.git
cd terc
cargo run --release --locked
```

还没有订阅链接、配置文件，且内核也没在跑时，会先弹出初始设置：粘贴机场订阅链接、定位 `mihomo` 二进制（Ctrl+D 按本机下载 `darwin-arm64`、`darwin-amd64`、`linux-arm64` 或 `linux-amd64`）、启动内核。已有配置则跳过这一步，直接进入面板。按 Esc 可以先关掉，未配置订阅时按 u 随时重新打开。

按 <kbd>Space</kbd> 开启或关闭系统代理（macOS 用 `networksetup`，Linux 在有 GNOME `gsettings` 时用 `org.gnome.system.proxy`，否则不动并提示），按 <kbd>K</kbd> 启动或停止 terc 管理的后台 `mihomo`。

macOS 按 <kbd>T</kbd> 开启 TUN 时，terc 会弹出系统管理员授权窗口，并以管理员权限重启自己管理的 Mihomo；现有连接会短暂中断，界面继续以普通用户运行。取消授权会保留原内核并恢复配置。以后按 <kbd>K</kbd> 停止这个内核时也可能需要授权；若配置已开启 TUN，启动内核时会直接请求授权。TUN 启动失败会显示内核错误，不再仅凭 API 返回成功就提示已开启。对于手动启动、使用同一配置目录的本机 Mihomo，terc 会核对控制器端口、程序路径和配置参数，授权后接管并重启。Homebrew/launchd 服务管理的内核，请先在原服务停止，再按 K 由 terc 启动。Linux 请自行通过系统服务或所需网络权限运行 Mihomo。

开启 TUN 前请先断开 Shadowrocket 等其他全流量 VPN，避免双方添加同一组路由而失败。terc 会检测已有虚拟网卡上的冲突路由并提示，不会自动删除其他 VPN 的路由。VPN 接管系统主接口时，系统代理仍按底层活动网卡对应的服务（例如 Wi-Fi）设置。

运行 `terc --version` 可查看已安装版本。

> [!NOTE]  
> `terc` 将界面与内核生命周期完全解耦。按 <kbd>q</kbd> 退出 `terc` 只会关闭终端界面并释放全部 UI 内存，后台 `mihomo` 代理服务依然稳固运行。

## 显示内容

| 视图 | 内容 |
| --- | --- |
| **策略组与节点** | 左右双栏，协议标签（如 `AnyTLS`）与按延迟着色的毫秒数 |
| **开关条** | 系统代理、分流模式与 TUN |
| **实时速率图** | btop 风格的上下行双速率历史图，自适应刻度并标注峰值（`max …/s`），支持 Braille 点阵与方块 |
| **内核概览** | 对齐展示内核运行状态、分流模式、系统代理、TUN、内存与连接数；下方显示端口与套餐余量 |
| **配置档案** | 把另一份 YAML 换成当前配置并热重载 |
| **主题** | Spring、Vintage、Mono，均保留终端透明背景 |

<details>
<summary>进阶功能与网络排查</summary>

| 视图 | 内容 |
| --- | --- |
| **活跃连接** | 进程、入站、嗅探域名、规则载荷、链路、Geo/ASN，可单条或全部断开 |
| **DNS** | 从配置读出的解析状态、即时查询，以及 DNS / Fake-IP 缓存清空 |
| **规则** | 顺序列表、实时命中次数、本机解释，以及运行时禁用 |
| **订阅源（v）** | `proxy-providers` 与 `rule-providers`，不是机场订阅链接。可单条或全部刷新，代理源可做健康检查 |
| **片段** | TUN、嗅探、Fake-IP、进程名、TCP 竞速、IPv6 的 YAML 叠加 |
| **探测** | 对当前节点同时做 DNS 查询和延迟测试 |
| **运行时** | TUN 设备，以及内核里已经存在的 WireGuard / Tailscale 出站 |
| **实时日志** | 按级别着色的内核日志流，支持暂停、搜索和全文阅读 |

</details>

底部只保留一行当前页面的快捷键提示。操作结果以浮动通知显示，普通通知 4 秒、错误通知 8 秒后自动收起；Backspace 可提前收起，按 `!` 仍可查看全文；按 `?` 打开帮助，支持上下键和翻页。连接页按 Enter 可在窄窗口打开完整详情。日志页用 `P` 暂停/继续、`/` 搜索、Enter 阅读全文。

鼠标点击策略组查看节点，点击节点直接切换；滚轮移动所在列表的选择，不会激活节点。当前焦点使用亮色粗边框、▶ 标记与选中行下划线。

## 快捷键

| 页面 | 按键 | 操作 |
| --- | --- | --- |
| 面板 / 设置 | Space | 开启或关闭系统代理。macOS 用 `networksetup`；Linux 用 GNOME `gsettings`，没有则不改动。不会自动打开 |
| 面板 | K | 启动或停止 terc 管理的后台 `mihomo` 内核 |
| 策略组 / 节点 | ← →、h l 或 Tab | 在左侧 **策略组** `[1]` 与右侧 **节点** `[2]` 之间切换焦点 |
| 任意列表 | ↑ ↓ 或 j k | 上下移动选择 |
| 节点列表 | Enter | 切换并激活当前高亮节点 |
| 面板 | r | 对当前策略组内所有节点发起并发延迟测速 |
| 面板 | a | 弹出优选范围：全球 / 当前连接国家；重新测速后选最低延迟节点 |
| 面板 | m | 循环切换分流模式（`Rule` → `Global` → `Direct`） |
| 面板 | u | 拉取最新机场订阅 YAML 并执行零停机热重载；未保存订阅链接时先打开初始设置窗口 |
| 设置窗口 | Enter | 保存订阅链接、写入配置并启动内核 |
| 设置窗口 | Ctrl+U / Ctrl+D | 清空输入行 / 下载托管 `mihomo` 内核 |
| 设置窗口 | Esc | 暂时关闭，未配置订阅时按 u 可重新打开 |
| 面板 | p / c / L | 切换主视图：**节点面板** / **连接监控** / **实时日志** |
| 面板 | t | 显示或隐藏顶部「实时速率」与「内核状态」面板 |
| 面板 | s | 打开双栏设置面板。设置里再按一次回到面板 |
| 设置 | ← →、h l 或 Enter | 调整并保存当前设置项，或执行动作 |
| 设置 | Tab / Shift+Tab / 1 2 3 | 切换设置分类页（`内核与代理` / `视觉与主题` / `订阅管理`） |
| 任意页面 | ? | 打开快捷键帮助，再按一次回到面板 |
| 面板 | q | 退出 `terc`（后台内核保持运行） |
| 面板 | Esc | 子页面回到节点页；退出请按 q |
| 设置 / 帮助 | Esc | 回到面板 |

<details>
<summary>进阶快捷键</summary>

| 页面 | 按键 | 操作 |
| --- | --- | --- |
| 面板 | T / n / i | 开关 TUN、嗅探或 IPv6。TUN 在 macOS 必要时请求管理员授权；运行时生效后保存配置 |
| 面板 | D | 切换配置里的 `dns.enable` 并热重载 |
| 面板 | d / g / v | DNS、规则、Provider |
| 面板 | o / f / b / w | 片段库、配置档案、探测、WireGuard / 运行时 |
| 规则 | / 或 e | 过滤列表，并解释域名、IP 或 `process:名称` |
| 规则 | x | 禁用或恢复当前规则（`PATCH /rules/disable`） |
| DNS | Enter / F / [ ] | 查询、清空 DNS 与 Fake-IP、切换记录类型 |
| Provider | Enter / F / H | 刷新当前项、刷新全部，或对代理源做健康检查 |
| 连接监控 | x / X | 断开当前选中连接 / 一键断开全部活跃连接 |

</details>

首次配置前先安装内核（设置窗口内可按 `Ctrl+D` 下载）。订阅、片段和档案会先运行 `mihomo -t` 验证，再替换配置；热重载被拒绝时恢复旧文件。更新订阅或切换档案会重新应用已启用片段。`K` 只停止 terc 启动的内核，外部服务请使用对应服务管理器。

优选只比较当前 Selector 策略组的可选代理节点。当前国家根据已连接节点名称的国旗、国家名称或独立代码识别，不代表出口 IP 定位；识别失败或无可达节点时保持原连接。

## 配置

按 s 打开**设置**。修改即时保存到 `~/.config/terc/config.json`。界面支持 **中文 / English / 日本語**。

| 分类 | 可调内容 |
| --- | --- |
| **内核与代理** | 启停 `mihomo`、切换系统代理、切换分流模式、按本机下载 `mihomo-darwin-arm64`、`darwin-amd64`、`linux-arm64` 或 `linux-amd64` 到 `~/.config/terc/core/mihomo` |
| **片段** | 内置 YAML 叠加，以及 `~/.config/terc/modules` 里的文件。开启时递归合并映射，关闭时还原原配置；应用前由内核验证 |
| **配置档案** | 配置目录和 `~/.config/terc/profiles` 中的 YAML。Enter 会把它写成 `config.yaml` 并热重载 |
| **视觉与主题** | 色彩主题（`Spring` / `Vintage` / `Mono`）、速率图样式（`Braille` / `Blocks`）、界面刷新率（`15` / `30` / `60` / `120 Hz`）、图表更新间隔（`1000–86400000 ms`，方向键每次调 `100 ms`，Enter 可直接输入；取期间平均速率，改变间隔会清空旧图）、界面语言 |
| **订阅管理** | 自动识别 Clash / Surge / 节点链接订阅（含 WireGuard、SSH、Snell v4/v5），与自有节点（`N`）和私有规则、AI 分流（`R`）合成配置，`mihomo -t` 校验后通过 `PUT /configs?force=true` 热重载 |

图表间隔按毫秒设置；Mihomo 流量流通常每秒提供一份数据，因此最小间隔为 1000 ms。

## 工作原理

`terc` 不用异步 HTTP 运行时，而是用标准库 `std::net::TcpStream` 连接本机 `127.0.0.1:9090`。后台线程读取 `/traffic`、`/memory` 和 `/logs`。开关走 `PATCH /configs`（`tun.enable`、`sniffing`、`ipv6`）。DNS 查询是 `GET /dns/query`，清空是 `POST /cache/dns/flush` 与 `POST /cache/fakeip/flush`，Provider 刷新是 `PUT /providers/...`。远端订阅和内核包通过系统 `curl` 下载。

```mermaid
flowchart LR
    A[Mihomo 内核 :9090] -->|分块 JSON 实时流| B[原生 TcpStream 线程]
    B -->|/traffic / /memory / /logs| C[上下行速率历史]
    D[系统代理 macOS networksetup / Linux gsettings] <-->|系统代理状态| E[控制器 API]
    C --> F[Ratatui 同步帧渲染]
    E --> F
```

<details>
<summary>项目结构</summary>

```text
assets/terc-hero.svg           复古终端画面：圆角面板、标题切口与盲文速率图
src/main.rs                    事件循环、界面状态与多语言
src/ui.rs                      圆角镂空 Panel、三套主题、Braille/Blocks 速率图
src/panels.rs                  开关条、DNS、规则、Provider 与浮层
src/control.rs                 开关、热重载、配置切换与探测
src/ops.rs                     YAML 叠加、规则解释、DNS/规则解析
src/mihomo.rs                  TcpStream 上的 HTTP/1.1、流式线程、networksetup 与 gsettings
```

</details>

## 开发

```bash
cargo test --all-targets --locked
cargo build --release --locked
```
