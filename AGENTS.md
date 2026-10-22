# Agent Instructions for `terc`

`terc` is a restrained terminal Mihomo (Clash.Meta) controller and traffic visualizer for macOS and Linux, designed as the sibling application to `terb`.

## Build & Verification Commands

- Run unit tests: `cargo test --all-targets --locked`
- Lint: `cargo fmt --check` and `cargo clippy --all-targets --locked -- -D warnings`
- Build release binary: `cargo build --release --locked`
- CI (`.github/workflows/ci.yml`) runs these on every pull request and push to main that changes code (changes only to `*.md`, `docs/`, `assets/` or `LICENSE` are skipped), with tests on Linux and clippy cross-checks for the macOS targets; macOS tests run only on manual runs (workflow_dispatch) and on pull requests labelled `macos`. The Rust version it uses is pinned there.
- macOS global binary symlink: `/opt/homebrew/bin/terc` -> `/Users/grada/Documents/GitHub/terc/target/release/terc`

## Architectural & Design Rules

1. **Zero Heavy Networking Dependencies**:
   - Keep dependencies strictly aligned with `terb` (`ratatui`, `crossterm`, `serde`, `serde_json`, `thiserror`, `unicode-width`).
   - Do not add `tokio`, `reqwest`, or `openssl`. Local controller calls (`127.0.0.1:9090`) use `std::net::TcpStream` in `src/mihomo.rs`, and remote HTTPS downloads invoke the system `curl` on macOS and Linux.
2. **Visual Consistency with `terb`**:
   - All panels must use the custom `Panel` widget in `src/ui.rs` with rounded corners (`╭ ╮ ╰ ╯`), btop-style title cutouts (`┐ Title ┌`), and transparent backgrounds (`Color::Reset`).
   - Preserve the three canonical palettes: `Spring`, `Vintage`, and `Mono`.
3. **Network Safety During Automated Agent Sessions**:
   - Never automatically enable the system proxy during non-interactive tests or builds. On macOS that is `networksetup`; on Linux it is `gsettings` for `org.gnome.system.proxy`. Switching system proxy routes while an AI agent session is active can interrupt model streaming.
   - Do not call `networksetup` on Linux. If GNOME `gsettings` is missing, leave the proxy unchanged.
   - If testing live Mihomo routing behavior from an agent session, switch Mihomo to `Direct` mode first.
