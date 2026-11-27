#!/usr/bin/env python3
"""Verify fresh, unauthenticated AI connections through a local Mihomo core."""

import argparse
import json
from pathlib import Path
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

DEFAULT_HOSTS = ("api.openai.com", "chatgpt.com", "api.anthropic.com",
                 "claude.ai", "gemini.google.com")


def controller(path):
    cfg = json.loads(path.read_text())["controller"]
    addr = cfg["addr"]
    url = urllib.parse.urlsplit(addr if "://" in addr else f"http://{addr}")
    if url.hostname not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("this check requires a loopback Mihomo controller")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get(endpoint):
        request = urllib.request.Request(
            f"{url.scheme}://{url.netloc}{endpoint}",
            headers={"Authorization": f"Bearer {cfg['secret']}"},
        )
        with opener.open(request, timeout=5) as response:
            return json.load(response)

    return get


def probe(get, port, host, expected, context):
    with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
        source_port = raw.getsockname()[1]
        target = f"{host}:443"
        raw.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
        with raw.makefile("rb", buffering=0) as header:
            status = header.readline(4096).split()
            if len(status) < 2 or status[1] != b"200":
                raise ValueError("HTTP CONNECT rejected")
            for line in iter(lambda: header.readline(4096), b""):
                if line == b"\r\n":
                    break
            else:
                raise ValueError("incomplete CONNECT response")
        # A verified TLS handshake exercises the actual outbound. Keep the
        # socket open so the controller can identify this exact new connection.
        with context.wrap_socket(raw, server_hostname=host):
            for attempt in range(4):
                if attempt:
                    time.sleep(0.15)
                for row in get("/connections").get("connections") or []:
                    meta = row["metadata"]
                    if meta.get("host") == host and str(meta.get("sourcePort")) == str(source_port):
                        chain = row.get("chains") or []
                        if not chain or chain[0] != expected:
                            raise ValueError(f"unexpected chain {chain!r}")
                        return f"{' → '.join(reversed(chain))} ({row.get('rule')} {row.get('rulePayload', '')})"
    raise ValueError("fresh connection not visible in controller")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-node", required=True)
    parser.add_argument("--group", default="AI")
    parser.add_argument("--config", type=Path, default=Path.home() / ".config/terc/config.json")
    parser.add_argument("hosts", nargs="*", default=DEFAULT_HOSTS)
    args = parser.parse_args()
    for host in args.hosts:
        if not host or not all(ch.isascii() and (ch.isalnum() or ch in ".-") for ch in host):
            parser.error("hosts must be DNS names")
    try:
        get = controller(args.config)
        runtime = get("/configs")
        port = runtime.get("mixed-port") or runtime.get("port")
        if runtime.get("mode") != "rule" or not port:
            raise ValueError("rule mode and an HTTP or mixed proxy port are required")
        group = get("/proxies")["proxies"].get(args.group, {})
        if group.get("type") != "Selector" or group.get("now") != args.expected_node:
            raise ValueError(f"{args.group} must select {args.expected_node} directly, got {group.get('now')!r}")
    except (OSError, ValueError, KeyError) as exc:
        print(f"FAIL configuration: {exc}", file=sys.stderr)
        return 1

    failed = False
    context = ssl.create_default_context()
    for host in args.hosts:
        try:
            print(f"PASS {host}: {probe(get, port, host, args.expected_node, context)}")
        except (OSError, ValueError, KeyError) as exc:
            print(f"FAIL {host}: {exc}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
