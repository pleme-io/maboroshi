# maboroshi

Pluggable transport framework for censorship-resistant tunneling.

Implements Tor's Pluggable Transport IPC specification in pure Rust. Provides
core traits for defining transports and obfuscation layers, built-in transport
implementations, and a CLI for running client/server endpoints. Designed for
making network traffic indistinguishable from allowed protocols.

## Quick Start

```bash
cargo test                   # run all 87 tests
cargo build --release        # release binary
nix build                    # Nix hermetic build
```

## Crates

| Crate | Purpose |
|-------|---------|
| `maboroshi-core` | `PluggableTransport` and `Obfuscator` traits, PT lifecycle types |
| `maboroshi-transports` | Built-in transports: plain, WebTunnel, obfs4 (planned) |
| `maboroshi-cli` | CLI binary with `client`, `server`, and `list` subcommands |

## Transports

| Name | Status | Description |
|------|--------|-------------|
| plain | Complete | Unobfuscated TCP passthrough (baseline/testing) |
| webtunnel | Stub | WebSocket-based obfuscation (looks like HTTPS) |
| obfs4 | Planned | Elligator2 + ntor + AES-CTR (Tor standard) |

## Usage

```bash
# List available transports
maboroshi list

# Start a client-side transport endpoint
maboroshi client --transport plain --listen 127.0.0.1:9100 --remote 192.0.2.1:443

# Start a server-side transport endpoint
maboroshi server --transport plain --listen 0.0.0.0:443 --forward 127.0.0.1:9050

# Use WebTunnel obfuscation (traffic looks like HTTPS)
maboroshi client --transport webtunnel --listen 127.0.0.1:9100 --remote bridge.example.com:443
```

## License

MIT
