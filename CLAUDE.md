# Maboroshi — Pluggable Transport Framework

Pure Rust implementation of Tor's Pluggable Transport IPC protocol with
obfuscation layers for censorship-resistant tunneling.

**Tests:** 87

## Architecture

```
maboroshi-core        Core traits (PluggableTransport, Obfuscator) + types
maboroshi-transports  Built-in transports (plain, webtunnel, obfs4 planned)
maboroshi-cli         CLI binary (client, server, list subcommands)
```

### Core Traits

- `PluggableTransport` — async start_client / start_server, name, transport_type
- `Obfuscator` — wrap a raw async stream into an obfuscated one

### Key Types

| Type | Kind | Description |
|------|------|-------------|
| `PtState` | Enum | 7 lifecycle states for transport processes |
| `ObfuscationLevel` | Enum | None / Moderate / Paranoid |
| `TransportMode` | Enum | Client / Server |
| `TransportStatus` | Struct | Runtime status of a transport instance |
| `MockPluggableTransport` | Struct | Deterministic transport for testing |
| `Error` | Struct | Clone + PartialEq + is_retryable() |

### Transports

| Transport | Status | Description |
|-----------|--------|-------------|
| plain | Complete | Unobfuscated TCP passthrough (baseline/testing) |
| webtunnel | Stub | WebSocket-based obfuscation (looks like HTTPS) |
| obfs4 | Planned | Elligator2 + ntor + AES-CTR (Tor standard) |

## Key Files

| Path | Purpose |
|------|---------|
| `maboroshi-core/src/lib.rs` | Core traits, error types, config structs, PtState, ObfuscationLevel, TransportMode, TransportStatus |
| `maboroshi-transports/src/plain.rs` | Plain TCP transport implementation |
| `maboroshi-transports/src/webtunnel.rs` | WebTunnel transport + obfuscator |
| `maboroshi-cli/src/main.rs` | CLI entry point with clap subcommands, execute() extracted for testability |
| `flake.nix` | Nix build (substrate workspace builder) |

## Build Commands

```bash
cargo check                    # Type-check all crates
cargo test                     # Run all tests
cargo build --release          # Release build
cargo run -- list              # List available transports
cargo run -- client --help     # Client subcommand help
cargo run -- server --help     # Server subcommand help
nix build                      # Nix hermetic build
```

## Conventions

- Edition 2024, Rust 1.89.0+, MIT license
- `[lints.clippy] pedantic = "warn"` with standard pleme-io allowances
- Release: codegen-units=1, lto=true, opt-level="z", strip=true
- Pure Rust only (rustls, no native-tls / C FFI)
- shikumi for configuration
- async-trait + tokio for async runtime
- thiserror 2 for error types
- tracing for structured logging (replaced silenced errors with tracing::debug)

## Adding a New Transport

1. Create `maboroshi-transports/src/{name}.rs`
2. Implement `PluggableTransport` trait (and optionally `Obfuscator`)
3. Add `TransportType::{Name}` variant to `maboroshi-core/src/lib.rs`
4. Register in `maboroshi-transports/src/lib.rs` (pub mod + re-export)
5. Add match arm in `maboroshi-cli/src/main.rs` (`transport_for` + `available_transports`)
6. Write tests (minimum 3: name, transport_type, connectivity)
