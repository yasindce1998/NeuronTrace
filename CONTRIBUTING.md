# Contributing to NeuronTrace

Thank you for considering a contribution to NeuronTrace. This document covers what you need to get started.

## Prerequisites

- **Rust nightly** — the workspace pins nightly via `rust-toolchain.toml`
- **Linux kernel 5.15+** with BTF — required for full eBPF testing
- **bpf-linker** — `cargo install bpf-linker` (needed for eBPF compilation)
- **Root access** — BPF program loading requires `CAP_BPF` or root

For userspace-only development (no BPF loading), any OS with Rust nightly works.

## Project Structure

NeuronTrace is a Cargo workspace with 4 crates:

| Crate | Purpose |
|-------|---------|
| `neurontrace` | Userspace binary — CLI, BPF loader, policy engine |
| `neurontrace-ebpf` | BPF programs — LSM hooks (`no_std`, `bpfel-unknown-none`) |
| `neurontrace-common` | Shared `#[repr(C)]` types between kernel and userspace |
| `xtask` | Build automation for cross-compiling BPF programs |

## Building

```bash
# Build everything (userspace + eBPF)
cargo xtask build

# Build only userspace crates
cargo build --package neurontrace --package neurontrace-common

# Build only eBPF (requires bpf-linker)
cargo xtask build-ebpf
```

## Running CI Checks Locally

The CI pipeline runs 5 jobs. Run these before pushing:

```bash
# 1. Format check (nightly rustfmt)
cargo +nightly fmt --all -- --check

# 2. Userspace type checking
RUSTFLAGS="-Dwarnings" cargo check --package neurontrace-common --features user
RUSTFLAGS="-Dwarnings" cargo check --package neurontrace
RUSTFLAGS="-Dwarnings" cargo check --package xtask

# 3. eBPF compilation
cargo +nightly build --package neurontrace-ebpf --target bpfel-unknown-none -Z build-std=core

# 4. Clippy
RUSTFLAGS="-Dwarnings" cargo clippy --package neurontrace-common --features user
RUSTFLAGS="-Dwarnings" cargo clippy --package neurontrace
RUSTFLAGS="-Dwarnings" cargo clippy --package xtask

# 5. Tests
RUSTFLAGS="-Dwarnings" cargo test --package neurontrace-common --features user --package neurontrace --package xtask
```

## Code Style

- Format with `cargo +nightly fmt --all`
- All clippy warnings are errors in CI (`-Dwarnings`)
- No `unsafe` in userspace code — aya handles the BPF FFI boundary
- Keep `neurontrace-common` `no_std`-compatible (std features behind `user` flag)

## Making Changes

1. Fork the repository and create a branch from `main`
2. Make your changes — one logical change per PR
3. Run the CI checks locally (see above)
4. Write a clear PR description: what changed and why
5. Submit the PR against `main`

## Commit Messages

- Use imperative mood: "Add policy validation" not "Added policy validation"
- Keep the first line under 72 characters
- Add a body when the "why" isn't obvious from the diff

## Reporting Issues

Use [GitHub Issues](https://github.com/yasindce1998/NeuronTrace/issues). For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
