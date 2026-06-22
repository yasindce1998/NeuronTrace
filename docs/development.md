# Development Guide

This guide covers setting up a full development environment for NeuronTrace, including kernel-level testing.

## System Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Linux kernel | 5.15 | Must have BTF support |
| Rust | nightly | Pinned via `rust-toolchain.toml` |
| bpf-linker | latest | `cargo install bpf-linker` |
| Privileges | root / `CAP_BPF` | For loading BPF programs |

## Kernel Configuration

Your kernel must be built with these options:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
```

Additionally, BPF-LSM must be enabled at boot:

```bash
# Add to kernel command line (GRUB, systemd-boot, etc.)
lsm=lockdown,capability,landlock,yama,bpf
```

Verify your running kernel supports BPF-LSM:

```bash
cat /sys/kernel/security/lsm
# Should include "bpf" in the comma-separated list

cat /boot/config-$(uname -r) | grep BPF_LSM
# Should show CONFIG_BPF_LSM=y
```

## Toolchain Setup

```bash
# Clone the repository
git clone https://github.com/yasindce1998/NeuronTrace.git
cd NeuronTrace

# rust-toolchain.toml auto-installs nightly + components
# Verify:
rustc --version   # should show nightly

# Install bpf-linker (required for eBPF compilation)
cargo install bpf-linker
```

## Building

### Full build (userspace + eBPF)

```bash
cargo xtask build
cargo xtask build --release
```

### Individual crates

```bash
# Userspace binary
cargo build --package neurontrace

# Common types (with serde support)
cargo build --package neurontrace-common --features user

# eBPF programs (cross-compiled to BPF target)
cargo +nightly build --package neurontrace-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core

# Build automation
cargo build --package xtask
```

### Why two compilation targets?

The eBPF crate compiles to `bpfel-unknown-none` (bare-metal BPF bytecode), while everything else targets your host. The `xtask` crate orchestrates this so `cargo xtask build` handles both in one command.

## Testing

### Without a kernel (CI-safe)

These work on any OS and don't require BPF:

```bash
# Type checking
cargo check --package neurontrace
cargo check --package neurontrace-common --features user

# Unit tests
cargo test --package neurontrace-common --features user \
           --package neurontrace \
           --package xtask

# Linting
cargo clippy --package neurontrace -- -D warnings
```

### With a real kernel

Full integration testing requires a Linux system with BPF-LSM enabled:

```bash
# Build release binary
cargo xtask build --release

# Load and run with a starter policy
sudo ./target/release/neurontrace run \
  --policy policies/generic-agent.yaml \
  --cgroup /sys/fs/cgroup/neurontrace

# In another terminal, test enforcement:
# (within the cgroup, exec should be blocked by generic-agent policy)
```

### Recommended: VM-based testing

Running eBPF development on your daily-driver kernel is risky. Use a VM:

**QEMU with virtme-ng** (fastest iteration):

```bash
# Install virtme-ng
pip install virtme-ng

# Boot your host kernel in a lightweight VM
vng --run -- ./target/release/neurontrace run --policy policies/generic-agent.yaml
```

**Dedicated VM** (VirtualBox, libvirt, etc.):
- Use Ubuntu 22.04+ or Fedora 38+ (both ship BTF-enabled kernels)
- Ensure `lsm=bpf` is in boot params
- Share the repo via 9p, NFS, or just clone inside the VM

## Debugging BPF Programs

### Verifier errors

The BPF verifier rejects unsafe programs at load time. Common issues:

```bash
# See verifier output (aya prints it on load failure)
sudo RUST_LOG=debug ./target/release/neurontrace run --policy policies/generic-agent.yaml
```

- **"back-edge in control flow"** — unbounded loops; BPF requires bounded iteration
- **"invalid mem access"** — accessing map values without null-checking `bpf_map_lookup_elem` return
- **"program too large"** — reduce branches or split into tail-called programs

### Inspecting loaded programs

```bash
# List loaded BPF programs
sudo bpftool prog list

# Dump program instructions
sudo bpftool prog dump xlated id <ID>

# View map contents
sudo bpftool map dump name POLICY_MAP
sudo bpftool map dump name GENERATION
sudo bpftool map dump name PID_ALLOWLIST
```

### Tracing

```bash
# Trace BPF program execution
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Enable tracing for specific hooks
sudo bpftool prog tracelog
```

## Common Issues

| Problem | Cause | Fix |
|---------|-------|-----|
| `bpf-linker` install fails | LLVM version mismatch | Install matching LLVM: `apt install llvm-17-dev` |
| "BPF_LSM not available" | LSM not enabled at boot | Add `lsm=bpf` to kernel cmdline |
| "BTF not found" | Kernel built without BTF | Rebuild kernel with `CONFIG_DEBUG_INFO_BTF=y` or use a distro kernel |
| Map lookup returns `None` | Map not populated yet | Load policy before testing enforcement |
| Permission denied on BPF load | Not root / no `CAP_BPF` | Run with `sudo` |
| eBPF build fails on macOS/Windows | Cross-compilation host limitation | eBPF crate only builds on Linux; use `cargo check` for userspace |
