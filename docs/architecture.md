# Architecture

## Overview

NeuronTrace is a kernel-level behavioral containment system built on Linux BPF-LSM. It enforces security policies on AI agent processes without requiring cooperation from the agent itself.

```
┌─────────────────────────────────────────────┐
│                 Userspace                     │
│                                              │
│  ┌──────────┐   ┌────────┐   ┌───────────┐ │
│  │ CLI/API  │──▶│ Policy │──▶│ BPF Loader│ │
│  └──────────┘   │ Parser │   └─────┬─────┘ │
│                  └────────┘         │        │
│  ┌──────────┐                       │        │
│  │ Event    │◀── ring buffer ───────┼──┐     │
│  │ Consumer │                       │  │     │
│  └──────────┘                       │  │     │
├─────────────────────────────────────┼──┼─────┤
│                 Kernel               │  │     │
│                                      ▼  │     │
│  ┌──────────────────────────────────────┐    │
│  │           BPF Programs               │    │
│  │                                      │    │
│  │  ┌────────┐  ┌────────┐  ┌───────┐  │    │
│  │  │  exec  │  │  file  │  │network│  │    │
│  │  │  hook  │  │  hooks │  │ hook  │  │    │
│  │  └───┬────┘  └───┬────┘  └──┬────┘  │    │
│  │      │            │          │       │    │
│  │      ▼            ▼          ▼       │    │
│  │  ┌─────────────────────────────────┐ │    │
│  │  │        Policy Engine            │ │    │
│  │  │  (POLICY_MAP + GENERATION check)│ │    │
│  │  └─────────────────────────────────┘ │    │
│  │      │                               │    │
│  │      ├──▶ ALLOW (return 0)           │    │
│  │      ├──▶ BLOCK (return -EPERM)      │    │
│  │      └──▶ emit event to ring buf ────┼────┘
│  └──────────────────────────────────────┘
└──────────────────────────────────────────────┘
```

## Data Flow

### Policy Loading

1. User provides YAML policy file
2. Userspace parses into `PolicyKey` → `PolicyValue` pairs
3. Pairs are inserted into `POLICY_MAP` (BPF HashMap)
4. BPF hooks read from this map on every syscall

### Enforcement Path (per syscall)

1. LSM hook fires (e.g., `bprm_check_security` for exec)
2. Hook extracts PID via `bpf_get_current_pid_tgid()`
3. Check PID allowlist — skip if controller process
4. Look up `(cgroup_id, event_type)` in `POLICY_MAP`
5. No match → **BLOCK** (default-deny)
6. Match found → apply action (allow/block/kill/audit)
7. Check generation: if labels are stale → **BLOCK**
8. On violation: reserve ring buffer slot, fill event, submit

### Generation Tagging

- Single `u32` counter in `GENERATION` array map
- Each process label carries its own generation stamp
- On `bump`: counter increments, all existing labels become stale
- Stale labels trigger immediate block regardless of policy
- Use case: new task = new generation = old context can't leak

## BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `POLICY_MAP` | HashMap | 1024 entries | cgroup+event → action |
| `LABEL_MAP` | LruHashMap | 4096 entries | pid → process labels |
| `GENERATION` | Array | 1 entry | current generation counter |
| `EVENTS` | RingBuf | 1 MB | violation events → userspace |
| `PID_ALLOWLIST` | HashMap | 64 entries | controller bypass |

## Crate Structure

### `neurontrace-common` (no_std)

Shared `#[repr(C)]` types used by both BPF and userspace. Feature-gated: the `user` feature enables serde and Display impls that would pull in std.

### `neurontrace-ebpf` (no_std, no_main)

BPF programs compiled to `bpfel-unknown-none`. Contains LSM hook entry points, map definitions, and the in-kernel policy engine. Compiled with `opt-level=2`, `panic=abort`.

### `neurontrace` (std)

Userspace binary. Loads BPF via aya, parses YAML policies, manages cgroups, consumes ring buffer events, handles generation counter bumps.

### `xtask`

Build automation. Handles cross-compilation of the eBPF target with proper flags (`-Z build-std=core`, `bpfel-unknown-none`).

## Security Model

- **Trust boundary**: The kernel. BPF programs run in kernel space — agents cannot tamper with them.
- **Default-deny**: Missing policy entries result in blocked syscalls, not allowed ones.
- **Fail-open on BPF error**: If a BPF helper fails internally, hooks return 0 (allow) to avoid bricking the system. This is intentional — BPF errors are infrastructure failures, not security violations.
- **Controller self-exemption**: The neurontrace process adds its own PID to `PID_ALLOWLIST` to avoid blocking itself.
