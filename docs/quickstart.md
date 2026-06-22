# Quick Start

See NeuronTrace block syscalls in real time — two commands, one terminal.

## Prerequisites

- Linux kernel 5.15+ with BPF-LSM enabled (`cat /sys/kernel/security/lsm` must include `bpf`)
- Rust nightly (`rustc --version`)
- Root access

> **Don't have BPF-LSM?** Add `lsm=lockdown,capability,landlock,yama,bpf` to your kernel command line and reboot.

## Run the demo

```bash
git clone https://github.com/yasindce1998/NeuronTrace.git
cd NeuronTrace
cargo xtask build --release

sudo ./scripts/demo.sh
```

That's it. The script:
1. Checks your kernel supports BPF-LSM
2. Creates a temporary cgroup
3. Starts NeuronTrace with the default-deny policy
4. Runs test commands **inside** the cgroup so you can see them get blocked
5. Shows the violation log
6. Cleans everything up on exit

### What you'll see

```
╔══════════════════════════════════════════════╗
║        NeuronTrace — Live Demo              ║
╚══════════════════════════════════════════════╝

▸ Pre-flight checks
✓ Kernel 6.1.0, BPF-LSM active, binary ready
✓ Policy: policies/generic-agent.yaml

▸ Creating demo cgroup
✓ /sys/fs/cgroup/neurontrace-demo

▸ Starting NeuronTrace (background)
✓ NeuronTrace running (PID 4521)

══════════════════════════════════════════════
  Testing enforcement inside the cgroup
══════════════════════════════════════════════

▸ Test 1: exec (should be BLOCKED)
  $ /bin/ls /tmp
    BLOCKED — Operation not permitted

▸ Test 2: exec another binary (should be BLOCKED)
  $ /usr/bin/whoami
    BLOCKED — Operation not permitted

▸ Test 3: network connect (should be BLOCKED)
  $ /usr/bin/curl -s --max-time 2 https://example.com
    BLOCKED — Operation not permitted

▸ Test 4: file delete (should be BLOCKED)
  $ rm /tmp/tmp.xyz123
    BLOCKED — Operation not permitted

▸ Test 5: file read (may be AUDITED — allowed but logged)
  $ cat /etc/hostname
    ALLOWED — my-machine

══════════════════════════════════════════════
  Demo complete!
══════════════════════════════════════════════
```

## Try different policies

```bash
# Claude Code agent: allows file I/O, blocks exec and network
sudo ./scripts/demo.sh policies/claude-code.yaml

# Codex agent: audits exec, blocks network
sudo ./scripts/demo.sh policies/codex.yaml

# Generic (most restrictive): blocks everything, audits file reads
sudo ./scripts/demo.sh policies/generic-agent.yaml
```

## Validate a policy without root

No kernel needed — just checks syntax:

```bash
cargo run --package neurontrace -- validate --policy policies/claude-code.yaml
```

## What just happened?

```
┌─────────────────────────────────────────────────┐
│ Agent process tries: execve("/bin/ls")           │
│         ↓                                       │
│ Kernel hits LSM hook → BPF program runs         │
│         ↓                                       │
│ Lookup (cgroup_id, event_type) in policy map    │
│         ↓                                       │
│ No match → return -EPERM (default-deny)         │
│         ↓                                       │
│ Agent sees: "Operation not permitted"           │
└─────────────────────────────────────────────────┘
```

The agent never knew NeuronTrace existed. There's nothing to bypass — no userspace sandbox, no prompt to jailbreak. The kernel said no.

## Next steps

| Want to... | Read |
|------------|------|
| Write a custom policy | [docs/policies.md](policies.md) |
| See real-world use cases | [docs/usecases.md](usecases.md) |
| Set up a dev environment | [docs/development.md](development.md) |
| Contribute | [CONTRIBUTING.md](../CONTRIBUTING.md) |
