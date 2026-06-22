# Quick Start Guide

Get NeuronTrace running in under 5 minutes and see kernel-level enforcement in action.

---

## Prerequisites

| Requirement | How to check |
|-------------|-------------|
| Linux kernel 5.15+ | `uname -r` |
| BTF enabled | `ls /sys/kernel/btf/vmlinux` |
| BPF-LSM enabled | `cat /sys/kernel/security/lsm` (must include `bpf`) |
| Rust nightly | `rustc --version` |
| Root access | `whoami` or use `sudo` |

> **Don't have BPF-LSM?** Add `lsm=lockdown,capability,landlock,yama,bpf` to your kernel command line and reboot. See [docs/development.md](development.md) for details.

---

## Step 1: Build

```bash
git clone https://github.com/yasindce1998/NeuronTrace.git
cd NeuronTrace

# Install bpf-linker (one-time)
cargo install bpf-linker

# Build everything
cargo xtask build --release
```

This produces `./target/release/neurontrace`.

---

## Step 2: Create a cgroup for the agent

NeuronTrace enforces policy on processes inside a cgroup. Create one:

```bash
sudo mkdir -p /sys/fs/cgroup/neurontrace-demo
```

---

## Step 3: Start NeuronTrace with a policy

Open a terminal and run:

```bash
sudo ./target/release/neurontrace run \
  --policy policies/generic-agent.yaml \
  --cgroup /sys/fs/cgroup/neurontrace-demo
```

You'll see:

```
INFO attached LSM hook program="nt_exec_check" hook="bprm_check_security"
INFO attached LSM hook program="nt_file_open" hook="file_open"
INFO attached LSM hook program="nt_inode_unlink" hook="inode_unlink"
INFO attached LSM hook program="nt_inode_rename" hook="inode_rename"
INFO attached LSM hook program="nt_socket_connect" hook="socket_connect"
INFO attached LSM hook program="nt_ptrace_check" hook="ptrace_access_check"
INFO policy rules loaded count=6
INFO NeuronTrace enforcing — default-deny active
```

NeuronTrace is now enforcing. Leave this terminal running.

---

## Step 4: Put a process in the cgroup

Open a **second terminal** and move a shell into the monitored cgroup:

```bash
# Move the current shell into the cgroup
echo $$ | sudo tee /sys/fs/cgroup/neurontrace-demo/cgroup.procs
```

This shell (and everything it spawns) is now under NeuronTrace enforcement.

---

## Step 5: See enforcement in action

From the shell you just moved into the cgroup, try things:

### Exec — BLOCKED

```bash
$ ls
bash: /usr/bin/ls: Operation not permitted

$ whoami
bash: /usr/bin/whoami: Operation not permitted

$ python3 -c "print('hello')"
bash: /usr/bin/python3: Operation not permitted
```

The `generic-agent` policy blocks all exec. The kernel returns `-EPERM` before the process even loads.

### Network — BLOCKED

```bash
$ curl https://example.com
bash: /usr/bin/curl: Operation not permitted
```

Even if exec weren't blocked, `connect` is also blocked. Double protection.

### File read — AUDITED

```bash
$ cat /etc/hostname   # This works (open is set to 'audit')
my-machine
```

But in the first terminal (NeuronTrace), you'll see:

```
INFO violation event="file_open" pid=12345 action="audit" path="/etc/hostname"
```

The operation succeeded, but NeuronTrace logged it.

### File delete — BLOCKED

```bash
$ rm /tmp/testfile
rm: cannot remove '/tmp/testfile': Operation not permitted
```

---

## Step 6: Try a less restrictive policy

Stop NeuronTrace (Ctrl+C) and restart with the Claude Code policy:

```bash
sudo ./target/release/neurontrace run \
  --policy policies/claude-code.yaml \
  --cgroup /sys/fs/cgroup/neurontrace-demo
```

Now from the cgroup shell:

```bash
$ ls              # Still blocked (exec = block)
bash: /usr/bin/ls: Operation not permitted

$ cat README.md   # Works (open = allow)
...

$ rm somefile     # Works but logged (unlink = audit)
```

The Claude Code policy allows file I/O but blocks exec and network — appropriate for an agent that edits code but shouldn't run arbitrary commands.

---

## Step 7: Generation tagging demo

See how NeuronTrace prevents cross-task data leakage:

```bash
# Terminal 1: NeuronTrace is running
# Terminal 2: Agent shell in the cgroup

# Assign a label to the agent process (generation 1)
sudo ./target/release/neurontrace label --pid 12345 --label "task-a" --generation 1

# Agent works on Task A... file access works normally

# Now Task A is done. Bump the generation:
sudo ./target/release/neurontrace bump

# Generation is now 2. The agent's label says generation 1 = STALE
# Even operations the policy allows will now be BLOCKED:
$ cat workspace/secret-from-task-a.txt
cat: workspace/secret-from-task-a.txt: Operation not permitted
```

The agent's old permissions expired. It must be re-labeled for the new generation before it can access anything — preventing data from leaking across task boundaries.

---

## Step 8: Validate policies without root

You don't need a kernel to check policy syntax:

```bash
# No root required — just parses and validates
cargo run --package neurontrace -- validate --policy policies/claude-code.yaml
```

Output:

```
Policy "claude-code" is valid
  Rules: 6
  Event types covered: 6/6
  Actions used: allow, block, audit
```

---

## What just happened?

1. NeuronTrace loaded BPF programs into the kernel via LSM hooks
2. Every syscall from processes in the cgroup hits those hooks
3. The hook looks up `(cgroup_id, event_type)` in the policy map
4. No match → blocked (default-deny). Match → action applied.
5. Violations emitted via ring buffer back to userspace for logging

The agent never knew NeuronTrace existed. It just saw "Operation not permitted" — there's nothing to bypass, no userspace sandbox to escape, no prompt to jailbreak. The kernel said no.

---

## Next steps

- **Write a custom policy**: See [docs/policies.md](policies.md)
- **Real-world use cases**: See [docs/usecases.md](usecases.md)
- **Architecture deep-dive**: See [docs/architecture.md](architecture.md)
- **Development setup**: See [docs/development.md](development.md)

---

## Cleanup

```bash
# Remove the demo cgroup (after moving processes out)
echo $$ | sudo tee /sys/fs/cgroup/user.slice/cgroup.procs  # move shell back
sudo rmdir /sys/fs/cgroup/neurontrace-demo
```

NeuronTrace BPF programs are automatically unloaded when the process exits (Ctrl+C).
