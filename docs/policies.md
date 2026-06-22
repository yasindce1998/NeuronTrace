# Policy Reference

NeuronTrace uses YAML policy files to define what an AI agent is allowed to do. This document covers the policy schema, semantics, and how to write custom policies.

## Core Principle: Default-Deny

If no rule matches a syscall, NeuronTrace **blocks** it. You don't write rules for what to block — you write rules for what to allow. Everything else is denied automatically.

## Policy Schema

```yaml
name: my-policy
description: What this policy is for
rules:
  - event_type: exec
    action: block
    cgroup_id: 0
    description: Prevent process execution
```

### Top-level fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Short identifier for the policy |
| `description` | Yes | Human-readable purpose |
| `rules` | Yes | List of enforcement rules |

### Rule fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `event_type` | Yes | — | Which syscall class this rule covers |
| `action` | Yes | — | What to do when this event fires |
| `cgroup_id` | No | `0` | Scope to a specific cgroup (0 = all cgroups) |
| `description` | No | `""` | Human-readable note about this rule |

## Event Types

Each event type maps to one or more Linux syscalls intercepted via BPF-LSM hooks:

| Event Type | LSM Hook | Syscalls Covered |
|------------|----------|------------------|
| `exec` | `bprm_check_security` | `execve`, `execveat` |
| `open` | `file_open` | `open`, `openat`, `openat2` |
| `unlink` | `inode_unlink` | `unlink`, `unlinkat` |
| `rename` | `inode_rename` | `rename`, `renameat`, `renameat2` |
| `connect` | `socket_connect` | `connect` |
| `ptrace` | `ptrace_access_check` | `ptrace` |

## Actions

| Action | Behavior | Return to Kernel |
|--------|----------|-----------------|
| `allow` | Permit the operation | `0` (success) |
| `block` | Deny the operation silently | `-EPERM` |
| `kill` | Deny and terminate the process | `-EPERM` + `SIGKILL` |
| `audit` | Permit but emit a violation event | `0` (success) |

**`block`** — The syscall fails with "permission denied." The agent sees an error but continues running.

**`kill`** — The process is terminated immediately. Use for critical violations where continued execution is dangerous (e.g., ptrace attempts suggesting sandbox escape).

**`audit`** — The operation succeeds, but NeuronTrace emits an event to the ring buffer. Userspace logs it. Useful for monitoring without enforcement, or for operations that are suspicious but not dangerous (e.g., file deletions in a workspace).

## Cgroup Scoping

The `cgroup_id` field scopes a rule to a specific cgroup:

- **`cgroup_id: 0`** (default) — Rule applies to all monitored processes regardless of cgroup
- **`cgroup_id: <id>`** — Rule applies only within that specific cgroup

The kernel resolves the cgroup ID at runtime from the process's cgroup membership.

### Lookup order

1. Look up `(process_cgroup_id, event_type)` in the policy map
2. If no match, look up `(0, event_type)` (global fallback)
3. If still no match → **BLOCK** (default-deny)

This means cgroup-specific rules override global rules for processes in that cgroup.

## Generation Tagging

Rules interact with the generation system:

- Even if a policy allows an operation, a **stale generation stamp** on the process's labels triggers a block
- Generation checks happen after policy lookup
- A process with no labels passes generation checks (no labels = nothing to go stale)
- Generation `0` on a label is treated as "unversioned" and never expires

This prevents data from leaking across task boundaries — when you bump the generation, all processes with old-generation labels lose their permissions regardless of policy.

## Examples

### Restrictive code agent (like Claude Code)

Allow file operations in the workspace, block everything else:

```yaml
name: code-agent-strict
description: Allows file I/O, blocks exec and network
rules:
  - event_type: open
    action: allow
  - event_type: rename
    action: allow
  - event_type: unlink
    action: audit
    description: Log file deletions
  - event_type: exec
    action: block
  - event_type: connect
    action: block
  - event_type: ptrace
    action: block
```

### Network-auditing agent

Let the agent run freely but log all network connections:

```yaml
name: network-audit
description: Full permissions except network is audited
rules:
  - event_type: exec
    action: allow
  - event_type: open
    action: allow
  - event_type: unlink
    action: allow
  - event_type: rename
    action: allow
  - event_type: connect
    action: audit
    description: Log every outbound connection
  - event_type: ptrace
    action: block
```

### Full lockdown (untrusted agent)

Block everything, audit file reads only:

```yaml
name: full-lockdown
description: Maximum restriction for untrusted agents
rules:
  - event_type: exec
    action: block
  - event_type: open
    action: audit
  - event_type: unlink
    action: block
  - event_type: rename
    action: block
  - event_type: connect
    action: block
  - event_type: ptrace
    action: block
```

## Starter Policies

NeuronTrace ships three starter policies in the `policies/` directory:

| File | Target | Philosophy |
|------|--------|------------|
| `claude-code.yaml` | Claude Code | Allow file ops, block exec and network |
| `codex.yaml` | OpenAI Codex | Audit exec (Codex spawns subprocesses), block network |
| `generic-agent.yaml` | Any untrusted agent | Maximum restriction, audit-only file reads |

Use these as templates for your own policies.

## Validation

Validate a policy without loading BPF:

```bash
cargo run --package neurontrace -- validate --policy my-policy.yaml
```

This checks YAML syntax, valid event types, valid actions, and reports coverage (which event types have rules).
