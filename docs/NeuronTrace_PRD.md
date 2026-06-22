# NeuronTrace
### Kernel-Level Behavioral Containment for AI Agents

**Product Requirements Document** · v0.1 · June 2026

| | |
|---|---|
| **Author** | Yasin · yasindce1998 |
| **Status** | Final — ready for implementation |
| **Language** | Rust (aya for eBPF, no libbpf/clang dependency) |
| **Platform** | Linux only (kernel 5.15+ with BTF) |
| **Prior art** | Inspired by ActPlane (eunomia-bpf). NeuronTrace adds task-boundary awareness via generation-tagging and ships default-deny policies out of the box. |

---

## Pitch

> ActPlane requires you to imagine every attack. NeuronTrace blocks everything by default and knows when your agent is leaking data across task boundaries.

---

## Table of Contents

1. [Summary](#1-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [v0.1 Scope](#4-v01-scope)
5. [Kernel Mode](#5-kernel-mode)
6. [Generation-Tagged Mode](#6-generation-tagged-mode)
7. [Starter Policy Packs](#7-starter-policy-packs)
8. [Feedback Loop](#8-feedback-loop)
9. [Self-Protection](#9-self-protection)
10. [Performance and Stability](#10-performance-and-stability)
11. [Success Criteria](#11-success-criteria)
12. [v0.2 Roadmap — Graph Mode & Defer](#12-v02-roadmap--graph-mode--defer)
13. [v0.3 Roadmap — Platform Expansion & Ecosystem](#13-v03-roadmap--platform-expansion--ecosystem)

---

## 1. Summary

NeuronTrace is a kernel-level (eBPF) behavioral containment tool for autonomous AI agents (Claude Code, Codex, etc.). It enforces process, filesystem, and network access at the syscall boundary — independent of what the model "decides" — and feeds violation context back so the agent can self-correct.

v0.1 ships two enforcement tiers in a single binary:

- **Kernel mode** (default) — default-deny allowlists enforced in-kernel. No userspace round-trip.
- **Generation-tagged mode** (opt-in flag) — extends kernel mode with a single-integer task-boundary stamp that detects cross-task data leakage at kernel speed.

Both tiers are entirely kernel-resident. No userspace decision engine, no graph database, no dashboard.

---

## 2. Problem Statement

Prompt injection defeats instruction-following defenses by design — the attack IS a successful instruction, not a malformed one. The only durable control point is the kernel boundary: what the underlying OS process is actually permitted to execute, read, write, or connect to.

Existing mitigations fail at the wrong layer:

- **Prompt-level guardrails** — bypassable because the attack is indistinguishable from a valid instruction
- **Approval UX** — too slow for autonomous sessions, alert fatigue bypasses it
- **Application-level allowlists** — enforced by the same process that can be manipulated

NeuronTrace's thesis: you cannot reliably control what an AI decides, but you can control what it is able to access.

---

## 3. Goals and Non-Goals

### Goals

1. Kernel-enforced containment independent of agent cooperation
2. Deployable by a non-kernel-expert in under 2 minutes (single binary, starter policies, audit-first onboarding)
3. Detect cross-task data leakage in-kernel via generation-tagging
4. Feed structured violation context back to agent hooks for self-correction
5. Default-deny: unanticipated actions are blocked without requiring a rule to be written in advance

### Non-Goals

- Not a general-purpose runtime security engine (that's Warmor)
- No graph mode / multi-hop data-flow tracing in v0.1
- No Windows or macOS (Linux/eBPF only)
- No dashboards, observability UI, or monitoring product
- No human-in-the-loop `defer` mechanism in v0.1

---

## 4. v0.1 Scope

Three things ship together. All three are required — shipping any subset makes NeuronTrace indistinguishable from ActPlane:

| Component | What it provides | Why it's in v0.1 |
|---|---|---|
| **Kernel mode** | BPF-LSM hooks, default-deny allowlists, kill/block/audit effects | Table stakes — the enforcement foundation |
| **Generation-tagging** | Single-integer task-boundary stamp, cross-task leakage detection | The differentiator — something ActPlane architecturally cannot do |
| **Starter policy packs** | Pre-built policies for Claude Code, Codex, generic shell agent | The UX win — zero rule-writing required, works in 2 minutes |

---

## 5. Kernel Mode

*As a security engineer, I can enforce syscall-level restrictions on AI agents so that no prompt injection or jailbreak can bypass my containment — because the kernel denies the action before it executes.*

*As a developer running Claude Code, I can restrict which binaries it spawns, which files it reads, and which hosts it contacts — without modifying the agent itself or trusting its cooperation.*

### 5.1 Hooks

| Hook | What it catches |
|---|---|
| fork / exec / exit | Unauthorized process spawning, shell-out attacks |
| open / unlink / rename | Credential reads, file destruction, covert channels via rename |
| connect | Network exfiltration, C2 callbacks |
| ptrace | Process injection, tracing evasion |
| execve argv/envp | curl-pipe-sh patterns, env var exfiltration (gated behind binary watchlist) |

### 5.2 Label Model

Flat label set per process/file/network node (taint-style). Capped at fixed maximum per process to bound fork-time copy cost. Stored in `BPF_MAP_TYPE_LRU_HASH` with automatic eviction.

### 5.3 Rule Language

Default-deny with explicit allowlists per task scope:

```yaml
scope: task-current
default: deny
allow:
  exec: ["/usr/bin/git", "/usr/bin/python3", "/usr/bin/node"]
  open:
    read: ["/home/user/project/**", "/tmp/**"]
    write: ["/home/user/project/**"]
  connect: ["api.github.com:443", "registry.npmjs.org:443"]
deny:
  open: ["~/.ssh/**", "~/.aws/**", "~/.config/gh/**"]
  exec: ["/usr/bin/curl | sh", "/usr/bin/wget | sh"]
```

### 5.4 Effects

- **block** — BPF-LSM returns `-EPERM` (default for deny rules)
- **kill** — `SIGKILL` to the process tree
- **audit** — logged, allowed through (default mode for first-run onboarding)

### 5.5 Cgroup Scoping

Hooks attach at cgroup scope, not system-wide. Non-agent processes never enter the BPF program. NeuronTrace creates a dedicated cgroup for the agent process tree at launch.

---

## 6. Generation-Tagged Mode

*As a user running multi-task agent sessions, I can ensure that data accessed in Task A cannot leak into Task B — even if the agent's context window carries forward — because NeuronTrace detects and blocks stale-generation access at the kernel level.*

*As a compliance officer, I can prove that cross-task data isolation is enforced by hardware-speed kernel checks, not by trusting the AI model to respect boundaries.*

Enabled via `--task-scoping=on`. No separate binary, no userspace component.

### 6.1 Mechanism

1. Harness writes one integer to a BPF map at each task boundary: `current_generation += 1`
2. Every label created is stamped with the active generation
3. Rules can compare: `deny if label.generation != current_generation`
4. Stale labels age out via existing LRU eviction — no cleanup needed

### 6.2 What It Catches

An agent reads a file scoped to Task A → harness signals task boundary → agent moves to Task B → agent (or injected instruction in carried-forward context) tries to use Task A's data in Task B → **blocked in-kernel**.

### 6.3 Performance

One extra integer load and compare per label check. The generation increment happens once per task boundary, not per syscall. Effectively free.

### 6.4 Limits

- Answers only "current vs. stale" — cannot trace multi-hop paths
- No benefit in single-task sessions
- Correctness depends on the harness signaling boundaries accurately

### 6.5 Harness Integration

NeuronTrace exposes a Unix socket API for harness integration:

```
POST /generation/advance    → increments the generation counter
GET  /generation/current    → returns current generation value
```

For Claude Code: a PostToolUse hook writes to this socket when the session switches tasks. For Codex: the orchestrator signals at job boundaries.

---

## 7. Starter Policy Packs

*As a developer who has never written eBPF or security policies, I can protect my agent in under 2 minutes by selecting a starter pack that matches my harness — no rule-writing, no kernel knowledge required.*

*As a team lead, I can roll out consistent containment across all developers using the same starter policy, then customize as we learn what our agents actually need.*

Shipped in-binary. Zero configuration required for supported harnesses.

### 7.1 Claude Code Pack

```yaml
name: claude-code
default: deny
audit_first: true   # first run is audit-only, user promotes to enforce after review

allow:
  exec:
    - /usr/bin/git
    - /usr/bin/node
    - /usr/bin/npm
    - /usr/bin/npx
    - /usr/bin/python3
    - /usr/bin/cargo
    - /usr/bin/rustc
  open:
    read: ["$PROJECT_DIR/**", "/tmp/**", "/usr/lib/**", "/usr/share/**"]
    write: ["$PROJECT_DIR/**", "/tmp/**"]
  connect:
    - "api.anthropic.com:443"
    - "github.com:443"
    - "api.github.com:443"
    - "registry.npmjs.org:443"
    - "crates.io:443"

deny:
  open: ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.config/gh/hosts.yml"]
  exec: ["**/curl|sh", "**/wget|sh"]
```

### 7.2 Codex Pack

Similar structure, tuned for OpenAI's agent patterns (different allowed endpoints, different default tools).

### 7.3 Generic Shell Agent Pack

Minimal allowlist — allows basic shell tools, denies credentials and network by default.

### 7.4 Onboarding Flow

```
$ cargo install neurontrace
$ neurontrace run claude -p "fix the login bug"

[NeuronTrace] Using starter policy: claude-code (audit mode)
[NeuronTrace] First run — all violations logged, nothing blocked.
[NeuronTrace] Review violations with: neurontrace audit show
[NeuronTrace] Promote to enforce with: neurontrace enforce enable

... agent runs normally ...

[NeuronTrace] Session complete. 3 violations logged:
  1. exec(/usr/bin/curl) — not in allowlist [audit]
  2. connect(unknown-host.com:443) — not in allowlist [audit]
  3. open(~/.ssh/id_rsa) — explicitly denied [audit]

$ neurontrace audit show   # review details
$ neurontrace enforce enable   # switch to blocking mode
```

---

## 8. Feedback Loop

*As an AI agent, when my action is blocked I receive structured context explaining what was denied and why — so I can self-correct (try a different approach) instead of retrying the same blocked action in a loop.*

*As a developer debugging a stuck agent, I can see exactly which syscalls were blocked and what policy rule triggered — without digging through kernel logs.*

When a violation occurs (in enforce mode), NeuronTrace delivers a structured JSON payload to the agent's hook system:

```json
{
  "kind": "violation",
  "hook": "connect",
  "target": "attacker.com:443",
  "effect": "block",
  "rule": "default-deny-network",
  "severity": "high",
  "suggested_retry": false,
  "message": "Network connection to attacker.com:443 denied — not in allowlist. This action is not permitted under the current policy."
}
```

Delivered via:
- Claude Code: PostToolUse / PostToolUseFailure hooks (stdin JSON)
- Codex: stdout structured event
- Generic: Unix socket + optional webhook

The agent receives enough context to self-correct (try an alternative approach) or escalate (ask the user) rather than retrying the same blocked action forever.

---

## 9. Self-Protection

*As a security engineer, I need NeuronTrace to be unkillable from inside the cgroup — so a compromised agent cannot disable enforcement by killing the controller process or unloading BPF programs.*

### 9.1 Threat

An agent discovers NeuronTrace is running and attempts to:
1. Kill the userspace process (`kill(nrt_pid, SIGKILL)`)
2. Unpin BPF programs from bpffs
3. Attach a debugger to corrupt NeuronTrace state

### 9.2 Defense: BPF Pinning

BPF programs and maps are pinned to `/sys/fs/bpf/neurontrace/` at load time. If the userspace process dies (crash, OOM, or attack), enforcement **continues in-kernel**. The hooks keep blocking syscalls — only the violation logger stops.

```
Agent kills NRT process → BPF hooks still attached → enforcement persists
Operator runs `neurontrace unload` → unpins from bpffs → hooks removed
```

### 9.3 Defense: `task_kill` LSM Hook

A 7th LSM hook on `task_kill` blocks signal delivery from processes inside the enforcement cgroup to PIDs outside it:

| Signal source | Target | Result |
|---|---|---|
| Inside cgroup | NeuronTrace PID | **BLOCKED** |
| Inside cgroup | Other cgroup process | Allowed (intra-cgroup) |
| Outside cgroup (operator) | NeuronTrace PID | Allowed |
| Outside cgroup (operator) | Any PID | Allowed |

The PID allowlist already exempts NeuronTrace — extend that logic to signal delivery.

### 9.4 Defense Layers (Summary)

```
┌─────────────────────────────────────────┐
│ Operator (outside cgroup)               │
│  • Can kill NRT process                 │
│  • Can unpin BPF programs               │
│  • Can delete the cgroup                │
│  • Full control                         │
├─────────────────────────────────────────┤
│ NeuronTrace (PID allowlist)             │
│  • Self-exempted from enforcement       │
│  • Manages policy maps                  │
│  • Reads ring buffer                    │
├─────────────────────────────────────────┤
│ Agent (inside cgroup)                   │
│  • Can't kill NRT (signal blocked)      │
│  • Can't exec kill command (exec block) │
│  • Can't unpin (no bpffs access)        │
│  • Can't ptrace (ptrace hook blocks)    │
│  • Sees only -EPERM                     │
└─────────────────────────────────────────┘
```

### 9.5 Stopping NeuronTrace (Operator Path)

```bash
# Normal stop — operator is outside cgroup, signals allowed
Ctrl+C / kill $(pidof neurontrace)

# Unload pinned BPF programs (enforcement stops)
sudo neurontrace unload

# Manual cleanup (if process already dead)
sudo rm -rf /sys/fs/bpf/neurontrace/
```

---

## 10. Performance and Stability

### 10.1 Performance

- Cgroup-scoped attach — zero overhead on non-agent processes
- Label storage in LRU hash map — bounded memory, O(1) lookups
- Argv/envp capture gated behind binary watchlist — not on every exec
- Ring buffer (256KB–1MB configurable) for async event delivery to CLI stats
- Target: <1μs per-syscall overhead for allow-path (label check + generation compare)

### 10.2 Stability

- **Fail-safe on crash:** fail-open by default (loud warning to stderr/syslog), fail-closed configurable
- **Clean detach:** BPF programs unpinned on exit/signal — no stale enforcement after controller dies
- **PID namespace aware:** resolves to cgroup ID for container compatibility
- **Symlink resolution:** rules match resolved paths, not argv[0]
- **Minimum kernel:** 5.15 with BTF (CO-RE for portability)

### 10.3 CLI

```
$ neurontrace status
[NeuronTrace] Mode: kernel + generation-tagged
[NeuronTrace] Policy: claude-code (enforce)
[NeuronTrace] Generation: 3 (task boundaries seen: 3)
[NeuronTrace] Syscalls observed: 14,821
[NeuronTrace] Violations: 2 blocked, 0 audited
[NeuronTrace] Ring buffer: 0 drops
```

---

## 11. Success Criteria

### 11.1 Demo (Week 2-3)

End-to-end: an agent attempts a prompt-injection pattern (curl-pipe-sh, credential read, network exfil) → blocked → structured feedback delivered → agent self-corrects.

### 11.2 Differentiation (Week 3-4)

Generation-tagging demo: agent leaks data across task boundaries → blocked in-kernel. This is something ActPlane cannot do.

### 11.3 Deployability (Week 4)

A user installs with `cargo install neurontrace`, runs with a starter policy, sees violations in audit mode, promotes to enforce — all within 2 minutes, no kernel knowledge required.

### 11.4 Benchmarks (Week 4)

Published overhead numbers: per-syscall latency (allow path), exec-heavy workload comparison (with/without NeuronTrace), ring buffer drop rate under stress.

---

## 12. v0.2 Roadmap — Graph Mode & Defer

*Target: 4-6 weeks after v0.1 ships. Only build if v0.1 usage data confirms generation-tagging is insufficient for real-world multi-hop violations.*

### 12.1 Graph Mode

*As a security researcher, I can query whether data from source A reached sink C through any intermediate path — even if no single hop violated policy — so I can detect complex exfiltration chains.*

- **Userspace graph engine** for multi-hop data-flow path queries
- **Split-decision architecture**: BPF hooks consult a verdict cache populated asynchronously by a userspace graph walker
- **Never holds syscalls in-kernel** — the BPF hook either finds a cached verdict (hit → allow/block immediately) or returns allow-with-audit (miss → log event, userspace evaluates async, updates cache for next time)
- **Graph storage**: in-memory adjacency list with bounded depth (configurable, default 4 hops)
- **Query API**: `neurontrace query --from <label> --to <label>` returns all paths

### 12.2 Defer Effect

*As a user, I can configure "ask me first" rules for ambiguous actions — the agent pauses, I approve or deny, and it resumes — so I retain human oversight without pre-deciding every edge case.*

- Uses `SIGSTOP` / `SIGCONT` on the process (not syscall holding — BPF cannot pause mid-syscall)
- Requires graph mode's verdict cache infrastructure (the deferred verdict is written to cache on user response)
- Timeout: configurable (default 30s), falls back to block on timeout
- Delivery: terminal prompt, Unix socket notification, or webhook

### 12.3 seccomp-notify Integration

*As an advanced user, I can intercept and rewrite syscall arguments (e.g., redirect file opens to sanitized copies) instead of binary allow/deny.*

- Alternative enforcement path using seccomp's supervisor notification mechanism
- Enables response injection: return fake file descriptors with sanitized content
- Research-stage in v0.2 — API design only, implementation in v0.3 if viable

### 12.4 Enhanced Policy Language

- Glob patterns for paths (`/home/*/project/**`)
- Time-based rules (block network after 5 minutes)
- Rate limiting (allow max 10 exec per minute)
- Policy composition: import and override rules from base policies

---

## 13. v0.3 Roadmap — Platform Expansion & Ecosystem

*Target: 8-12 weeks after v0.2. Contingent on community adoption and demand signals.*

### 13.1 Cross-Platform Research

*As a macOS or Windows user, I want equivalent kernel-level containment for AI agents running on my platform.*

- **macOS**: Endpoint Security Framework (ESF) — user-space daemon receiving authorization events from the kernel
- **Windows**: ETW (Event Tracing for Windows) + minifilter drivers — significantly different architecture
- Outcome: architecture assessment document, not necessarily a shipped product. Ship only if demand justifies investment.

### 13.2 Warmor Integration

*As a Warmor user, I can activate NeuronTrace as an "agent containment" policy profile within Warmor's cross-platform framework — one tool for both system-wide and agent-specific enforcement.*

- NeuronTrace policies expressed as Warmor policy modules
- Shared event pipeline: NeuronTrace violations appear in Warmor's audit stream
- Prerequisite: both projects must have stable v1.0 APIs independently

### 13.3 Container & Orchestrator Support

*As a platform engineer, I can deploy NeuronTrace enforcement across a fleet of agent containers using standard orchestrator primitives (DaemonSet, sidecar).*

- Kubernetes DaemonSet deployment with auto-discovery of agent pods
- Container runtime integration (containerd, CRI-O) for automatic cgroup attachment
- Helm chart with per-namespace policy configuration
- Multi-tenant: different policies per namespace/pod label

### 13.4 Observability & Audit Trail

*As a compliance auditor, I can retrieve a complete, tamper-evident log of every enforcement decision made by NeuronTrace across all agents in my fleet.*

- Structured event export to OpenTelemetry / OTLP
- Append-only audit log with cryptographic chaining (hash chain)
- Grafana dashboard templates for violation rates, latency, generation drift
- Alert rules: generation stuck (agent not signaling boundaries), ring buffer drops, policy load failures

### 13.5 Agent SDK Integration

*As an agent framework developer, I can integrate NeuronTrace awareness directly into my SDK — so agents receive violation context natively without custom hook wiring.*

- Python SDK: `neurontrace-py` package for harness integration
- TypeScript SDK: `@neurontrace/sdk` for Node.js-based agents
- Protocol: lightweight gRPC or Unix socket with protobuf messages
- Auto-discovery: SDK finds the NeuronTrace socket via well-known path or env var
