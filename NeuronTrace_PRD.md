# NeuronTrace
### Kernel-Level Behavioral Containment for AI Agents

**Product Requirements Document** · Dual-Mode Enforcement Architecture · June 2026

| | |
|---|---|
| **Author** | Yasin · yasindce1998 |
| **Status** | Draft for review |
| **Related projects** | Warmor (eBPF+WASM cross-platform runtime security policy engine) — NeuronTrace is intentionally a separate repository, not a Warmor module. |

---

## Table of Contents

1. [Summary](#1-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Competitive Context](#4-competitive-context)
5. [Kernel Mode (Default Backend)](#5-kernel-mode-default-backend)
6. [Generation-Tagged Mode (Near-Free Upgrade to Kernel Mode)](#6-generation-tagged-mode-near-free-upgrade-to-kernel-mode)
7. [Graph Mode (Opt-In Backend)](#7-graph-mode-opt-in-backend)
8. [Open Questions](#8-open-questions)

---

## 1. Summary

NeuronTrace is a kernel-level (eBPF) behavioral containment tool for autonomous AI agents and coding harnesses (e.g. Claude Code, Codex). It addresses the core weakness of prompt-level and sandbox-level guardrails: they constrain what a model is told to do, not what it is technically able to do. Prompt injection defeats instruction-following defenses by design — the only durable control point is what the agent's underlying process can actually touch on the system.

NeuronTrace enforces process, filesystem, and network access at the syscall boundary, independent of what the model "decides," and feeds violation context back into the agent's own hook system so it can self-correct rather than simply dying mid-task.

NeuronTrace ships as a single binary with three enforcement tiers, selected by a runtime flag rather than by version. Each tier answers a different question, at a different cost:

- **Kernel mode** (default, `--enforcement=kernel`) — "is this specific action allowed?" Fast, inline, syscall-pattern matching compiled into the BPF program. No userspace round trip for gated decisions.
- **Generation-tagged mode** (`--enforcement=kernel --task-scoping=on`) — "is this data from the current task, or a stale one?" A lightweight extension of kernel mode: labels are stamped with a task/turn generation counter, and a single integer comparison detects cross-task reuse. Still entirely kernel-resident; no userspace round trip.
- **Graph mode** (`--enforcement=graph`, opt-in) — "did data flow from A to B through any path, ever?" Kernel emits events only; matching, scoped labels, and graph-assertion rules run in a userspace engine. Answers general data-flow reachability questions the other two tiers structurally cannot, at the cost of added per-decision latency and a larger trust boundary.

> This is a deliberate, disclosed cost ladder, not a staged migration: higher tiers do not replace lower ones. Most users should never need to leave kernel mode. Generation-tagging is offered as a near-free upgrade for long-running, multi-task agent sessions. Full graph mode is reserved for users who specifically need multi-hop data-flow path queries, confirmed against real usage rather than assumed upfront.

---

## 2. Problem Statement

Agentic AI is moving from a novelty to a default mode of interacting with software. Every team running an autonomous coding agent, support agent, or research agent inherits the same risk: a sufficiently crafted input (a webpage, a file, a tool result) can redirect the agent's behavior in ways no system prompt anticipated.

Existing mitigations operate at the wrong layer:

- **Prompt-level guardrails** (system prompts, instructions, refusal training) — bypassable by definition, since the attack is a successful instruction, not a malformed one.
- **Sandbox/approval UX** (human-in-the-loop confirmation dialogs) — too slow for autonomous, long-running agent sessions and frequently bypassed via alert fatigue.
- **Application-level allowlists** (tool-calling restrictions inside the harness) — enforced by the same process that can be manipulated; not a trust boundary.

The only control point that holds regardless of what the model is convinced to do is the kernel boundary: what the underlying OS process is actually permitted to execute, read, write, or connect to. NeuronTrace's thesis is that you cannot reliably control what an AI decides — but you can control what it is able to access.

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. Provide kernel-enforced containment for AI agent processes that is independent of the agent's own cooperation.
2. Ship a default (kernel-mode) experience that is deployable by a non-kernel-expert in minutes, with a safe default (audit-mode-first) onboarding path.
3. Feed structured, machine-readable violation context back into the agent's own hook system so it can self-correct without a human in the loop for routine cases.
4. Outperform comparable existing tools (notably ActPlane) on deployability, stability, and real-world syscall coverage relevant to prompt-injection attack patterns (e.g. curl-pipe-sh, credential exfiltration, cross-task data leakage).
5. Offer a near-zero-cost generation-tagged tier for task-boundary scoping before reaching for a full graph engine, validating whether it covers most real cross-task leakage cases on its own.
6. Offer an opt-in graph-mode backend for general multi-hop data-flow path queries — a class of constraint neither flat taint nor generation-tagging can express — without forcing that cost onto users who don't need it.

### 3.2 Non-Goals

- Not a general-purpose runtime security policy engine (that is Warmor's scope). NeuronTrace stays deliberately narrow to the AI-agent-harness niche.
- Not a replacement for prompt-level safety training or sandboxing — NeuronTrace is a complementary, lower-layer control, not a substitute for upper-layer defenses.
- No Windows or macOS enforcement backend (Linux/eBPF only). Cross-platform is an explicit future consideration, not a near-term commitment.
- No general process-lineage observability product (e.g. an AgentSight competitor) — agents are the workload, not one example among many.
- Graph mode is not intended to become the default — it is an opt-in cost users accept deliberately, not a planned replacement for kernel mode.

---

## 4. Competitive Context

ActPlane (eunomia-bpf) is the closest existing project: a Rust+aya eBPF tool that hooks fork/exec/exit/open/unlink/rename/connect, propagates labels across process/file/network nodes, and enforces kill/block/audit effects via a kernel-compiled rule DSL, with violation reasons fed back into agent hooks. It is early-stage (v0.0.9, single-digit GitHub stars) but technically credible, with working end-to-end tests.

NeuronTrace's differentiation is deliberate, not cosmetic:

| Dimension | ActPlane | NeuronTrace |
|---|---|---|
| Where matching happens | Kernel — rules compiled into BPF bytecode | Kernel + gen-tagged tiers: kernel. Graph mode (opt-in): userspace |
| Label model | Flat, permanent taint set | Kernel: flat, capped. Gen-tagged: flat + generation stamp. Graph: typed, scoped, decaying |
| Can express cross-task data leakage (boundary-recency) | No | Yes, at kernel speed, via generation-tagging |
| Can express multi-hop data-flow (arbitrary path) | No | No in kernel/gen-tagged tiers (by design) — Yes in graph mode only |
| Effects | kill / block / audit | kill / block / audit in all tiers; graph mode adds `defer` (human-in-the-loop) |
| Platform | Linux only | Linux only; cross-platform explicitly out of scope for now |
| Violation feedback | Human-readable reason string | Structured JSON with `kind` + `severity` + `suggested_retry` |
| Mode selection | N/A — single architecture | Single binary, runtime flags; kernel mode is default, others opt-in |

> ActPlane has one tier: fast, kernel-resident, flat taint. It cannot distinguish "data is stale from a past task" from "data is current," and it cannot answer multi-hop reachability questions at all. NeuronTrace's three tiers are an explicit cost ladder addressing exactly these two gaps separately, so neither gap forces the cost of the other: task-boundary recency is solved in-kernel at near-zero cost (generation-tagging), and only genuine multi-hop path queries pay the graph-mode tax.

---

## 5. Kernel Mode (Default Backend)

### 5.1 Scope

A kernel-side, syscall-pattern enforcement backend: default-deny allowlists, fast inline decisions, no userspace round-trip for the common case. Optimized for time-to-first-demo, real-world prompt-injection coverage, and zero-friction onboarding. This is the default backend — most users should never need to touch the mode flag.

### 5.2 Use Case

Stopping a specific, anticipatable action regardless of why the agent decided to take it: reading a credential file, exec-ing curl piped to a shell, connecting to an unapproved endpoint, spawning an unexpected child process. This is the actual 2026 threat model — prompt injection mostly manifests as an otherwise-ordinary action taken without authorization, not a subtle multi-step data-flow chain. A single syscall-pattern rule, matched in-kernel, catches the overwhelming majority of real injection outcomes without needing any notion of tasks, generations, or graphs at all.

### 5.3 Kernel Hooks

- fork / exec / exit
- open / unlink / rename
- connect (socket-level, not just initial connect)
- **ptrace** — added beyond ActPlane's hook set; covers process-injection and tracing-evasion attempts.
- **execve argv/envp capture** — full argument and environment capture (gated behind a binary watchlist for cost control), enabling rules against real attack shapes such as curl-pipe-to-shell and environment-variable exfiltration, which path-only matching cannot detect.

### 5.4 Label Model

Flat label set per process/file/network node (taint-style), matching ActPlane's model. Capped at a fixed maximum size per process to bound fork-time copy cost and to force an early architectural seam toward graph mode's scoped/TTL model.

### 5.5 Rule Language

Syscall-pattern matching, default-deny with explicit allowlists per task scope (an improvement on ActPlane's denylist-first model — unanticipated actions are blocked by default rather than requiring a rule to be written in advance):

```yaml
scope: task-current
default: deny
allow:
  exec: ["/usr/bin/git", "/usr/bin/python3"]
  connect: ["api.github.com:443"]
```

### 5.6 Effects

- **kill** — hard stop of the process tree
- **block** — BPF-LSM pre-commit denial (EPERM)
- **audit** — logged, allowed through (default mode for first-run onboarding)

### 5.7 Feedback Loop

Structured JSON violation payloads delivered to the agent's PostToolUse / PostToolUseFailure hooks (Claude Code, Codex), including a severity/confidence field and a `suggested_retry` hint — enabling the agent to distinguish a low-severity correction from a high-severity violation that should escalate or terminate rather than retry indefinitely.

### 5.8 Performance Requirements

- Label storage in `BPF_MAP_TYPE_LRU_HASH` with automatic eviction; hooks attached at cgroup scope (not system-wide) so non-agent processes never enter the BPF program.
- Argv/envp reads capped in length and gated behind a binary watchlist check, not performed unconditionally on every exec.
- Ring buffer sized generously (256KB–1MB, configurable) with explicit drop-count instrumentation surfaced to the CLI.
- Audit-only rules never enter a userspace round trip; only kill/block effects gate the syscall return path.
- Benchmarked explicitly against: exec-heavy workloads (build/install), ring-buffer drop rate under high syscall volume, and cgroup-scoped vs. system-wide attach overhead.

### 5.9 Stability Requirements

- Defined, configurable fail-safe behavior on userspace crash (loud fail-open by default, with stderr/syslog warning; fail-closed configurable).
- Verifier compatibility tested against the actual minimum supported kernel version, not just the development kernel.
- Clean BPF program detachment on exit/signal — no orphaned pinned programs enforcing stale rules after the controller process ends.
- Correct behavior across PID namespaces / containers (resolve to host PID or cgroup ID consistently) — tested explicitly, since most real agent harnesses run sandboxed.
- Rule matching resolves symlinks and handles non-obvious exec paths (via `/usr/bin/env`, statically-linked binaries, shell builtins).

### 5.10 Deployability / UX Requirements

- Single static binary install (`cargo install neurontrace`), CO-RE prebuilt BPF objects, no clang/libbpf required at runtime.
- Starter policy packs shipped in-binary for major harnesses (Claude Code, Codex, generic shell agent) — zero rule-writing required for first run.
- Audit-only mode as the default first-run experience, not an opt-in flag.
- Live CLI status indicator during operation (e.g. syscalls observed / violations count) rather than a silent background process.
- **`--explain` mode** — given a rule file and a hypothetical syscall, statically reports which rule would match and why, without executing anything.

### 5.11 Success Criteria

1. End-to-end demo: an agent attempting a real prompt-injection pattern (e.g. curl-pipe-to-shell, credential file read) is blocked, with a structured violation reason fed back to the harness.
2. Cold start and per-syscall overhead benchmarked and published; cgroup-scoped attach measured against system-wide as a documented comparison.
3. Verified working inside at least one containerized/sandboxed agent harness configuration, not only on bare metal.
4. No silent event drops under a synthetic high-syscall-rate test session (or drops are surfaced, not silent).

---

## 6. Generation-Tagged Mode (Near-Free Upgrade to Kernel Mode)

### 6.1 Scope

An extension of kernel mode, not a separate backend: enable with `--task-scoping=on` alongside `--enforcement=kernel`. No userspace component, no new BPF program variant, no graph engine. Adds exactly one capability: detecting when labeled data is being used outside the task it was created in.

### 6.2 Use Case

Stopping data read under one task from being used in an action under a different task, within a single long-running agent process handling a sequence of distinct jobs (different tickets, different users, different repos) without restarting.

Concrete scenario: the agent reads a file scoped to Task A; the harness signals a task boundary; the agent moves to Task B; the agent (or an injected instruction riding along in carried-forward context) tries to use Task A's data in a Task B action. Generation-tagging catches this because it is fundamentally a recency check, not a true data-flow trace — "is this label current or stale" rather than "how did this data get here."

### 6.3 Mechanism

1. The harness writes one integer to a BPF map at each task/turn boundary it defines: `current_generation += 1`.
2. Every label created (on file/process/network nodes) is stamped with the generation active at creation time.
3. Rules compare the label's stamp to the current generation: `deny if label exists AND label.generation != current_generation`.
4. No label is ever deleted by this mechanism — it simply becomes irrelevant once the generation moves on, and ages out naturally under the same LRU eviction policy already used for kernel-mode label maps.

### 6.4 Performance Profile

Effectively free on the hot path: one extra integer load and compare per label check, on top of a lookup kernel mode already performs. The generation increment itself happens once per task boundary, not per syscall, so it does not scale with syscall volume. It rides entirely on infrastructure (capped label maps, LRU eviction) already required for kernel mode — there is no new performance investment here, only a correctness one.

### 6.5 Honest Limits

- Answers only "current vs. stale," not "which path did this data travel." Cannot detect a secret that passed through several intermediate tool calls before landing somewhere — that is a multi-hop reachability question, which only graph mode answers.
- Provides no benefit in a single-task session — with only one generation, the comparison never has anything to be stale against.
- Correctness depends entirely on the harness signaling task boundaries accurately. A missed or ambiguous boundary signal (e.g. does a sub-agent spawn count as a new task?) produces either false negatives (stale data treated as current) or false positives (legitimate continuity blocked) — this is a design risk, not a performance risk, and must be validated against real harness behavior before relying on it.

### 6.6 Why This Tier Exists Separately From Graph Mode

Building this as a standalone, kernel-resident tier — rather than folding task-scoping into graph mode by default — means the most common real-world cross-task leakage shape is solved without paying graph mode's latency or trust-boundary cost. Graph mode is reserved for the narrower set of cases that are genuinely about multi-hop reachability, not recency, which real usage data (once kernel mode and this tier are live) should be used to confirm before further investing in the graph engine.

---

## 7. Graph Mode (Opt-In Backend)

### 7.1 Scope

Graph mode is the architectural alternative users explicitly opt into via a runtime flag. Unlike the naive "hold a syscall in-kernel waiting for userspace" approach (which risks deadlocks and kernel thread exhaustion), NeuronTrace uses a **split-decision architecture**: the BPF program still makes synchronous, sub-microsecond decisions using a verdict cache populated asynchronously by the userspace graph engine. The graph engine runs ahead of the agent, predicting and pre-caching deny verdicts before the dangerous syscall is even attempted.

This trades the simplicity of kernel-only matching for unbounded rule expressiveness — a deliberate, disclosed trade-off, not a future default.

### 7.2 Use Case

Answering multi-hop data-flow reachability questions: did data originating at node A reach node C through any chain of intermediate processes, files, or connections, regardless of task boundaries? This is a strictly harder question than generation-tagging's recency check (Section 6) — generation-tagging tells you whether a label is from the current task, but cannot trace whether a secret passed through several intermediate tool calls before surfacing somewhere unexpected. Graph mode is the only tier that can express that path.

### 7.3 Mode Selection Mechanics

NeuronTrace ships as a single binary. The enforcement backend is selected at launch via a CLI flag, not a build-time choice or a separate package:

```bash
neurontrace run claude -p "..." --enforcement=kernel                      # default
neurontrace run claude -p "..." --enforcement=kernel --task-scoping=on    # gen-tagged
neurontrace run claude -p "..." --enforcement=graph                       # opt-in
```

- Each mode loads a distinct BPF program variant. Kernel mode's program (with or without task-scoping) contains compiled rule-matching logic; graph mode's program performs label checks, generation-tag checks, AND verdict-cache lookups — then emits structured events to the ring buffer for graph-engine consumption. They are not the same program with an internal branch — combining all code paths into a single BPF program would defeat the verifier-simplicity and attack-surface benefits kernel mode exists for.
- **Rule compatibility:** flat-taint and generation-tagged rules written for kernel mode remain valid under graph mode without rewriting, since they are a strict subset of what graph assertions can express. New graph-assertion syntax (scoped labels, path queries, defer) is additive and only available when graph mode is active — switching modes never silently breaks an existing rule file.
- The CLI surfaces which mode is active in its status output at all times, so a user auditing logs later can tell which guarantees were in force during a given session.

### 7.4 Split-Decision Architecture

The core design principle: **never hold a syscall in-kernel waiting for userspace**. Instead, use a verdict cache with configurable miss policies.

#### 7.4.1 Fast Path (BPF, synchronous, <1μs)

```
┌─────────────────────────────────────────────────────┐
│  BPF LSM Hook (synchronous, <1μs)                   │
│                                                      │
│  1. Label check         (kernel mode rules)          │
│  2. Generation-tag check (if task-scoping enabled)   │
│  3. Verdict cache lookup (BPF_MAP_TYPE_LRU_HASH)     │
│     - HIT + ALLOW → allow                           │
│     - HIT + DENY  → deny (return -EPERM)            │
│     - HIT + DEFER → send SIGSTOP to process tree    │
│     - MISS        → apply default_on_miss policy    │
│  4. Emit event to ring buffer (always, for graph)    │
└─────────────────────────────────────────────────────┘
```

The `default_on_miss` policy is configurable per-rule:

- **`deny-on-miss`** — for high-risk actions (credential reads, network connects to unknown hosts, unlink of critical paths). Blocks first; if the graph engine later determines it was safe, the verdict cache is updated and the next identical attempt succeeds.
- **`allow-on-miss`** — for low-risk actions where async analysis is acceptable (reading non-sensitive files, spawning allowlisted binaries).
- **`defer-on-miss`** — for ambiguous actions requiring human approval (see Section 7.6).

#### 7.4.2 Slow Path (Userspace Graph Engine, asynchronous, 1–50ms)

```
┌──────────────────────────────────────────────────────┐
│  Userspace Graph Engine (async, 1-50ms)              │
│                                                       │
│  1. Consume ring buffer events                        │
│  2. Update data-flow graph (nodes, edges, labels)     │
│  3. Evaluate graph assertions against new state       │
│  4. Write verdicts to BPF verdict_cache map           │
│  5. Predictive warming (see 7.4.3)                    │
│  6. On violation: emit feedback to agent hooks        │
│  7. On defer: send notification, manage approval      │
└──────────────────────────────────────────────────────┘
```

#### 7.4.3 Verdict Cache Warming (Predictive Enforcement)

The graph engine does not merely react to events — it **predicts and pre-denies**. When it observes the agent read a secret-labeled file, it immediately writes deny verdicts into the BPF map for all network `connect()` targets not in the current allowlist. By the time the agent attempts exfiltration, the verdict is already cached — the syscall hits the BPF map, gets denied in-kernel, with zero userspace round-trip.

This is the key performance insight: **graph mode's latency is amortized, not inline**. The first novel action pattern pays the cache-miss cost (handled by `default_on_miss`); all subsequent identical patterns hit the pre-warmed cache at kernel speed.

Warming strategies:
- **On secret read**: pre-deny all non-allowlisted network destinations
- **On untrusted data ingest**: pre-deny exec of interpreters (curl|sh, python -c, etc.)
- **On task boundary**: invalidate stale verdicts from previous task scope
- **On graph assertion violation**: pre-deny the full exfiltration path (all intermediate nodes)

#### 7.4.4 Full Architecture Diagram

```
                    ┌─────────────────────────┐
                    │   Agent Process Tree     │
                    │   (Claude Code, etc.)    │
                    └────────────┬────────────┘
                                 │ syscalls
                    ┌────────────▼────────────┐
                    │  BPF LSM Hooks          │
                    │  ┌───────────────────┐  │
                    │  │ 1. Label check    │  │  ← kernel mode (always runs)
                    │  │ 2. Gen-tag check  │  │  ← if --task-scoping=on
                    │  │ 3. Verdict cache  │  │  ← graph mode cache lookup
                    │  │ 4. Default action │  │  ← deny/allow/defer on miss
                    │  └───────┬───────────┘  │
                    │          │ event         │
                    └──────────┼──────────────┘
                               │ ring buffer
                    ┌──────────▼──────────────┐
                    │  Userspace Graph Engine  │
                    │  ┌───────────────────┐  │
                    │  │  Event Ingest     │  │
                    │  │       │           │  │
                    │  │  Graph Update     │  │  ← maintains full data-flow DAG
                    │  │       │           │  │
                    │  │  Assert Eval      │  │  ← path queries, reachability
                    │  │       │           │  │
                    │  │  Verdict Write    │──┼──→ BPF verdict_cache map (writeback)
                    │  │       │           │  │
                    │  │  Predictive Warm  │──┼──→ BPF verdict_cache map (pre-deny)
                    │  │       │           │  │
                    │  │  Feedback/Notify  │──┼──→ Agent hooks / Slack / SIGSTOP
                    │  └───────────────────┘  │
                    └─────────────────────────┘
```

### 7.5 Label Model

Typed, scoped labels, available only in graph mode:

```rust
struct Label {
    origin: NodeId,
    kind: LabelKind,        // Secret | TaskScope(id) | Untrusted | ToolOutput
    ttl: Option<Generation>, // expires at a task/turn boundary
}
```

### 7.6 Rule Language

Graph assertions over label-flow paths, not just syscall-pattern matching:

```yaml
contract: no-secret-exfil-via-any-path
assert:
  not exists path(label: Secret -> label: Untrusted)
effect: deny
default_on_miss: deny   # block immediately if verdict not cached

contract: sensitive-delete-requires-approval
assert:
  not (action: unlink AND path matches "/critical/**")
effect: defer
timeout: 60s
escalation: slack
```

### 7.7 The `defer` Effect — Process Freezing, Not Syscall Holding

A fourth effect alongside kill/block/audit. **Critical design decision:** `defer` does NOT hold a syscall inside a BPF-LSM hook waiting for userspace. Instead, it uses POSIX process signals:

```
1. BPF sees action matching a `defer` rule (or verdict cache returns DEFER)
2. BPF returns -EPERM (denies the specific syscall)
3. BPF sends SIGSTOP to the process (freezes entire process tree)
4. BPF emits event to ring buffer with defer flag
5. Userspace picks it up → sends Slack/webhook/CLI notification
6. Human approves → userspace sends SIGCONT + updates verdict cache to ALLOW
7. Human denies (or timeout expires) → userspace sends SIGKILL
```

**Why this is safe:**
- No kernel thread blocked waiting for userspace — the LSM hook returns immediately with -EPERM
- Process is frozen at user-space level (standard POSIX signal), visible via `ps aux | grep T`
- If NeuronTrace crashes, the frozen process remains in stopped state — a human can manually `kill -CONT <pid>` to recover. No invisible deadlock, no orphaned kernel state.
- Timeout is a simple userspace timer, not a BPF helper with verifier constraints
- The denied syscall can be retried by the agent after SIGCONT (the agent sees EPERM + a structured feedback message explaining the hold)

**Limitation:** `defer` denies-then-freezes, meaning the triggering action was already blocked. For actions where you want "allow after approval," use a two-step pattern: first attempt is denied with a `defer` hold, approval updates the verdict cache to ALLOW, agent retries and succeeds on the cache hit.

### 7.8 Flagship Demo

A multi-hop secret-exfiltration scenario: a credential read at one point in a session passes through two or three intermediate tool calls before an attempt to send it over the network.

1. Agent reads `~/.ssh/id_rsa` → graph engine labels the process tree with `Secret(origin=ssh_key)`
2. Agent writes content to `/tmp/scratch.txt` → label propagates to file node
3. Agent spawns `curl` reading from `/tmp/scratch.txt` → label propagates to curl process
4. `curl` calls `connect("attacker.com:443")` → **verdict cache already contains DENY** (pre-warmed at step 1 for all non-allowlisted destinations)
5. BPF denies inline, no userspace round-trip needed for the actual block

This is a violation class that ActPlane, NeuronTrace's kernel mode, and even generation-tagging cannot structurally express, since none of them trace paths through intermediate nodes — only graph mode can. The predictive cache warming means the block still happens at kernel speed despite being a graph-mode decision.

### 7.9 Fail-Safe Behavior

| Scenario | Behavior |
|---|---|
| Userspace engine crashes | BPF continues enforcing stale verdict cache (conservative: deny entries persist, allow entries age out via LRU). Kernel-mode and gen-tag rules continue independently. Loud warning emitted to stderr/syslog. |
| Verdict cache full (LRU eviction) | Oldest entries evicted; new actions hit `default_on_miss` policy. Deny-on-miss rules remain safe; allow-on-miss rules degrade to kernel-mode-only protection. |
| Ring buffer overflow (events dropped) | Graph state becomes stale — may miss label propagation. Mitigated by: (a) generous ring buffer sizing (1MB+), (b) drop-count metric surfaced to CLI, (c) conservative defaults on cache miss. |
| Agent retries after EPERM | Expected behavior. If verdict cache hasn't changed, retry is denied again. If approval granted (defer) or graph state updated (false positive), retry succeeds. |

### 7.10 Disclosed Costs (Documentation Requirement)

Because graph mode is opt-in rather than default, its costs must be stated plainly in user-facing documentation, not just in this PRD:

- **Amortized latency, not zero latency:** The first occurrence of a novel action pattern pays the cache-miss cost (governed by `default_on_miss`). Subsequent identical patterns hit the cache at kernel speed. Published benchmarks must compare: kernel mode (baseline), generation-tagged (near-zero overhead), graph mode cache-hit (near kernel speed), graph mode cache-miss (default_on_miss latency).
- **Larger trust boundary:** A persistent userspace process making security decisions is a bigger attack surface than kernel-only matching. The kernel↔userspace writeback channel (BPF map updates) needs explicit hardening — a compromised graph engine could write ALLOW verdicts into the cache. Mitigation: the BPF program validates verdict entries against a signed rule fingerprint before accepting them.
- **Higher resource footprint:** Persistent userspace process maintaining live graph state per traced process tree. Memory grows with graph complexity (number of nodes, edges, labels tracked). Bounded by configurable graph-size limits with oldest-edge eviction.
- **Predictive warming is heuristic:** Pre-denied verdicts may produce false positives (legitimate network calls denied because a secret was read earlier). Users must tune allowlists or switch specific rules to `allow-on-miss` when false positive rate is unacceptable.

### 7.11 Open Risks

- Validate against real agent traces before promoting graph mode beyond opt-in status: if generation-tagging (Section 6) turns out to cover the large majority of real cross-task violations, graph mode's marginal benefit narrows to genuinely rare multi-hop cases — worth confirming empirically before further investment.
- Avoid feature creep that quietly makes graph mode the only fully-supported path — kernel mode and generation-tagging must remain first-class, equally maintained tiers, not legacy fallbacks.
- The verdict-cache writeback path (userspace writing to BPF maps) is a privilege escalation vector if the graph engine process is compromised. Hardening options: (a) dedicated unprivileged helper that only accepts signed verdict structs, (b) BPF-side validation of a rule-fingerprint field in each verdict entry, (c) rate-limiting map updates to prevent cache-flooding attacks.

---

## 8. Open Questions

1. Should NeuronTrace's policy distribution eventually adopt an OCI-based model (as Warmor does), or stay file-based given its narrower scope?
2. At what point (if any) does cross-platform support become a real requirement, given most individual agent usage happens on developer laptops including macOS?
3. Should graph mode be validated with a research-style empirical study of real agent violation logs (gathered from kernel-mode usage) before investing further engineering time in it?
4. What telemetry, if any, should the CLI collect on mode usage (kernel vs. graph) to inform whether graph mode's cost is justified for the user base, without compromising user privacy?
5. Is there a future integration path with Warmor (e.g. NeuronTrace as an "agent mode" profile) once both have matured, without compromising NeuronTrace's current architectural independence?
