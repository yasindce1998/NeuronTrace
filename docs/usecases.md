# Use Cases & Example Policies

Real-world scenarios for deploying NeuronTrace, with ready-to-use policy configurations.

---

## 1. CI/CD Pipeline Agent

**Situation:** You run an AI coding agent (Claude Code, Codex) inside CI to auto-fix linting errors, generate tests, or refactor code. The agent has access to your repo checkout but should never phone home, install packages, or touch files outside the workspace.

**Threat:** A prompt injection in a PR description causes the agent to exfiltrate secrets via `curl`, install a backdoor, or modify CI scripts.

```yaml
name: ci-pipeline-agent
description: Locked-down agent for CI/CD automated code tasks
rules:
  - event_type: open
    action: allow
    description: Read/write source files in workspace
  - event_type: rename
    action: allow
    description: Refactoring moves files
  - event_type: unlink
    action: audit
    description: Log deletions but allow (tests may clean temp files)
  - event_type: exec
    action: block
    description: No subprocess spawning — agent works through file I/O only
  - event_type: connect
    action: block
    description: No network access — prevents exfiltration
  - event_type: ptrace
    action: kill
    description: Immediate kill on debugger attachment attempt
```

**Why this works:** The agent can read and write code but cannot execute anything or reach the network. Even if prompt-injected, it has no channel to exfiltrate data.

---

## 2. Research Agent with Web Access

**Situation:** An agent browses documentation, APIs, and public datasets to compile research. It needs outbound HTTPS but should never modify the filesystem beyond its output directory or spawn processes.

**Threat:** The agent follows a malicious link that triggers a download-and-execute chain, or writes to system paths.

```yaml
name: research-agent
description: Web-enabled research agent with filesystem restrictions
rules:
  - event_type: connect
    action: allow
    description: Outbound connections for web research
  - event_type: open
    action: audit
    description: Log all file access — review for unexpected paths
  - event_type: exec
    action: block
    description: No shell commands
  - event_type: unlink
    action: block
    description: Cannot delete files
  - event_type: rename
    action: block
    description: Cannot move files
  - event_type: ptrace
    action: block
```

**Why this works:** Network is open for research, but the agent cannot execute downloaded payloads or tamper with the filesystem. Audit on `open` provides a trail for post-hoc review.

---

## 3. Multi-Tenant Shared Compute

**Situation:** Multiple AI agents from different users share a single Linux host. Each runs in its own cgroup. You want per-tenant isolation: Tenant A's agent cannot see Tenant B's files.

**Threat:** One agent escapes its cgroup or reads another tenant's data.

```yaml
name: tenant-alpha
description: Policy for Tenant Alpha's agent cgroup
rules:
  - event_type: open
    action: allow
    cgroup_id: 12345
    description: File access only within Tenant Alpha's cgroup
  - event_type: exec
    action: audit
    cgroup_id: 12345
    description: Log process spawning within this tenant
  - event_type: connect
    action: block
    cgroup_id: 12345
    description: No network for this tenant
  - event_type: unlink
    action: allow
    cgroup_id: 12345
  - event_type: rename
    action: allow
    cgroup_id: 12345
  - event_type: ptrace
    action: kill
    cgroup_id: 12345
    description: Kill on ptrace — prevents cross-process snooping
```

**Why this works:** Every rule is scoped to a specific `cgroup_id`. Processes outside that cgroup hit the default-deny baseline. Even if an agent somehow forks outside its cgroup, it gets blocked.

---

## 4. Autonomous Deployment Agent

**Situation:** An agent handles production deployments — it needs to execute scripts (`kubectl apply`, `docker push`) and reach the network, but should never modify source code or read secrets outside its designated paths.

**Threat:** The agent is tricked into running `rm -rf /` or reading `/etc/shadow`.

```yaml
name: deploy-agent
description: Deployment automation with exec and network, restricted file access
rules:
  - event_type: exec
    action: allow
    description: Must spawn kubectl, docker, helm
  - event_type: connect
    action: allow
    description: Needs network for registry and cluster API
  - event_type: open
    action: audit
    description: Audit all file reads — flag unexpected paths in review
  - event_type: unlink
    action: block
    description: Cannot delete files
  - event_type: rename
    action: block
    description: Cannot move files
  - event_type: ptrace
    action: kill
```

**Why this works:** Exec and network are necessary for deploys, so they're allowed. But file deletion/renaming is blocked (deploy agents write, not delete), and all file opens are audited for anomaly detection.

---

## 5. Coding Agent with Test Execution

**Situation:** An AI agent writes code and runs the test suite to verify its changes. It needs `exec` for running `cargo test` or `pytest`, filesystem access for source files, but no network (tests should be hermetic).

**Threat:** The agent installs malicious dependencies from PyPI/crates.io during the test run.

```yaml
name: code-and-test
description: Agent that writes code and runs local tests, no network
rules:
  - event_type: exec
    action: audit
    description: Allow exec for test runners, but log every invocation
  - event_type: open
    action: allow
    description: Full filesystem access for source and test files
  - event_type: unlink
    action: allow
    description: Tests may create and clean up temp files
  - event_type: rename
    action: allow
    description: Refactoring operations
  - event_type: connect
    action: block
    description: No network — tests run against local state only
  - event_type: ptrace
    action: block
```

**Why this works:** Exec is audited (not blocked) so you can review what commands ran. Network is blocked so `pip install` or `cargo add` from a compromised prompt fails. The audit trail on exec lets you verify the agent only ran test commands.

---

## 6. Data Pipeline Agent

**Situation:** An agent processes data files — parsing CSVs, transforming JSON, writing output. It never needs to execute programs or reach the network. Pure file I/O workload.

**Threat:** Malformed input data contains shell metacharacters that trigger command execution if the agent uses system() calls.

```yaml
name: data-pipeline
description: Pure file I/O agent, zero exec or network
rules:
  - event_type: open
    action: allow
    description: Read input, write output
  - event_type: rename
    action: allow
    description: Move processed files to output directory
  - event_type: unlink
    action: allow
    description: Clean up intermediate files
  - event_type: exec
    action: kill
    description: Immediately terminate on exec attempt — this agent should never spawn
  - event_type: connect
    action: kill
    description: Immediately terminate on network attempt — data stays local
  - event_type: ptrace
    action: kill
```

**Why this works:** The `kill` action on exec/connect means any exploitation attempt (shell injection via malformed data) terminates the process before damage spreads. This is stricter than `block` — the process doesn't survive to retry.

---

## 7. Interactive Chat Agent (Customer Support)

**Situation:** A customer-facing chatbot agent responds to user queries. It reads a knowledge base but should have near-zero system access. Runs in a minimal container.

**Threat:** Prompt injection from user messages attempts to make the agent access internal systems.

```yaml
name: chat-agent
description: Minimal permissions for a customer-facing chat agent
rules:
  - event_type: open
    action: audit
    description: Audit all file reads — should only touch knowledge base
  - event_type: exec
    action: kill
    description: No reason to ever exec — kill immediately
  - event_type: connect
    action: audit
    description: May need inference API call — audit all connections
  - event_type: unlink
    action: block
  - event_type: rename
    action: block
  - event_type: ptrace
    action: kill
```

**Why this works:** The agent's only legitimate action is reading its knowledge base and calling an inference API. Everything is audited or blocked. If a prompt injection causes unexpected behavior, the audit trail catches it immediately.

---

## 8. Red Team / Adversarial Testing

**Situation:** You're intentionally running an agent in adversarial mode to test your defenses. You want to see what it *tries* to do without actually letting it succeed.

**Threat:** N/A — you're testing the agent's behavior intentionally.

```yaml
name: honeypot
description: Audit everything, block nothing — observe adversarial behavior
rules:
  - event_type: exec
    action: audit
  - event_type: open
    action: audit
  - event_type: unlink
    action: audit
  - event_type: rename
    action: audit
  - event_type: connect
    action: audit
  - event_type: ptrace
    action: audit
```

**Why this works:** Every action succeeds but generates an event. You get a complete behavioral trace of what the agent attempts. Combine with generation-tagging to see how behavior changes across task boundaries.

---

## Choosing the Right Policy

| Scenario | Exec | Network | Files | Kill on |
|----------|------|---------|-------|---------|
| CI/CD pipeline | block | block | allow | ptrace |
| Research agent | block | allow | audit | — |
| Multi-tenant | audit | block | allow (cgroup-scoped) | ptrace |
| Deploy agent | allow | allow | audit | ptrace |
| Code + test | audit | block | allow | — |
| Data pipeline | kill | kill | allow | exec, connect |
| Chat agent | kill | audit | audit | exec, ptrace |
| Red team | audit | audit | audit | — |

## Combining with Generation Tagging

Any policy above becomes more powerful with generation tagging:

```bash
# Agent completes Task A
sudo ./target/release/neurontrace bump

# Now Task B starts — any labels from Task A are stale
# If the agent tries to use Task A's context for Task B, the kernel blocks it
```

This adds cross-task isolation on top of per-syscall policy. The policy defines *what* is allowed; generations define *when* those permissions are valid.
