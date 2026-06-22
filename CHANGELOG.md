# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-22

### Added

- BPF-LSM enforcement engine with 7 hooks: exec, file_open, inode_unlink, inode_rename, socket_connect, ptrace_access_check, task_kill
- Default-deny policy model — no rule means blocked
- Generation-tagging system for task-boundary isolation
- YAML policy format with validation command
- Path/glob filtering in policy rules (`path` and `argv` fields with globset patterns)
- Starter policy packs for Claude Code, Codex, and generic agents (with path-specific rules)
- Cgroup-scoped enforcement targeting only agent process trees
- Ring buffer event pipeline for violation reporting
- PID allowlist for controller self-exemption
- Self-protection: BPF pinning to `/sys/fs/bpf/neurontrace/` — enforcement persists if userspace process dies
- Self-protection: `task_kill` LSM hook — blocks signals from inside cgroup targeting external PIDs
- Path/argv extraction from LSM context into events
- Structured JSON feedback delivery via Unix socket, JSONL file, or stdout (`--feedback-stdout`)
- Feedback protocol v1 with `version`, `timestamp_ns`, and `pid` fields for agent-agnostic consumption
- Feedback protocol specification (`docs/feedback-protocol.md`)
- `--audit-only` mode for observing agent behavior without blocking
- CLI with `run`, `validate`, `bump`, `unload`, and `status` commands
- `--dry-run` flag for `run` command — validates config and policy without root or BPF loading
- Config resolution: CLI flags → env vars (`NEURONTRACE_POLICY`, `NEURONTRACE_CGROUP`, `NEURONTRACE_FEEDBACK`) → `/etc/neurontrace/config.yaml` → defaults
- Graceful shutdown via Ctrl+C (BPF programs remain pinned for continued enforcement)
- Single-command demo script (`scripts/demo.sh`)
- Unit tests for policy parsing, glob matching, and config resolution
- GitHub Actions release workflow for pre-built binaries (x86_64 + aarch64)
- Agent adapter scripts for Claude Code, Codex, Gemini CLI, and generic fallback
- Architecture documentation, development guide, and quickstart

### Fixed

- BPF stack overflow in all hooks — eliminated intermediate 256-byte buffers by writing directly into ring buffer

[0.1.0]: https://github.com/yasindce1998/NeuronTrace/commits/v0.1.0
