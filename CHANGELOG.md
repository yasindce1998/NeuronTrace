# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Structured JSON feedback delivery via Unix socket or JSONL file
- `--audit-only` mode for observing agent behavior without blocking
- CLI with `run`, `validate`, `bump`, `unload`, and `status` commands
- Single-command demo script (`scripts/demo.sh`)
- Unit tests for policy parsing and glob matching
- GitHub Actions release workflow for pre-built binaries (x86_64 + aarch64)
- Architecture documentation, development guide, and quickstart

### Fixed

- BPF stack overflow in all hooks — eliminated intermediate 256-byte buffers by writing directly into ring buffer

[Unreleased]: https://github.com/yasindce1998/NeuronTrace/compare/main...HEAD
