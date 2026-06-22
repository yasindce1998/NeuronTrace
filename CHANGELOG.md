# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- BPF-LSM enforcement engine with 6 hooks: exec, file_open, inode_unlink, inode_rename, socket_connect, ptrace_access_check
- Default-deny policy model — no rule means blocked
- Generation-tagging system for task-boundary isolation
- YAML policy format with validation command
- Starter policy packs for Claude Code, Codex, and generic agents
- Cgroup-scoped enforcement targeting only agent process trees
- Ring buffer event pipeline for violation reporting
- PID allowlist for controller self-exemption
- Self-protection: BPF pinning to `/sys/fs/bpf/neurontrace/` — enforcement persists if userspace process dies
- Self-protection: `task_kill` LSM hook — blocks signals from inside cgroup targeting external PIDs
- CLI with `run`, `validate`, `bump`, and `unload` commands
- Single-command demo script (`scripts/demo.sh`)
- Architecture documentation and development guide

[Unreleased]: https://github.com/yasindce1998/NeuronTrace/compare/main...HEAD
