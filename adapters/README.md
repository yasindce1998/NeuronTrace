# Agent Adapters

Thin install scripts that wire NeuronTrace's agent-agnostic feedback protocol into specific agent frameworks.

## How it works

```
NeuronTrace (JSONL) → adapter hook script → agent sees violation context
```

NeuronTrace emits structured JSONL (see [docs/feedback-protocol.md](../docs/feedback-protocol.md)). Each adapter is a small shell script that reads the last violation and formats it for the agent's hook system.

## Available Adapters

| Agent | Install |
|-------|---------|
| Claude Code | `bash adapters/claude-code/install.sh` |
| Codex | `bash adapters/codex/install.sh` |
| Gemini CLI | `bash adapters/gemini/install.sh` |
| Generic (any agent) | `bash adapters/generic/neurontrace-watch.sh` |

## Writing a new adapter

An adapter only needs to:

1. Read the JSONL feedback file (default: `/run/neurontrace/feedback.jsonl`)
2. Extract the last violation
3. Print a one-line summary that the agent will see

That's it — usually 5-10 lines of shell. See `generic/neurontrace-watch.sh` for the pattern.

## No agent? No problem

Use `--feedback-stdout` and pipe NeuronTrace output directly:

```bash
sudo neurontrace run --policy policy.yaml --cgroup /sys/fs/cgroup/agent --feedback-stdout | your-agent
```
