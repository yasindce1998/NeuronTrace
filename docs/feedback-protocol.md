# Feedback Protocol Specification

NeuronTrace emits structured violation events so that any agent — regardless of language, framework, or runtime — can react to policy enforcement in real time.

## Design Principles

- **Agent-agnostic**: No dependency on any agent framework. Any process that can read JSONL from a Unix socket, file, or stdout can consume feedback.
- **Language-neutral**: JSON over byte streams. No protobuf, no gRPC, no shared-memory requirement.
- **Zero-config consumption**: Agents can read `stdout` with `--feedback-stdout`, or tail a JSONL file — no client library needed.

## Transport

NeuronTrace delivers feedback through one of three channels (in priority order):

| Transport | Flag | When to use |
|-----------|------|-------------|
| Unix socket | `--feedback /path/to.sock` | Production: agent connects a listener socket, NeuronTrace writes to it |
| JSONL file | `--feedback /path/to/file` | When no socket listener exists, NeuronTrace appends to `<path>.jsonl` |
| Stdout | `--feedback-stdout` | Piped agents that read their parent's stdout (simplest integration) |

### Unix Socket

NeuronTrace connects as a **client** to the socket path. The agent (or a sidecar) must listen on that path before NeuronTrace starts. Each violation is one newline-terminated JSON object written to the stream.

If connection fails, NeuronTrace falls back to file output automatically.

### JSONL File

Each line is a self-contained JSON object. The file is opened in append mode so multiple NeuronTrace restarts don't overwrite history. Agents can tail the file with `tail -f` or poll on inotify.

### Stdout

With `--feedback-stdout`, violation JSON lines are written to NeuronTrace's stdout. This is ideal for agents that spawn NeuronTrace as a subprocess and read its output directly. Log messages go to stderr via `tracing`, keeping stdout clean for structured data only.

## Schema (v1)

```json
{
  "version": 1,
  "kind": "violation",
  "timestamp_ns": 1719043200000000000,
  "pid": 12345,
  "hook": "exec",
  "target": "/usr/bin/curl",
  "effect": "blocked",
  "rule": "default-deny:exec",
  "severity": "high",
  "suggested_retry": true,
  "message": "Operation 'exec' was blocked by NeuronTrace policy. Check your allowed operations."
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `version` | `u8` | Protocol version (currently `1`). Consumers should check this and ignore unknown versions. |
| `kind` | `string` | Event category. Currently always `"violation"`. Future: `"audit"`, `"generation_bump"`. |
| `timestamp_ns` | `u64` | Kernel timestamp in nanoseconds (from `bpf_ktime_get_ns`). Monotonic, not wall-clock. |
| `pid` | `u32` | PID of the process that triggered the violation. |
| `hook` | `string` | LSM hook that fired: `exec`, `open`, `unlink`, `rename`, `connect`, `ptrace`, `fork`, `exit`, `task_kill`. |
| `target` | `string` | What was being accessed — a file path, network address (`1.2.3.4:443`), or `pid:<N>` for signals. |
| `effect` | `string` | Enforcement action taken: `blocked`, `process_killed`, `audited`, `allowed`. |
| `rule` | `string` | Which policy rule matched (format: `<rule-source>:<event-type>`). |
| `severity` | `string` | One of: `low`, `medium`, `high`, `critical`. Derived from the enforcement action. |
| `suggested_retry` | `bool` | `true` if the agent should retry with a different approach (e.g., blocked exec → try a different binary). `false` for kill/critical violations where retry won't help. |
| `message` | `string` | Human-readable explanation suitable for agent context injection. |

## Consuming Feedback

### Minimal Python Example (file-based)

```python
import json, sys

with open("/run/neurontrace/feedback.jsonl") as f:
    for line in f:
        event = json.loads(line)
        if event["version"] != 1:
            continue
        if event["suggested_retry"]:
            # Adjust strategy based on what was blocked
            print(f"Blocked: {event['hook']} → {event['target']}", file=sys.stderr)
```

### Minimal Shell Example (stdout)

```bash
neurontrace run --policy policy.yaml --cgroup /sys/fs/cgroup/agent --feedback-stdout \
  | while IFS= read -r line; do
      hook=$(echo "$line" | jq -r .hook)
      target=$(echo "$line" | jq -r .target)
      echo "VIOLATION: $hook on $target" >&2
    done
```

### Node.js Example (Unix socket listener)

```javascript
const net = require('net');
const server = net.createServer((conn) => {
  let buf = '';
  conn.on('data', (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const event = JSON.parse(buf.slice(0, idx));
      buf = buf.slice(idx + 1);
      if (event.suggested_retry) {
        console.error(`Policy blocked ${event.hook} → ${event.target}`);
      }
    }
  });
});
server.listen('/run/neurontrace/feedback.sock');
```

## Versioning

The `version` field is a monotonically increasing integer. Consumers MUST:

1. Check `version` before processing
2. Ignore events with an unknown `version` (forward compatibility)
3. Not assume field ordering in the JSON object

When new fields are added to version 1, they are always optional and additive. A breaking schema change increments the version number.

## Future Extensions

- `kind: "generation_bump"` — notify agents when task boundaries are signaled
- `kind: "policy_reload"` — notify when the active policy is hot-swapped
- `context` field — additional structured metadata (labels, cgroup path, generation ID)
