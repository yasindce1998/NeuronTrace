#!/usr/bin/env bash
# Install NeuronTrace feedback hook for Claude Code
# Run from your project root where .claude/ lives

set -euo pipefail

HOOK_DIR=".claude/hooks"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/neurontrace-feedback.sh" << 'HOOK'
#!/usr/bin/env bash
# Claude Code post-tool hook: surfaces NeuronTrace violations into agent context
FEEDBACK="/run/neurontrace/feedback.jsonl"
[ -f "$FEEDBACK" ] || exit 0
# Show last violation (if any in the last 5 seconds)
tail -1 "$FEEDBACK" 2>/dev/null | jq -r '
  select(.kind == "violation") |
  "⚠ NeuronTrace: \(.hook) on \(.target) was \(.effect). \(.message)"
' 2>/dev/null || true
HOOK
chmod +x "$HOOK_DIR/neurontrace-feedback.sh"

# Add hook to Claude Code settings
SETTINGS=".claude/settings.local.json"
if [ ! -f "$SETTINGS" ]; then
  echo '{}' > "$SETTINGS"
fi

python3 -c "
import json, sys
s = json.load(open('$SETTINGS'))
hooks = s.setdefault('hooks', {})
post = hooks.setdefault('post-tool-use', [])
entry = '.claude/hooks/neurontrace-feedback.sh'
if entry not in post:
    post.append(entry)
json.dump(s, open('$SETTINGS', 'w'), indent=2)
" 2>/dev/null || echo "Note: manually add .claude/hooks/neurontrace-feedback.sh to your post-tool-use hooks"

echo "Installed NeuronTrace feedback hook for Claude Code"
