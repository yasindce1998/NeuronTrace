#!/usr/bin/env bash
# Install NeuronTrace feedback hook for Gemini CLI
# Run from your project root

set -euo pipefail

HOOK_DIR=".gemini/hooks"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/neurontrace-feedback.sh" << 'HOOK'
#!/usr/bin/env bash
# Gemini post-tool hook: surfaces NeuronTrace violations into agent context
FEEDBACK="/run/neurontrace/feedback.jsonl"
[ -f "$FEEDBACK" ] || exit 0
tail -1 "$FEEDBACK" 2>/dev/null | jq -r '
  select(.kind == "violation") |
  "⚠ NeuronTrace: \(.hook) on \(.target) was \(.effect). \(.message)"
' 2>/dev/null || true
HOOK
chmod +x "$HOOK_DIR/neurontrace-feedback.sh"

echo "Installed NeuronTrace feedback hook for Gemini CLI"
echo "Add .gemini/hooks/neurontrace-feedback.sh to your post-tool-use hooks config"
