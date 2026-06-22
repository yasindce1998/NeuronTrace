#!/usr/bin/env bash
# Install NeuronTrace feedback hook for Codex CLI
# Run from your project root where .codex/ lives

set -euo pipefail

HOOK_DIR=".codex/hooks"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/neurontrace-feedback.sh" << 'HOOK'
#!/usr/bin/env bash
# Codex post-tool hook: surfaces NeuronTrace violations into agent context
FEEDBACK="/run/neurontrace/feedback.jsonl"
[ -f "$FEEDBACK" ] || exit 0
tail -1 "$FEEDBACK" 2>/dev/null | jq -r '
  select(.kind == "violation") |
  "⚠ NeuronTrace: \(.hook) on \(.target) was \(.effect). \(.message)"
' 2>/dev/null || true
HOOK
chmod +x "$HOOK_DIR/neurontrace-feedback.sh"

# Write hooks.json
cat > ".codex/hooks.json" << 'EOF'
{
  "post-tool-use": [".codex/hooks/neurontrace-feedback.sh"]
}
EOF

echo "Installed NeuronTrace feedback hook for Codex"
