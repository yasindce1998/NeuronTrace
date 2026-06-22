#!/usr/bin/env bash
set -euo pipefail

# NeuronTrace Demo — see kernel enforcement in one command
# Usage: sudo ./scripts/demo.sh [policy]
# Default policy: policies/generic-agent.yaml

POLICY="${1:-policies/generic-agent.yaml}"
CGROUP_PATH="/sys/fs/cgroup/neurontrace-demo"
BINARY="./target/release/neurontrace"
NT_PID=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

cleanup() {
    echo ""
    echo -e "${CYAN}▸ Cleaning up...${RESET}"
    if [[ -n "$NT_PID" ]] && kill -0 "$NT_PID" 2>/dev/null; then
        kill "$NT_PID" 2>/dev/null || true
        wait "$NT_PID" 2>/dev/null || true
    fi
    if [[ -d "$CGROUP_PATH" ]]; then
        # Move any remaining processes back to root cgroup
        if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
            while read -r pid; do
                echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
            done < "$CGROUP_PATH/cgroup.procs"
        fi
        rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi
    echo -e "${GREEN}✓ Done.${RESET}"
}
trap cleanup EXIT

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║        NeuronTrace — Live Demo              ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# --- Pre-flight checks ---
echo -e "${CYAN}▸ Pre-flight checks${RESET}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}✗ Must run as root (sudo ./scripts/demo.sh)${RESET}"
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo -e "${YELLOW}  Binary not found. Building...${RESET}"
    cargo xtask build --release
fi

if ! cat /sys/kernel/security/lsm 2>/dev/null | grep -q bpf; then
    echo -e "${RED}✗ BPF-LSM not enabled. Add 'lsm=bpf' to kernel cmdline.${RESET}"
    exit 1
fi

if [[ ! -f "$POLICY" ]]; then
    echo -e "${RED}✗ Policy not found: $POLICY${RESET}"
    exit 1
fi

echo -e "${GREEN}✓ Kernel $(uname -r), BPF-LSM active, binary ready${RESET}"
echo -e "${GREEN}✓ Policy: $POLICY${RESET}"
echo ""

# --- Setup cgroup ---
echo -e "${CYAN}▸ Creating demo cgroup${RESET}"
mkdir -p "$CGROUP_PATH"
echo -e "${GREEN}✓ $CGROUP_PATH${RESET}"
echo ""

# --- Start NeuronTrace ---
echo -e "${CYAN}▸ Starting NeuronTrace (background)${RESET}"
$BINARY run --policy "$POLICY" --cgroup "$CGROUP_PATH" &>"$CGROUP_PATH/../neurontrace-demo.log" &
NT_PID=$!
sleep 1

if ! kill -0 "$NT_PID" 2>/dev/null; then
    echo -e "${RED}✗ NeuronTrace failed to start. Check log:${RESET}"
    cat "$CGROUP_PATH/../neurontrace-demo.log" | tail -20
    exit 1
fi
echo -e "${GREEN}✓ NeuronTrace running (PID $NT_PID)${RESET}"
echo ""

# --- Run tests inside the cgroup ---
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Testing enforcement inside the cgroup${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo ""

# Helper: run a command inside the cgroup and show result
try_in_cgroup() {
    local label="$1"
    local cmd="$2"
    local expect_fail="${3:-yes}"

    echo -e "${YELLOW}  $ $cmd${RESET}"

    # Fork a subshell into the cgroup, then try the command
    result=$(
        echo $BASHPID > "$CGROUP_PATH/cgroup.procs"
        eval "$cmd" 2>&1
    ) && exit_code=0 || exit_code=$?

    if [[ "$expect_fail" == "yes" && $exit_code -ne 0 ]]; then
        echo -e "    ${RED}BLOCKED${RESET} — $result"
    elif [[ "$expect_fail" == "no" && $exit_code -eq 0 ]]; then
        echo -e "    ${GREEN}ALLOWED${RESET} — $(echo "$result" | head -1)"
    else
        echo -e "    exit=$exit_code — $result"
    fi
    echo ""
}

echo -e "${CYAN}▸ Test 1: exec (should be BLOCKED)${RESET}"
try_in_cgroup "exec" "/bin/ls /tmp" "yes"

echo -e "${CYAN}▸ Test 2: exec another binary (should be BLOCKED)${RESET}"
try_in_cgroup "exec" "/usr/bin/whoami" "yes"

echo -e "${CYAN}▸ Test 3: network connect (should be BLOCKED)${RESET}"
try_in_cgroup "connect" "/usr/bin/curl -s --max-time 2 https://example.com" "yes"

echo -e "${CYAN}▸ Test 4: file delete (should be BLOCKED)${RESET}"
TMPFILE=$(mktemp)
try_in_cgroup "unlink" "rm $TMPFILE" "yes"
rm -f "$TMPFILE" 2>/dev/null || true

echo -e "${CYAN}▸ Test 5: file read (may be AUDITED — allowed but logged)${RESET}"
try_in_cgroup "open" "cat /etc/hostname" "no"

# --- Show violation log ---
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Violation log (last 10 events)${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo ""
tail -10 "$CGROUP_PATH/../neurontrace-demo.log" 2>/dev/null || echo "(no log output)"
echo ""

# --- Summary ---
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Demo complete!${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo ""
echo "  What happened:"
echo "    • NeuronTrace loaded BPF-LSM hooks into the kernel"
echo "    • Processes in the demo cgroup hit those hooks on every syscall"
echo "    • Policy rules decided: allow, block, kill, or audit"
echo "    • No match = BLOCKED (default-deny)"
echo ""
echo "  Try with a different policy:"
echo "    sudo ./scripts/demo.sh policies/claude-code.yaml"
echo "    sudo ./scripts/demo.sh policies/codex.yaml"
echo ""
