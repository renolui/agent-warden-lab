#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR="/tmp/agent_warden_test"
MODE="${1:-hash}"

echo "=========================================================="
echo " Starting Agent-Warden End-to-End Evaluation Experiment"
echo " Backend Engine Mode: ${MODE}"
echo "=========================================================="

rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"
mkdir -p "${ROOT_DIR}/graphs"

# 1. Start mock exfiltration server in background with auto-timeout
python3 "${SCRIPT_DIR}/mock_server.py" 8888 &
MOCK_PID=$!
sleep 0.5

# 2. Start agent simulation in waiting mode
python3 "${SCRIPT_DIR}/attack_simulation.py" --wait-ready &
SIM_PID=$!

# Wait for PID file
for i in {1..20}; do
    if [ -f "${TEST_DIR}/agent.pid" ]; then
        AGENT_PID=$(cat "${TEST_DIR}/agent.pid")
        break
    fi
    sleep 0.1
done

if [ -z "${AGENT_PID}" ]; then
    echo "[-] Error: Failed to acquire Agent PID"
    kill ${SIM_PID} 2>/dev/null || true
    kill ${MOCK_PID} 2>/dev/null || true
    exit 1
fi

echo "[+] Captured Agent PID: ${AGENT_PID}"

# 3. Start Agent-Warden collector attached to AGENT_PID
echo "[*] Launching Agent-Warden collector (timeout: 10s)..."
"${ROOT_DIR}/collector/agent-warden" \
    --mode "${MODE}" \
    --agent-pid "${AGENT_PID}" \
    --timeout 8 \
    --output-dot "${ROOT_DIR}/graphs/provenance.dot" \
    --output-png "${ROOT_DIR}/graphs/provenance.png" &
COLLECTOR_PID=$!

# Give collector 0.8s to load BPF bytecode and seed root agent state
sleep 0.8

# 4. Trigger attack execution
echo "[+] Signaling Agent to start attack lifecycle..."
touch "${TEST_DIR}/ready"

# Wait for collector to finish capturing and exporting DAG
wait ${COLLECTOR_PID} || true

# Clean up mock server if still running
kill ${MOCK_PID} 2>/dev/null || true

echo "=========================================================="
echo " Experiment Complete! Inspecting Provenance Artifacts..."
echo "=========================================================="
if [ -f "${ROOT_DIR}/graphs/provenance.dot" ]; then
    echo "[+] Graphviz DOT file:"
    cat "${ROOT_DIR}/graphs/provenance.dot"
fi

if [ -f "${ROOT_DIR}/graphs/provenance.png" ]; then
    ls -lh "${ROOT_DIR}/graphs/provenance.png"
    echo "[+] PNG topology successfully rendered!"
fi
