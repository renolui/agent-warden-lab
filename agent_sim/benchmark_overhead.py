#!/usr/bin/env python3
"""
Reproduce bursty workload benchmark described in Section V-C of Agent-Warden paper:
Measure execution time across 1,000 iterations of:
  - File write
  - File read
  - File rename
  - Process creation (fork/exec)
over N measurement rounds (mean ± std), under:
  1. Baseline (No probe)
  2. Warden-Hash mode
  3. Warden-Local mode
"""

import os
import sys
import time
import subprocess
import shutil
import math

ROOT_DIR = "/root/dev/agent-warden-lab"
BENCH_DIR = "/tmp/agent_warden_bench"
COLLECTOR_BIN = os.path.join(ROOT_DIR, "collector/agent-warden")

def run_bursty_workload(iterations=1000):
    os.makedirs(BENCH_DIR, exist_ok=True)
    t0 = time.perf_counter()
    for i in range(iterations):
        target = f"{BENCH_DIR}/f_{i % 20}.tmp"
        renamed = f"{BENCH_DIR}/f_{i % 20}.dat"
        # 1. Write file
        with open(target, "w") as f:
            f.write(f"sample_payload_data_for_provenance_benchmarking_{i}\n")
        # 2. Read file
        with open(target, "r") as f:
            _ = f.read()
        # 3. Rename file
        os.rename(target, renamed)
        # 4. Fork & Exec process
        subprocess.run(["/bin/true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t1 = time.perf_counter()
    shutil.rmtree(BENCH_DIR, ignore_errors=True)
    return t1 - t0

def calc_stats(data):
    n = len(data)
    mean = sum(data) / n
    if n > 1:
        variance = sum((x - mean) ** 2 for x in data) / (n - 1)
        std = math.sqrt(variance)
    else:
        std = 0.0
    return mean, std

def benchmark(rounds=5, iterations=1000):
    print("==========================================================")
    print(f" Agent-Warden Benchmark ({rounds} Rounds x {iterations} Cycles)")
    print("==========================================================")
    
    # 1. Baseline Off
    baseline_times = []
    print(f"[*] Running Baseline (No probes, {rounds} rounds)...")
    for r in range(rounds):
        t = run_bursty_workload(iterations)
        baseline_times.append(t)
        print(f"    Round {r+1}: {t:.4f} s")
    base_mean, base_std = calc_stats(baseline_times)
    print(f"    -> Baseline: {base_mean:.4f} ± {base_std:.4f} s\n")
    time.sleep(1)

    # 2. Warden-Hash
    hash_times = []
    print(f"[*] Running Warden-Hash ({rounds} rounds)...")
    for r in range(rounds):
        col_proc = subprocess.Popen([COLLECTOR_BIN, "--mode", "hash", "--timeout", "30",
                                     "--output-dot", "/tmp/bench_hash.dot",
                                     "--output-png", "/tmp/bench_hash.png"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)  # Wait for BPF probes to attach
        t = run_bursty_workload(iterations)
        hash_times.append(t)
        col_proc.terminate()
        col_proc.wait()
        print(f"    Round {r+1}: {t:.4f} s")
    hash_mean, hash_std = calc_stats(hash_times)
    hash_overhead = ((hash_mean - base_mean) / base_mean) * 100
    print(f"    -> Warden-Hash: {hash_mean:.4f} ± {hash_std:.4f} s (Overhead: {hash_overhead:+.2f}%)\n")
    time.sleep(1)

    # 3. Warden-Local
    local_times = []
    print(f"[*] Running Warden-Local ({rounds} rounds)...")
    for r in range(rounds):
        col_proc = subprocess.Popen([COLLECTOR_BIN, "--mode", "local", "--timeout", "30",
                                     "--output-dot", "/tmp/bench_local.dot",
                                     "--output-png", "/tmp/bench_local.png"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)  # Wait for BPF probes to attach
        t = run_bursty_workload(iterations)
        local_times.append(t)
        col_proc.terminate()
        col_proc.wait()
        print(f"    Round {r+1}: {t:.4f} s")
    local_mean, local_std = calc_stats(local_times)
    local_overhead = ((local_mean - base_mean) / base_mean) * 100
    print(f"    -> Warden-Local: {local_mean:.4f} ± {local_std:.4f} s (Overhead: {local_overhead:+.2f}%)\n")

    print("==========================================================================")
    print(" Multi-Round Performance Summary Table (Ubuntu 24.04, Kernel 6.8)")
    print("==========================================================================")
    print(f" Baseline (Off) : {base_mean:.4f} ± {base_std:.4f} s  (Reference: 0.00%)")
    print(f" Warden-Hash    : {hash_mean:.4f} ± {hash_std:.4f} s  (Overhead: {hash_overhead:+.2f}%)")
    print(f" Warden-Local   : {local_mean:.4f} ± {local_std:.4f} s  (Overhead: {local_overhead:+.2f}%)")
    print("==========================================================================")
    
    # Save results to a file for auditing
    with open(os.path.join(ROOT_DIR, "agent_sim/benchmark_results.txt"), "w") as f:
        f.write(f"Rounds: {rounds}\n")
        f.write(f"Iterations: {iterations}\n")
        f.write(f"Baseline: {base_mean:.4f} ± {base_std:.4f} s\n")
        f.write(f"Warden-Hash: {hash_mean:.4f} ± {hash_std:.4f} s, Overhead: {hash_overhead:+.2f}%\n")
        f.write(f"Warden-Local: {local_mean:.4f} ± {local_std:.4f} s, Overhead: {local_overhead:+.2f}%\n")

if __name__ == "__main__":
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    benchmark(rounds=rounds)
