# Agent-Warden: eBPF-Based Kernel-Native Provenance Tracking for LLM Agents

A kernel-level process-file causal lineage tracking prototype based on the research paper:
> *Agent-Warden: eBPF-Based Kernel-Native Process-File Provenance Tracking for LLM Agents* (IEEE TPS 2026).

---

## Architecture Overview

Agent-Warden introduces a dual-backend eBPF observability architecture designed to track the execution and file propagation of LLM Agents at the Linux OS layer, defeating uncoupling and chain-severing evasion attacks.

- **Warden-Hash Backend**: Maintains process and file provenance state via BPF Hash Maps (`hash_task_map`, `hash_inode_map`). Compatible with Linux kernels prior to 5.11.
- **Warden-Local Backend**: Utilizes `BPF_MAP_TYPE_TASK_STORAGE` to couple process provenance states directly to kernel `task_struct` objects, offering zero-collision lookup and kernel-object-driven RCU garbage collection.
- **Asynchronous DAG Reconstruction**: Kernel probes perform $O(1)$ scalar taint state updates in constant time, streaming incremental causal edges through a 1MB BPF RingBuffer to a user-space C collector that maintains the DAG and generates Graphviz topologies.

---

## Directory Structure

```
├── ebpf/               # Kernel eBPF probes and build rules
│   ├── warden.bpf.c    # Core eBPF tracepoint and fexit hooks
│   ├── warden.h        # Unified event and state data structures
│   ├── vmlinux.h       # Kernel BTF definitions
│   └── Makefile        # Builds warden.bpf.o and generates skeleton
├── collector/          # User-space collector and provenance engine
│   ├── collector.c     # libbpf-based event polling, DAG builder & renderer
│   └── Makefile        # Compiles agent-warden executable
├── agent_sim/          # Attack simulation and benchmarking
│   ├── attack_simulation.py   # Simulates multi-phase prompt injection evasion
│   ├── mock_server.py         # Loopback exfiltration listener (watchdog protected)
│   ├── run_experiment.sh      # End-to-end integration and evaluation runner
│   └── benchmark_overhead.py  # Bursty workload stress benchmark (1,000 cycles)
├── graphs/             # Exported provenance DAG artifacts
│   ├── provenance.dot  # Graphviz DOT format causal graph
│   └── provenance.png  # Rendered topology diagram
└── docs/               # Research paper and documentation
    ├── 2609.38245v1.pdf       # Original IEEE TPS 2026 research paper
    └── weekly_report.md       # Technical report and team presentation guide
```

---

## Quick Start

### 1. Build Probes and Collector

```bash
# Compile eBPF probe and generate skeleton
make -C ebpf

# Build user-space collector
make -C collector
```

### 2. Run End-to-End Experiment

```bash
# Run multi-phase attack simulation with Warden-Hash
./agent_sim/run_experiment.sh hash

# Or run with Warden-Local (Linux 5.11+)
./agent_sim/run_experiment.sh local
```

The resulting provenance topology diagram will be automatically exported to `graphs/provenance.png`.

### 3. Run Benchmark (1,000 Cycles)

```bash
python3 agent_sim/benchmark_overhead.py
```

