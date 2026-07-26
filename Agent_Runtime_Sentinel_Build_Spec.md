# Agent Runtime Sentinel — Build Specification (V1 → V2)
### Everything needed to start building, in one place

---

## 1. Project Summary

**What this is:** AI Agent Runtime Security for Kubernetes. Instead of monitoring an AI agent's prompts/outputs, this system observes what the agent *actually does* at the kernel level (syscalls, network calls, MCP tool calls) and flags behavior that deviates from a learned baseline — then automatically isolates the offending pod.

**Status:** This is not a greenfield project. **V1 already exists, is deployed, and has been evaluated with real results** (see Section 2). V2 is a targeted upgrade of V1 to a new domain (AI agents) with stronger detection methods, not a rewrite.

---

## 2. What Already Exists — V1 (reuse, don't rebuild)

V1 is a completed university capstone project: *"Runtime Security System Using eBPF Combined with Anomaly Detection and Automatic Isolation on Kubernetes"* (Nguyễn Tuấn Đạt, HUST, term 2025.2, advisor Nguyễn Đức Toàn).

### 2.1 Infrastructure already running
- 3-node Kubernetes cluster (1 master, 2 workers), built with `kubeadm` on VMware vSphere VMs, Ubuntu 22.04 LTS, 8 vCPU / 32GB RAM / 40GB disk each
- **Cilium 1.19.2** as CNI (eBPF-based, identity-based network policy, replaces kube-proxy)
- **Tetragon** deployed as a DaemonSet, using declarative `TracingPolicy` CRDs, exporting events via JSON log and gRPC (port 54321)
- `pod-network-cidr=10.10.0.0/16`

**→ Action: reuse this cluster as-is. Do not re-provision.**

### 2.2 Code modules already built (V1 pipeline)

| File | Role | Reuse in V2? |
|---|---|---|
| `analyze_profile.py` | Parses Tetragon JSONL, builds per-workload syscall frequency profile | Reference only — V2 needs agent/tool-level profiling instead of syscall-only |
| `generate_baseline.py` (Markov/synthetic) | Generates synthetic training sequences | **Do not reuse** — V1's own findings show synthetic data underperforms real data (see 2.4) |
| `generate_baseline2.py` (real vectors) | Builds training vectors from real captured events | **Reuse the pattern** — always train on real captured behavior, never synthetic |
| `ml_models.py` (LSTM Autoencoder + Isolation Forest) | Per-pod anomaly scoring, ensemble 0.6×LSTM + 0.4×IF, static threshold τ=0.80 | **Replaced** by GAT + EVT-POT (Section 4, Layer 3) — this is the core V1→V2 upgrade |
| `anomaly_detector.py` | Reads Tetragon stream, windows events (30s), scores, emits `AnomalyAlert` | **Replaced**, but keep the same `AnomalyAlert` dataclass shape for compatibility with the responder |
| `isolation_responder.py` | 4-step isolation: cordon node → label `quarantine=true` → CiliumNetworkPolicy deny-all → evict pod | **Reuse directly, unchanged.** This is already fast (~0.5s) and correctly ordered (label before evict, preventing exfiltration during shutdown) |

### 2.3 Validated results (5 attack scenarios × 5 runs = 25 trials)

| Metric | Result |
|---|---|
| Detection Rate | 100% (25/25) |
| False Positive Rate | 0% |
| MITRE ATT&CK mapping accuracy | 100% (25/25) |
| Avg. detection latency | 88.46s (bounded by 30s window size) |
| Avg. response latency (full isolation) | ~0.5s |

Scenarios covered: Reverse Shell (T1059, T1046), Container Escape (T1059, T1611, T1496), Cryptomining (T1059, T1496), Privilege Escalation (T1059, T1548), Data Exfiltration (T1059, T1046, T1041).

**→ Use these numbers as the baseline to beat/match when V2 is evaluated on AI agent scenarios.**

### 2.4 Hard-won lessons from V1 (apply directly to V2)
- **Training distribution must match runtime distribution** — this mattered more than model architecture. Collect V2's baseline from *real* running agents, not synthetic MCP traffic.
- **`sendfile()` and keep-alive silently drop events** — if a workload uses a syscall path that bypasses userspace (like `sendfile`), Tetragon/eBPF sees nothing. **Direct implication for V2: if MCP traffic runs over TLS, socket-level hooks alone will see only encrypted bytes — you need a `uprobe` on `SSL_read`/`SSL_write`, not just socket syscall hooks.** This is not a hypothetical risk — V1 already hit an analogous real bug in production and had to work around it.
- **`kubectl logs --follow` cannot keep up with high-throughput events** — read the Tetragon log file directly inside the container, or consume the gRPC stream instead.
- **Per-pod (V2: per-agent) baseline is required** — a shared baseline across workload types causes both false positives and false negatives.
- **Isolation step order matters**: quarantine label must be applied *before* evict, or there's a race condition allowing data exfiltration during graceful pod shutdown.

---

## 3. What's New in V2

| V1 limitation (self-identified in the report, Section 7.3–7.4) | V2 solution |
|---|---|
| Static threshold τ=0.80, not adaptive (V1's own future-work section proposed "Threshold Adaptation") | **EVT-POT** (Extreme Value Theory – Peaks Over Threshold): statistically-derived adaptive threshold instead of a fixed cutoff |
| Detection based on raw syscall n-grams — no understanding of application semantics | **Graph Attention Network (GAT)** over a behavior graph (agent → tool → resource), not just syscall frequency |
| No visibility into what tool/resource is being called, only raw syscalls | **Custom eBPF/C with `uprobe` on TLS functions**, parsing MCP JSON-RPC 2.0 payloads |
| Only tested on generic workloads (nginx, redis, postgres) | New target: **AI agents executing tool calls via MCP inside K8s pods** |
| Response layer (4-step isolation) | **No change — already correct and fast** |

---

## 4. V2 Architecture (5 layers)

```
AI Agent (via MCP, inside K8s Pod)
        │
        ▼
┌─────────────────────────────────────────────┐
│ LAYER 1 — Data Collection (kernel, eBPF)     │
│  • Custom eBPF/C (libbpf) — NEW              │
│    - uprobe on SSL_read/SSL_write (OpenSSL)  │
│    - captures raw bytes → BPF ring buffer    │
│  • Tetragon — REUSE from V1 (base loading,   │
│    standard syscall TracingPolicy)           │
└─────────────────────────────────────────────┘
        │  raw bytes via ring buffer
        ▼
┌─────────────────────────────────────────────┐
│ LAYER 2 — Graph Construction (Go) — NEW      │
│  • cilium/ebpf Go lib reads ring buffer      │
│  • parse JSON-RPC 2.0 → method, params       │
│  • build sliding-window behavior graph:      │
│    nodes = agent / tool / resource / pod     │
│    edges = calls over time                   │
└─────────────────────────────────────────────┘
        │  graph snapshot every 10–30s
        ▼
┌─────────────────────────────────────────────┐
│ LAYER 3 — Anomaly Detection (Python) — NEW   │
│  • Graph Attention Network (PyTorch Geometric)│
│  • EVT-POT for adaptive thresholding         │
│  • emits AnomalyAlert (same shape as V1)     │
└─────────────────────────────────────────────┘
        │  AnomalyAlert
        ▼
┌─────────────────────────────────────────────┐
│ LAYER 4 — Response — REUSE FROM V1, AS-IS    │
│  cordon → label quarantine=true →            │
│  CiliumNetworkPolicy deny-all → evict        │
│  (~0.5s, already validated)                  │
└─────────────────────────────────────────────┘
        │  (only after design partner)
        ▼
┌─────────────────────────────────────────────┐
│ LAYER 5 — Product (later, enterprise tier)   │
│  Dashboard, Helm chart, multi-cluster        │
└─────────────────────────────────────────────┘
```

---

## 5. Suggested Repository Structure

```
agent-runtime-sentinel/
├── ebpf/
│   ├── mcp_probe.bpf.c        # eBPF program: uprobe SSL_read/write, ring buffer output
│   ├── mcp_probe.h            # shared struct definitions (event schema)
│   └── loader/                # Go userspace loader (cilium/ebpf)
├── graph-builder/              # Layer 2
│   ├── main.go
│   ├── mcp/                   # JSON-RPC 2.0 parsing
│   └── graph/                 # behavior graph data structure, sliding window
├── detector/                   # Layer 3
│   ├── gat_model.py           # GATConv-based model (PyTorch Geometric)
│   ├── evt_pot.py             # EVT-POT threshold module
│   └── train.py               # training entrypoint, reuses V1's real-data-first lesson
├── responder/                   # Layer 4 — port directly from V1
│   └── isolation_responder.py  # same 4-step logic, same AnomalyAlert schema
├── k8s/
│   ├── tracingpolicy.yaml      # extend V1's TracingPolicy for MCP-relevant hooks
│   └── helm/                   # packaging, build later (Layer 5)
└── eval/
    └── scenarios/               # port V1's 5-scenario methodology to agent-specific attacks
```

---

## 6. Implementation Plan (in order)

### Step 1 — Layer 1: eBPF/C MCP interceptor (start here)
- Bootstrap from `libbpf-bootstrap` (standard starting template for libbpf/C eBPF projects)
- Hook `SSL_write`/`SSL_read` via `uprobe` on `libssl.so` — **do not attempt full JSON-RPC parsing inside the eBPF program**; the verifier will reject it (no unbounded loops, no arbitrary function calls, small stack). eBPF's only job: copy raw buffer bytes into a `BPF_MAP_TYPE_RINGBUF`.
- Prototype fast with `bpftrace` before committing to full libbpf/C — much faster iteration for exploring which hook points actually fire.
- Extend (don't replace) V1's existing `TracingPolicy` CRDs for the baseline syscall layer.

### Step 2 — Layer 2: Graph construction service (Go)
- Use the `cilium/ebpf` Go library to read the ring buffer written by Layer 1.
- Parse JSON-RPC 2.0 with the standard `encoding/json` package — extract `method` (tool name), `params`, and enrich with Kubernetes metadata the same way Tetragon already does (pod name, namespace, container ID).
- Maintain an in-memory sliding-window graph (e.g., last 5–10 minutes); prune aggressively to avoid unbounded memory growth — this was not a problem V1 faced (no graph state), so budget explicit time for it in V2.

### Step 3 — Layer 3: GAT + EVT-POT (Python)
- `pip install torch-geometric` — use `GATConv` layers to learn "normal" agent behavior graph embeddings.
- For EVT-POT, either use an existing implementation (`pyextremes`) or implement the SPOT/DSPOT streaming algorithm directly.
- **Follow V1's lesson religiously: train only on real captured agent behavior, never synthetic data.** This was V1's single biggest source of wasted debugging time.
- Keep the output schema identical to V1's `AnomalyAlert` dataclass (`pod_name`, `pod_namespace`, `node_name`, `detected_at`, `ensemble_score`/new score, `threshold`, `top_syscalls`/new top-signals, `window_start`, `window_end`) so Layer 4 needs zero changes.

### Step 4 — Layer 4: Response (port, don't rebuild)
- Copy `isolation_responder.py` from V1 essentially unchanged. Confirm the K8s client calls (`patch_node`, pod label patch, `CiliumNetworkPolicy` creation, `V1Eviction`) still work against the same cluster.
- Keep the quarantine-label-before-evict ordering — this is a validated, non-negotiable invariant from V1.

### Step 5 — Evaluation
- Reuse V1's evaluation harness (5 scenarios × 5 runs, automated scripted evaluation) but redefine the 5 scenarios for AI agent misbehavior instead of generic workload attacks — see Founder Strategy Framework, Pain section, for candidate scenarios (secret leakage via agent context, over-privileged deploy via agent-issued kubectl, agent-triggered production deletion — mirroring the real Replit incident — lateral movement via loose service-account scoping, container escape).
- Compare V2's detection rate / false positive rate / latency directly against V1's numbers (Section 2.3) — this comparison table is strong material for both the thesis defense and the product pitch.

---

## 7. Key Technical Risks (carried over from architecture doc + V1 precedent)

1. **TLS blinds socket-level hooks** — must use `uprobe` on SSL library functions, not just `connect`/`sendto`/`recvfrom`. V1 already proved this class of problem is real (its `sendfile` bug was the same *shape* of issue: syscall-level assumptions broken by an actual runtime optimization).
2. **eBPF verifier limits** — no JSON parsing in-kernel; capture raw bytes only, parse in userspace (Layer 2).
3. **GAT inference cost** — score in batches/windows (10–30s), not per-event.
4. **Graph state growth** — enforce a sliding window with explicit expiry; V1 never had this problem (no graph state), so don't assume it's automatically handled.
5. **Explainability for thesis defense** — GAT is less interpretable than the LSTM Autoencoder V1 used. Prepare attention-weight visualization (PyTorch Geometric supports this natively) so the thesis committee can see *why* something was flagged, not just a score.

---

## 8. First Two Weeks — Concrete Checklist

1. Confirm the V1 cluster (3-node, Cilium 1.19.2, Tetragon) is still up and reachable; if not, redeploy from V1's documented `kubeadm`/Helm steps (Section 2.1) — do not design a new cluster.
2. Stand up a minimal MCP server + client running inside a pod on the existing cluster, communicating over HTTPS, as the first real test target.
3. Bootstrap the eBPF project from `libbpf-bootstrap`; get a `uprobe` on `SSL_write` firing and printing raw bytes to confirm the hook works before writing any parsing logic.
4. Port `isolation_responder.py` from V1 unchanged and confirm it still executes all 4 steps against the current cluster — this validates Layer 4 is ready before Layers 1–3 exist.
5. Only after 1–4 work: start the Go ring-buffer consumer (Layer 2).
