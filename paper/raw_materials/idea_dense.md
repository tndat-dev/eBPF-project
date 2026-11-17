# Idea (PaperOrchestra input `idea_dense.md`)

Working name of the system: **Sentinel Pulse**. Source of truth: `thesis/chapters/design.tex`, `implementation.tex`
(same content, Vietnamese). Every number about results lives in `experimental_log.md`, not here.

## Problem

Rule-based container runtime security tools (Falco, Tetragon) only catch behaviour someone wrote a rule for. Anomaly
detection from system calls exists since Forrest et al. (1996), but most work evaluates offline on recorded traces. It
rarely measures (i) the latency from the kernel event to the person who must act, (ii) the alert burden on a real
workload over a day, or (iii) whether the detector can tell an attack from a new but harmless process, such as an
operator's `kubectl exec`. We build a detector that learns only from normal behaviour, runs in the kernel and in user
space of a production-like Kubernetes cluster, and is evaluated with pre-registered protocols on public datasets and on
blind live runs.

## Threat model

- Attacker already runs code inside an application container (post-compromise), or exploits the containerised service
  itself. On the cluster: starts a new process and performs syscall-level actions (namespace changes, ptrace, unusual
  exec, memory protection changes, seccomp API use). On the datasets: the exploit goes through the application.
- Protected: every replica of the 21 workloads of one application namespace; infrastructure pods are not scored.
- Trusted: kernel, eBPF, Tetragon, the detector's worker. Normal data used for learning and thresholds has no attacks.
- Out of scope: an adaptive attacker who uses only syscall sequences already in the workload's normal; attacks that only
  change the meaning of data inside a process without changing its system behaviour (e.g. a SQL injection that is an
  ordinary login request at the syscall level); attacks on the host or cluster infrastructure.

## Architecture (four parts in a chain)

1. **eBPF probe** in the kernel turns every syscall of a watched container into one 32-bit token and counts 4-token
   sequences per thread in a kernel map.
2. **Per-workload token language model**, learnt only from normal, scores each 0.5 s window.
3. **Alert path**: a bridge pushes each over-threshold window straight to the cluster's Alertmanager (no scrape interval).
4. **Root-cause analysis (RCA)** builds a process evidence tree from Tetragon events around each alert that Alertmanager
   received.

Kernel only builds tokens and counts grams; all probabilities are computed in user space. The model is learnt offline,
locked by SHA-256 and unchanged during a run.

## Tokens (alphabet `select1f`)

Each event is one syscall return. Token, by priority:
1. **Error code**: if the syscall is one of 27 that keep their errno and it failed, token = `name!errno`
   (e.g. `openat!2` = ENOENT). The 27: stat family (stat, lstat, fstat, newfstatat), access, faccessat, open family
   (open, openat, creat), read, write, writev, ioctl, connect, execve, fcntl, close, rename, renameat, sendfile, unlink,
   unlinkat, mkdir, kill, recvfrom, shutdown, futex.
2. **Successful open**: `name:mode:first-directory`, mode r or w, first directory = first component of the absolute path
   (`/etc`, `/tmp`), `/` at the root, `rel` for a relative path (e.g. `openat:r:/etc`).
3. **Successful read or write**: `name#b`, b = min(15, floor(log2 n)), n = bytes returned (4096 bytes read = `read#12`).
4. Otherwise: the syscall name.

In the kernel the token is a 32-bit number: syscall number in bits 23-31, token kind in bits 21-22, the rest holds the
error code, size bucket, or write flag plus an FNV-1a hash of the first directory.

## Probe (kernel)

- `raw_tp/sys_enter` runs for every syscall of the node and looks the task's cgroup up in an allow-list map (filled by a
  resolver: Pod UID -> container -> cgroup -> workload revision); others leave after one map lookup.
- 39 syscalls whose token needs the return value emit at `raw_tp/sys_exit`; the others emit their name at entry. A
  syscall skipped by seccomp never reaches sys_exit, so `fexit/__seccomp_filter` emits it. Hence exactly one token per
  syscall (verified by a proof script per kernel and build).
- First directory: walk the dentry tree from the opened fd up to the task's root (the container's root) with
  `bpf_loop`, at most 64 steps, then FNV-1a. No `d_path`, no fentry on open.
- Gram map: key = (cgroup, 0.5 s window, 4 tokens, pad), value = count; 262,144 entries (about two live windows). Every
  0.5 s the loader batch-reads the map, takes the closed windows, deletes them and prints one JSON line per (cgroup,
  window). Single events never cross to user space.
- Design rejected: one `fexit` program per syscall. With Tetragon's kprobe on `__x64_sys_openat`, every open walked the
  list of all ftrace trampolines; open+close got 2.3-2.7 us slower. One generic `raw_tp/sys_exit` avoids it.
- **Lineage tag** (added for the latest run, telemetry only): each thread is native (the workload's own process tree)
  or session (entered through a runtime exec such as `kubectl exec`, and all its descendants). At fork
  (`raw_tp/sched_process_fork`) the child copies the parent's tag; a thread first seen without state takes the tag of its
  thread-group leader, else of its parent if the parent is in the same cgroup, else it is native when its pid in its pid
  namespace is 1 (the container entrypoint), session otherwise. The tag sits in the gram key's pad, so the loader prints
  the whole window (unchanged) plus its session part. Known limits: shared process namespaces; a session process
  orphaned before the probe attached is taken as native.

## Sequences per thread

Each thread keeps its last four tokens; event e_i yields 4-gram g_i = (t_{i-3}, t_{i-2}, t_{i-1}, t_i) of that thread
(shorter at thread start). Thread history is not cut at window borders. The gram goes to the 0.5 s window holding the
event; the kernel counts (cgroup, window, gram).

## Probability model

Estimate P(t_i | t_{i-3}, t_{i-2}, t_{i-1}) by counting normal. c(h, w): times token w follows context h; c(h) = sum_w
c(h, w); T(h): number of distinct tokens that followed h.

Base level (handles unseen tokens), with nu(w) the syscall name of w, N total events, V distinct names, V_nu distinct
tokens of name nu:

P_0(w) = (c(nu) + 1/2) / (N + (V + 1)/2) * (c(nu, w) + 1/2) / (c(nu) + (V_nu + 1)/2)

If the name itself is unseen, the second factor is the mean "unseen variant" probability over known names (an unseen
`openat!13` stays far likelier than a never-called `ptrace`).

Interpolated Witten-Bell (Witten & Bell 1991; Chen & Goodman 1999), k = 1, 2, 3, h_k the k tokens before w:

P_k(w | h_k) = (c(h_k, w) + T(h_k) P_{k-1}(w | h_{k-1})) / (c(h_k) + T(h_k)), and P_k = P_{k-1} if h_k unseen.

Score uses P_3. A 4-gram that is new but built from familiar steps gets a moderate probability; one with a strange
token gets a tiny one.

## Window score

Surprise of an event = -ln P_3. Window score s(W) = mean of the 10 largest surprises, each gram weighted by its count
(mean of all if fewer than 10 events, 0 for an empty window). Top-10 rather than the mean of the window, so a few
strange events are not diluted by thousands of familiar ones; 10 rather than 1, so a single rare normal event does not
alarm.

Worked example (live run, harmless control binary in a RabbitMQ container, 5.2 s after start): 89 events; gram
(getpid, clock_nanosleep, getpid, clock_nanosleep) 6 times at 34.0 (never in RabbitMQ's normal), next gram 6 times at
7.0; s = (6 x 34.0 + 4 x 7.0)/10 = 23.2 > threshold 13.4: alarm. Same binary in order-service: only 3 occurrences at
26.7, s = 11.3 < 13.3: no alarm. The model measures novelty and its density, not intent.

## Threshold (normal only)

Unit of normal: a recording (dataset) or a 60 s block of one container (cluster). M_j = largest window score in unit j.
1. Held-out scores by 5-fold cross-fit: dataset recordings go to fold sha256(name) mod 5; on the cluster, time is cut
   into contiguous 30-minute chunks dealt to the folds in turn. The scoring model learns all data.
2. Drop the top 1 % of maxima (at least one).
3. Moment Gumbel fit: beta = sqrt(6)/pi * sigma_M, mu = mean_M - 0.5772 beta.
4. tau = mu - beta ln(-ln(1 - alpha')), alpha' = 0.0002 x 0.9 = 0.00018.

Equivalently tau = mean_M + 6.27 sigma_M. The Gumbel assumption does not hold (rejected on all 15 dataset scenarios;
exceedance 10x the design on the dataset, 14-17x on the cluster), so alpha' is a knob, not a guaranteed false-alarm
rate; among normal-only rules tried (MLE Gumbel, GEV, normal, largest held-out maximum) this one gives the most
detections at every false-alarm budget tested.

## Decision

One window with s(W) > tau alarms; alarm time = end of that window. The worker scores a window about 0.15 s after it
closes.

## Parameters and provenance

| Parameter | Value | Chosen how |
|---|---|---|
| Gram length | 4 | dataset development; a large LSTM did not beat it |
| Window | 0.5 s | fixed from the latency goal |
| Values averaged | 10 | development (vs 1, 3, 5, 20) |
| Token alphabet | select1f | development, with attack labels |
| Size buckets | 16 (log2) | development |
| alpha | 0.0002 | development, by measured false alarms |
| Folds, trimmed share | 5; 1 % | development and CB-DS |
| Maxima block (cluster) | 60 s | fixed before any cluster data |
| Cross-fit chunk (cluster) | 30 min | fixed before thresholds on the cluster |

The 21 workload models take about 1.5 MB (gzip count tables).

## Dataset vs cluster

Same algorithm, alphabet and threshold rule. Unit of learning: one model per dataset scenario (training + validation
recordings) vs one per workload (12 h of normal-only capture plus the previous live run's normal outside its trials).
Token order: on the cluster, syscalls without a return-value token emit at entry, so a long blocking call's token
arrives earlier; alphabet `probe1f` reproduces this order on the dataset.

## Learning operator activity, and lineage separation (what we tried for benign new processes)

The model flags almost every new process entering a container through `kubectl exec`, harmless or not. Tried, each
pre-registered:
- A gate before the model (pool model of all workloads; skipping or a separate threshold 1-2 s after execve): rejected
  on the dataset (loses development/CB-DS detections).
- Learning operator commands as normal (B, B2): not enough.
- Lineage proxy (B3): native part clean, but a separate session model under the Gumbel rule detects nothing; hence only
  the kernel lineage tag as telemetry, measured in the next live run.
- A rule layer after the model (R1: downgrade an alarm whose cgroup had only runtime execs of tools present in the
  image; R2: label a non-image binary as drift). Benefit measured on the previous live run; harm (living-off-the-land
  attacks using image tools) measured in the latest live run.

## Alert path and RCA

- Bridge: reads decisions from each worker's local disk, pushes alerts to Alertmanager directly; the scrape-based
  Prometheus path runs in parallel for comparison.
- RCA: for each alert Alertmanager delivered, opens a case and builds a process evidence tree from Tetragon events
  (runtime, fork, flow policies), ranks suspects (new execs near the alert, tie broken by launch time closest to the
  alert), follow-up cases on novel execs; latest fix: consider execs up to the decision time and recheck once after 2 s.

## Evaluation methodology

- Pre-registration: every main analysis and live run has a JSON protocol committed before the data is read; changes are
  timestamped amendments.
- Development vs blind: development = data seen while designing; blind = LID-DS official split and live runs.
- Datasets: LID-DS 2021 (15 scenarios of real vulnerabilities; test recordings split by seed: 30 % development, 70 %
  official), CB-DS (container breakout: 9 scenarios x 99 recordings, 1,700 normal of an e-shop container), LID-DS 2019
  reserved as a final once-only test.
- Cluster: 3 workers (16 vCPU, 36 GB since 12/11), application with 21 workloads. Trials on one replica: control idle
  15 s; harmless control binary through the same `kubectl exec` path (getpid + clock_nanosleep loop); an operator
  command; one of 5 self-written attack fixtures (child ptrace TRACEME, setns with fd -1, execveat of a missing file,
  mprotect churn on an anonymous page, invalid seccomp operation; all only affect the process itself or fail) at 1, 3, 6,
  12, 24 actions/s. 21 x 5 x 5 = 525 trials; primary set = 6, 12, 24/s. 90-minute selection prefix before attacks.
- Metrics: recall (attack interval has an alarm within 15 s), control positive rate, precision 1:1, latency kernel event
  -> end of alarm window and -> Alertmanager, burden = episodes per replica-hour of normal (alarms of one container less
  than 15 s apart), Wilson CIs, workload-clustered bootstrap for burden.
- Latest live run adds: lineage build, operator commands never used before, seeded random order of admin/benign/attack/
  living-off-the-land steps, dilution trials (PAD 30 and 300 pairs of getpid + sched_yield after each attack operation).

## Contributions (claims to support)

1. In-kernel syscall tokens with return values (error code, returned size, first directory, open mode), per-thread 4-gram
   counting in an eBPF map, one token per syscall verified, measured overhead.
2. A label-free count language model with a normal-only threshold rule that holds pre-registered levels on LID-DS 2021,
   CB-DS and blind live runs, with sub-second kernel-to-Alertmanager latency.
3. Honest evaluation: development / official / live blind, pre-registered protocols, negative results reported (benign
   new processes, seen-only attackers, threshold calibration, model aging).
4. A kernel lineage tag separating a workload's own process tree from operator sessions, as a direction for the open
   problem of benign new processes (results of the latest run pending).
