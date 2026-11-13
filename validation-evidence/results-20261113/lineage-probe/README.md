# Lineage tag of the token probe: build and proofs (13/11/2026)

Protocol `sentinel_pulse/protocol/ml-final-study-v1-amendment-2.json`: telemetry only, the alert path is unchanged.
Built from the working tree on k8s-worker1 (`make tokens`), hashes and kernel in `build-sha256.txt`.

| Proof | Script | Result |
|---|---|---|
| Token proof (unchanged checks) | `scripts/token_probe_proof.py` | valid: 411,052 token events = 411,052 syscalls of the cgroup; seccomp path, expected tokens, no insert failure (`token-proof-RESULTS.json`) |
| Lineage proof on a test pod | `scripts/lineage_probe_proof.py` | valid, all 8 checks (`lineage-proof-RESULTS.json`) |

Lineage proof, pod `pulse-proof/lineage-proof` (busybox, its command loops over `cat` and `sleep`), entered with `crictl exec`:

| Phase | Windows | Native events | Session events |
|---|---|---|---|
| A, the container's own loop | 5 | 1,157 | 0 |
| B, exec: `ls /; cat /etc/hostname; sleep 1; ls /tmp` | 3 | 712 | 687 |
| C, idle | 2 | 445 | 0 |
| D, after the exec command returned, its backgrounded child still running | 3 | 715 | 198 |
| E, idle | 2 | 445 | 0 |

The children that the container's pid 1 forks stay native (execve tokens in A), an exec through the runtime and its children
are session, and a child that outlives its session parent keeps the session lineage (phase D): the tag is copied at fork.
One token per syscall holds over the run. Not measured here: the cost of the fork hook, and the proof on the other workers
(done with the run's build before a run).
