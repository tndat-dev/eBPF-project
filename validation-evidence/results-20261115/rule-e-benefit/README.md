# Part E (rule layer after ML), benefit side on pulse-live-v5-1110 (15/11/2026)

Protocol `sentinel_pulse/protocol/ml-final-study-v1.json` part `E_rule_layer_after_ml` and `rule-integration-v1`
(ML first, rules after, then compare without and with rules). Runner `scripts/analysis/rule_e_benefit.py`, reusing
`live_attribution.py`'s token-branch loader and `flagged()` so the ML alarms are exactly the v5 token model's
(FIT `pulse-live-v5-fit-1110/token`). 87 token segments read.

- **R1 (image-tool exec):** an alert whose window had only runtime execs of binaries that belong to the container
  image is downgraded to info.
- **R2 (drift):** an alert whose exec is a binary not in the image stays an alert, labelled drift.

On the v5 campaign each trial injects, per workload: a **control** (no exec); a **benign** exec of the operator
binary `/operator/sentinel-benign-exec-control` (NOT an image binary); an **admin** command (cat / date / df / env /
id / ls / ps / python / sh / uname — image binaries); a blind **attack** `/operator/sentinel-runtime-attack-blind`
(NOT an image binary).

## Result

| Phase (exec) | n | ML alarms | after R1 | R2 drift |
|---|---|---|---|---|
| admin (image tools) | 439 | 422 | **0** | 0 |
| attack (/operator, non-image) | 522 | 521 | **521** | 521 |
| benign (/operator, non-image) | 523 | 520 | 520 | 520 |
| control (no exec) | 525 | 0 | 0 | 0 |

Primary attack rates (1/3/6 per second): admin 256 → **0** after R1; **attack recall 314/314 = 1.0, unchanged by R1**;
benign 314/314, unchanged. Per admin command, every command was flagged by the model and **all downgraded to 0 by R1**
(cat 49/49→0, ls 44/44→0, sh 46→0, ps 7→0, df 51→0, env 52→0, id 51→0, date 45→0, python 34→0, uname 43→0).

## Reading

- **R1 removes every admin-command false flag (422 → 0) while leaving attack recall untouched (314/314).** Admin
  activity (an operator running cat/ls/ps/... through `kubectl exec`) stops paging; real attacks still page, because
  the v5 attack binary is a non-image `/operator/` binary that R1 does not downgrade. This is the clean benefit the
  rule layer is for: separate benign in-image tool use from attacks.
- **R1 does not reduce the benign-exec flagging (520 → 520)** — the v5 benign exec is an operator-injected non-image
  binary, not an image tool, so R1 correctly leaves it; **R2 labels it drift** (a genuinely new non-image binary).
  Reducing the flagging of a benign *image* tool is what R1 does for admin; the operator benign exec is a different,
  real drift.
- **R2** labels all non-image exec alerts (attack + benign, 521 + 520) as drift.

## Limit (why this is benefit side only)

The v5 campaign has no living-off-the-land attack — one that execs an image tool. R1 would also downgrade such an
attack (a miss), and the campaign cannot measure that. Part F of a live run (`pulse-live-v6`) must add attacks that
exec image tools before R1 is adopted; this is registered in the protocol. So R1's recall cost is not yet measured;
only its benign-admin benefit and its (zero) effect on the measured attacks are.

## Data

`rule-e-benefit.json` (full per-label and per-command counts and rates). ML alarms recomputed from the v5 FIT token
models over `pulse-live-v5-1110/workers/*/segments/*/tokens.jsonl`.
