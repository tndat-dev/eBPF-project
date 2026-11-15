# Part E (rule layer after ML): ML-only vs ML+rule on pulse-live-v5-1110 (15/11/2026)

Protocol `sentinel_pulse/protocol/ml-final-study-v1.json` part `E_rule_layer_after_ml` and `rule-integration-v1`
(ML decided first, rules after, then compare **without vs with rules**, per memory `rule-framework-last`). Runner
`scripts/analysis/rule_e_benefit.py` (commit that added the `comparison` block), reusing `live_attribution.py`'s
token-branch loader and `flagged()` so the ML alarms are exactly the deployed v5 token model's (FIT
`pulse-live-v5-fit-1110/token`). 87 token segments read.

The two systems the thesis separates:

- **ML-only** — the token model alone is the alert path (the deployed v5 system). An alert = the model fired.
- **ML+rule** — the token model + the Part E rule layer. An alert = the model fired **and** was not downgraded by R1.
  - **R1 (image-tool exec):** an alert whose window had only runtime execs of binaries that belong to the container
    image is downgraded to info.
  - **R2 (drift):** an alert whose exec is a binary not in the image stays an alert, labelled drift.

Each trial injects, per workload: a **control** (no exec); a benign **admin** command (cat / date / df / env / id /
ls / ps / python / sh / uname — binaries that are part of the image); a **benign** exec of the operator binary
`/operator/sentinel-benign-exec-control` (NOT an image binary); a blind **attack** `/operator/sentinel-runtime-attack-blind`
(NOT an image binary). So on v5 only the **admin** class execs image tools — the class R1 acts on; the benign operator
exec and the attack are non-image, so R1 leaves both and R2 labels them drift.

## Result — ML-only vs ML+rule, split out

**Primary attack rates (6 / 12 / 24 per second — `pulse_live_v4.PRIMARY`; the campaign's full set is 1/3/6/12/24):**

| Metric | ML-only | ML+rule |
|---|---|---|
| Attack recall | **314/314 = 1.000** | **314/314 = 1.000** |
| Admin false-alarm (in-image tool use) | 256/262 = 0.977 | **0/262 = 0.000** |
| Benign operator exec (non-image → drift) | 314/314 | 314/314 (kept, labelled drift) |
| Control (no exec) | 0 | 0 |

**All rates pooled:**

| Metric | ML-only | ML+rule |
|---|---|---|
| Attack recall | **521/522 = 0.998** | **521/522 = 0.998** |
| Admin false-alarm (in-image tool use) | 422/439 = 0.961 | **0/439 = 0.000** |
| Benign operator exec (non-image → drift) | 520/523 = 0.994 | 520/523 = 0.994 (drift) |
| Control (no exec) | 0/525 | 0/525 |
| Pooled false-alarm over all benign classes | 942/1487 = 0.633 | 520/1487 = 0.350 |

Per admin command, every command was flagged by the model and **all downgraded to 0 by R1** (cat 49/49→0, ls 44/44→0,
sh 46→0, ps 7→0, df 51→0, env 52→0, id 51→0, date 45→0, python 34→0, uname 43→0).

## Reading

- **The only metric the rule layer moves is the admin (in-image tool use) false-alarm rate: 0.961 → 0.000, with attack
  recall unchanged (0.998).** An operator running cat/ls/ps/... through `kubectl exec` stops paging; real attacks still
  page, because the v5 attack binary is a non-image `/operator/` binary that R1 does not downgrade. This is the clean
  benefit the rule layer is for: separate benign in-image tool use from attacks.
- **The benign operator exec is unchanged (520→520 / 314→314).** It is a non-image binary, not an image tool, so R1
  correctly leaves it; **R2 labels it drift** — a genuinely new non-image binary, a real signal, not a false alarm.
  (Reducing the flagging of a benign *image* tool is what R1 does for admin; the operator benign exec is a different,
  real drift.) The pooled false-alarm row above counts it as a false alarm for a conservative single number; the
  per-class rows show that admin is the class the rule actually fixes and benign-drift is unchanged under both systems.
- **Control is 0 under both systems** — no exec, no alert, as expected.

## Limit (why this is the benefit side only)

The v5 campaign has no living-off-the-land attack — one that execs an image tool. R1 would also downgrade such an
attack (a miss), and the campaign cannot measure that. Part F of a live run (`pulse-live-v6`) must add attacks that
exec image tools before R1 is adopted; this is registered in the protocol. So **the ML+rule column's recall cost is
not yet measured** — only its benign-admin benefit and its (zero) effect on the measured non-image attacks are. The
314/314 and 521/522 recall for ML+rule is "unchanged by R1 on these attacks", not "R1 never costs recall".

## Data

`rule-e-benefit.json` — top-level `comparison` block with `all_rates` and `primary`, each split into `ml_only` and
`ml_plus_rule` (attack_recall, false_alarm_by_class, false_alarm_pooled, with hit/n/rate); `by_label` and
`admin_by_command` keep the full per-label and per-command counts. ML alarms recomputed from the v5 FIT token models
over `pulse-live-v5-1110/workers/*/segments/*/tokens.jsonl`. Reproduce:

```
python3 scripts/analysis/rule_e_benefit.py \
  --run-root  /mnt/sentinel-pulse-archive/pulse-live-v5-1110 \
  --models    /mnt/sentinel-pulse-archive/pulse-live-v5-fit-1110/token/MODELS.json \
  --output    rule-e-benefit.json --jobs 6
```
