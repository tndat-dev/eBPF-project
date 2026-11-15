# W3(b): frequency (rate) signal, measured end-to-end on LID-DS 2021 + CB-DS (15/11/2026)

Protocol `sentinel_pulse/protocol/ml-final-study-v1.json` part D (rate signal) and amendment-3 (split-alpha). Runner
`scripts/analysis/lidds_token_rate.py`. This is the **ML-only (model) vs ML+branch (model + rate)** comparison for the
frequency branch — the "with vs without" the plan asks for, on the offline benchmark.

The rate branch: per seen gram g, `m_g` is the largest count of g in one 0.5 s window over the learning recordings; a
test window's rate score is `max over its seen grams of log((n_g+1)/(m_g+1))`. A window with no seen gram never fires.
Unseen grams never enter the score, so the rate branch's detections equal its seen-only-simulation detections. It is
meant to catch an adaptive attacker who uses only sequences normal knows, but at an anomalous *rate*.

Inputs (all present on `.234`, contrary to an earlier note that called W3(b) blocked):
- caches `/var/tmp/lid-ds-2021/token-study/cache` (16 npz: 15 LID-DS + CB-DS, each with `<rec>/w|g|c` gram arrays and
  a meta json carrying `vocab` and per-recording `split`/`subset`/`exploit`);
- alarms inventories `lidds-evaluation-v2-alarms.json.gz` (snapshot `runtime-9a506d1-20261110`) and
  `/var/tmp/cb-ds/v4/lidds-evaluation-v2-cbds-alarms.json.gz`.

## Result — `[detected, false_alarm_recordings]`

| Arm | LID-DS development (544 attack / 3403 normal) | CB-DS (891 / 1410) |
|---|---|---|
| **model** (token model alone = deployed v5) | **530, FA 6** | 891, FA 3 |
| rate (frequency branch alone) | 225, FA 7 | 891, FA 3 |
| model_or_rate (both at the shared α′ 0.00018 — part D) | 530, **FA 12** | 891, **FA 4** |
| model_or_rate_split (amendment-3: model α 0.00018, rate α 0.00002) | 530, **FA 7** | 891, **FA 4** |

`joins`: **false**. `joins_split`: **false**.
Latency p95 unchanged by the branch (model 1.52 s; combined 1.52 s on LID-DS).

The `model` arm reproduces the deployed v5 token-only development number exactly (530/544, FA 6/3403), which
cross-checks that this harness scores the same model, not a hardcoded figure.

## Reading (the honest negative)

- **The rate branch adds no detections over the model: 530 → 530 on LID-DS, 891 → 891 on CB-DS.** Every attack the
  rate branch catches, the token model already catches; it catches none of the model's misses on either dataset. On
  the static benchmark the branch earns no recall.
- **It only adds false alarms:** LID-DS 6 → 12 at the shared α′ (the part-D budget doubled), 6 → 7 with the amendment-3
  split-α; CB-DS 3 → 4 in both. The split-α (model keeps 0.00018, rate gets the freed 0.00002) is the honest fix for
  the doubled budget and it halves the extra LID-DS false alarms (12 → 7), but still misses the adopt criteria:
  **LID-DS FA 7 > 6 and CB-DS FA 4 > 3.** So neither `joins` nor `joins_split` holds.
- **Conclusion:** on the offline LID-DS 2021 + CB-DS benchmark the frequency branch does **not** earn adoption — no new
  recall, extra false alarms, over budget even split. This is expected: the benchmark contains no *diluted* attack
  (one that pads a real attack with high-frequency seen grams), so the branch has nothing to catch here. Its value can
  only be shown against the **W3(a) dilution fixture of a live run** (registered in amendment-3). The branch stays in
  shadow; the deployed alert path remains the token model alone.

## Data

`rate-signal.json` — `arms` (rate / model / model_or_rate / model_or_rate_split, each with lidds + cbds
detected/attack_recordings/false_alarm_recordings/latency), `criteria`, `joins`, `joins_split`, `seen_only_note`.
Reproduce:

```
python3 scripts/analysis/lidds_token_rate.py \
  --caches       /var/tmp/lid-ds-2021/token-study/cache \
  --out          /var/tmp/ml-final/rate-signal \
  --lidds-alarms .../lidds-evaluation-v2-alarms.json.gz \
  --cbds-alarms  /var/tmp/cb-ds/v4/lidds-evaluation-v2-cbds-alarms.json.gz --jobs 6
```
