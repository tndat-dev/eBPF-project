"""Rolling conformal calibration in the live worker (calibration-strategies-v1 ``rolling-W-R``; Pulse 5.6, 5.7d, 5.17).

Every ``refresh_hours`` the frozen model's two calibration arrays per workload (``model.base.calibration_scores``,
tree branch; ``model.support_calibration``, support branch) are replaced by the sorted scores of the eligible
windows of the preceding ``window_hours`` of every worker of the run, as ``attack/rolling_recalibration.py`` does
offline and ``detector/recalibrate_bundle.py`` does for a bundle. Estimators, support boundaries, policy and the
pinned scorer files stay byte-identical: both scoring paths (``PulseSupportEnsemble.predict_contexts`` and
``fast_forest.predict_contexts``) read the two arrays at every call, so a swap between frames changes the
p-values of later windows and nothing else. Every decision row then carries ``calibration_epoch`` (0 = the
bundle's calibration) so the p-values can be recomputed offline.

Data path, off the scoring loop (one background thread):
- each worker's ``ScoreBuffer`` (pipeline/retention.py) writes one file per UTC hour on local disk;
- ``publish_delay_seconds`` after an hour ends, the thread copies that hour (.bin, .json) to ``shared/<node>/``;
- ``refresh_delay_seconds`` after the hour, it reads [H - window, H) from every worker's shared copy (hours
  already read stay cached, eligible windows only), builds the arrays and queues them; the loop calls ``apply``
  between frames. A workload below ``minimum_examples`` in either branch keeps its current arrays.

Deviations from the offline replay, to be registered with any run that uses this: a refresh takes effect
``refresh_delay_seconds`` after the hour instead of at the hour; a workload below the minimum keeps its previous
calibration instead of being left unscored; a worker whose hour is missing from the shared copy at refresh time
is left out of that refresh (logged).

``exclude_intervals`` (optional, the campaign's INTERVALS.jsonl): windows ending in [start - 20, start + 35] of a
registered control/benign/attack interval are left out of every calibration, as offline (campaign_spans). An
operational deployment has no such list; an evaluation run states whether it uses it.
"""
from __future__ import annotations

import json
from pathlib import Path
import queue
import shutil
import threading
import time

import numpy as np

from .retention import ELIGIBLE, RECORD

HOUR = 3600
MARGIN, INTERVAL = 20.0, 15.0


def hour_name(hour: int) -> str:
    return time.strftime('%Y%m%d%H', time.gmtime(hour * HOUR))


def interval_spans(path: Path | None):
    if path is None or not Path(path).exists():
        return np.empty((0, 2))
    starts = [float(json.loads(line)['start_at']) for line in Path(path).read_text().splitlines() if line.strip()]
    return np.array(sorted((s - MARGIN, s + INTERVAL + MARGIN) for s in starts)).reshape(-1, 2)


def excluded(end, spans):
    out = np.zeros(len(end), dtype=bool)
    for a, b in spans:
        out |= (end >= a) & (end < b)
    return out


class LiveRecalibration:
    def __init__(self, models: dict, buffer_dir: Path, shared: Path, node: str, window_hours: int = 12,
                 refresh_hours: int = 1, publish_delay_seconds: float = 60, refresh_delay_seconds: float = 300,
                 minimum_examples: int = 1200, exclude_intervals: Path | None = None, log: Path | None = None,
                 clock=time.time, keep_shared_hours: int | None = None):
        if not (1 <= int(window_hours) <= 47 and 1 <= int(refresh_hours) <= 24
                and 0 <= publish_delay_seconds < refresh_delay_seconds < HOUR):
            raise ValueError('invalid live recalibration schedule')
        self.models, self.buffer, self.shared, self.node = models, Path(buffer_dir), Path(shared), node
        self.window, self.every = int(window_hours), int(refresh_hours)
        self.publish_delay, self.refresh_delay = float(publish_delay_seconds), float(refresh_delay_seconds)
        self.minimum = int(minimum_examples)
        # hours of this worker's shared copy kept: the window by default; an evaluation run keeps the whole run so
        # that every refresh can be rebuilt afterwards (scripts/analysis/live_recalibration_check.py)
        self.keep = int(keep_shared_hours) if keep_shared_hours else self.window + 1
        if self.keep < self.window + 1:
            raise ValueError('the shared copy must keep at least the calibration window')
        self.intervals = Path(exclude_intervals) if exclude_intervals else None
        self.log_path, self.clock = (Path(log) if log else None), clock
        self.cache = {}                       # (node, hour) -> {workload: (end, tree, support)} eligible windows
        self.published, self.refreshed = set(), set()
        self.ready = queue.SimpleQueue(); self.logs = queue.SimpleQueue()   # log rows are written by the thread
        self.epoch = 0
        self.stats = dict(published=0, refreshes_built=0, refreshes_applied=0, failures=0)
        self.stop = threading.Event(); self.thread = None
        (self.shared / node).mkdir(parents=True, exist_ok=True)

    # ---- background thread -------------------------------------------------------------------------------------
    def start(self):
        self.thread = threading.Thread(target=self._loop, name='live-recalibration', daemon=True)
        self.thread.start(); return self

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=30)
        self.write_logs()

    def _loop(self):
        while not self.stop.wait(5):
            try:
                self.tick(self.clock())
            except Exception as exc:          # a failed refresh keeps the current calibration; never stops scoring
                self.stats['failures'] += 1
                self._log(event='failure', error=f'{type(exc).__name__}: {exc}')
            try:
                self.write_logs()
            except OSError:
                self.stats['failures'] += 1

    def tick(self, now: float):
        hour = int(now // HOUR); into = now - hour * HOUR
        if into >= self.publish_delay and hour - 1 not in self.published:
            self.publish(hour - 1)
        if hour % self.every == 0 and into >= self.refresh_delay and hour not in self.refreshed:
            self.refreshed.add(hour)
            self.ready.put(self.build(hour))

    def publish(self, hour: int):
        """Copy this worker's finished hour to the shared directory (tmp + rename, sidecar last)."""
        base = self.buffer / hour_name(hour); dest = self.shared / self.node
        if base.with_suffix('.bin').exists() and base.with_suffix('.json').exists():
            for suffix in ('.bin', '.json'):
                tmp = dest / (hour_name(hour) + suffix + '.tmp')
                shutil.copyfile(base.with_suffix(suffix), tmp); tmp.replace(dest / (hour_name(hour) + suffix))
            self.stats['published'] += 1
        self.published.add(hour)
        for old in dest.glob('*.json'):       # keep the shared copy bounded (keep_shared_hours)
            try:
                h = int(time.mktime(time.strptime(old.stem + 'UTC', '%Y%m%d%H%Z')) - time.timezone) // HOUR
            except ValueError:
                continue
            if h < hour - self.keep:
                old.unlink(missing_ok=True); old.with_suffix('.bin').unlink(missing_ok=True)

    def _read(self, node: str, hour: int):
        key = (node, hour)
        if key not in self.cache:
            side = self.shared / node / (hour_name(hour) + '.json')
            if not side.exists():
                return None
            meta = json.loads(side.read_text())
            data = np.fromfile(side.with_suffix('.bin'), dtype=RECORD)
            data = data[(data['flags'] & ELIGIBLE) > 0]
            self.cache[key] = {w: (data['window_end'][data['workload'] == i].copy(), data['tree_score'][data['workload'] == i].copy(),
                                   data['support_score'][data['workload'] == i].copy())
                               for i, w in enumerate(meta['workloads']) if (data['workload'] == i).any()}
        return self.cache[key]

    def build(self, hour: int):
        """Calibration from [hour - window, hour) of every worker -> (hour, {workload: (tree, support)}, info)."""
        lo, hi = hour - self.window, hour
        for key in [k for k in self.cache if k[1] < lo]:
            del self.cache[key]
        nodes = sorted(p.name for p in self.shared.iterdir() if p.is_dir())
        parts, missing = {}, []
        for node in nodes:
            for h in range(lo, hi):
                got = self._read(node, h)
                if got is None:
                    missing.append([node, hour_name(h)]); continue
                for w, arrays in got.items():
                    parts.setdefault(w, []).append(arrays)
        spans = interval_spans(self.intervals)
        out = {}
        for w, chunks in parts.items():
            end = np.concatenate([c[0] for c in chunks])
            keep = ~excluded(end, spans)
            out[w] = (np.sort(np.concatenate([c[1] for c in chunks])[keep]), np.sort(np.concatenate([c[2] for c in chunks])[keep]))
        self.stats['refreshes_built'] += 1
        return hour, out, dict(span=[lo * HOUR, hi * HOUR], nodes=nodes, missing=missing, excluded_spans=len(spans))

    # ---- scoring loop ------------------------------------------------------------------------------------------
    def apply(self) -> int:
        """Swap every queued calibration into the models (call between frames); returns the current epoch."""
        while True:
            try:
                hour, cal, info = self.ready.get_nowait()
            except queue.Empty:
                return self.epoch
            swapped, kept = {}, []
            for w, model in self.models.items():
                c = cal.get(w)
                need = max(self.minimum, int(getattr(model, 'minimum_calibration_examples_per_branch', 0)))
                if c is None or min(len(c[0]), len(c[1])) < need:
                    kept.append(w); continue
                model.base.calibration_scores = np.asarray(c[0], dtype=np.float64)
                model.support_calibration = np.asarray(c[1], dtype=np.float64)
                swapped[w] = [len(c[0]), len(c[1])]
            if swapped:                       # the epoch names a calibration state: it moves only when one changed
                self.epoch += 1; self.stats['refreshes_applied'] += 1
            self._log(event='applied' if swapped else 'unchanged', epoch=self.epoch, hour=hour_name(hour), swapped=swapped,
                      kept=kept, **info)

    def _log(self, **row):
        self.logs.put(dict(row, node=self.node, at=self.clock()))

    def write_logs(self):
        rows = []
        while True:
            try:
                rows.append(self.logs.get_nowait())
            except queue.Empty:
                break
        if rows and self.log_path is not None:
            with self.log_path.open('a') as f:
                f.write(''.join(json.dumps(r) + '\n' for r in rows))
