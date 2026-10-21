"""What a matched worker keeps on disk, beyond the live preview (SENTINEL_PULSE_STATUS 5.19, retention policy).

Two independent, opt-in pieces (absent from a run config = the experiment behaviour, unchanged):

``ScoreBuffer`` (cfg ``score_buffer``: {"path", "retention_hours"}): a bounded ring of the raw branch scores of
every scored window, enough to rebuild a conformal calibration of the frozen model for any recent span
(``detector/recalibration.py`` needs only tree_score and support_score per workload). One file per UTC hour,
fixed 31-byte records, plus a JSON sidecar with the workload names; files older than the retention are
deleted by the writer itself, so the size stays bounded (~75 MB per worker for 12 h at ~200 000 scored
windows per hour) instead of growing with the run.

``OutputPolicy`` (cfg ``outputs``): the experiment mode writes every feature and decision row (~80 GB per
24 h run as JSON); the operational mode keeps only what operations and audits read:
- ``features``: "full" (default) | "off";
- ``decisions``: "full" (default) | "positives" (rows that passed the window threshold or raised a preview,
  plus one sampled scored row in every ``sample_every`` for audits).
"""
from __future__ import annotations

import json
from pathlib import Path
import time
import zlib

import numpy as np

# scores kept in float64, as computed, so a calibration rebuilt from the buffer equals one rebuilt from decisions
RECORD = np.dtype([('window_end', '<f8'), ('tree_score', '<f8'), ('support_score', '<f8'), ('workload', '<u2'),
                   ('container', '<u4'), ('flags', 'u1')])            # 31 bytes
ELIGIBLE, PREVIEW, PASSED = 1, 2, 4
IDENTITY = ('node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id')
SCORED = 'candidate-raw-score-only'


def container_id(row) -> int:
    return zlib.crc32('|'.join(str(row.get(k)) for k in IDENTITY).encode())


class ScoreBuffer:
    def __init__(self, path: Path, retention_hours: float = 12.0, clock=time.time):
        if not 1 <= float(retention_hours) <= 48:
            raise ValueError('score buffer retention must be 1-48 hours')
        self.path, self.retention, self.clock = Path(path), float(retention_hours) * 3600, clock
        self.path.mkdir(parents=True, exist_ok=True)
        self.hour = None; self.stream = None; self.workloads = {}

    def _open(self, hour: int):
        if self.stream is not None:
            self.stream.close()
        self.hour = hour
        base = self.path / time.strftime('%Y%m%d%H', time.gmtime(hour * 3600))
        side = base.with_suffix('.json')
        self.workloads = {w: i for i, w in enumerate(json.loads(side.read_text())['workloads'])} if side.exists() else {}
        self.stream = base.with_suffix('.bin').open('ab')
        self.prune()

    def _sidecar(self):
        base = self.path / time.strftime('%Y%m%d%H', time.gmtime(self.hour * 3600))
        tmp = base.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(dict(schema='sentinel-pulse-score-buffer-v1', record=RECORD.descr,
                                       workloads=sorted(self.workloads, key=self.workloads.get))))
        tmp.replace(base.with_suffix('.json'))

    def add(self, decision: dict) -> bool:
        """Append one decision row; returns False (nothing written) unless it is a scored window."""
        if decision.get('status') != SCORED or decision.get('tree_score') is None:
            return False
        end = float(decision['window_end'])
        hour = int(end // 3600)
        if hour != self.hour:
            self._open(hour)
        workload = decision['workload_key']
        if workload not in self.workloads:
            if len(self.workloads) >= 65535:
                raise ValueError('too many workloads for one score-buffer hour')
            self.workloads[workload] = len(self.workloads); self._sidecar()
        flags = (ELIGIBLE * bool(decision.get('eligible_for_normal_review')) + PREVIEW * bool(decision.get('candidate_alert_preview'))
                 + PASSED * bool(decision.get('window_passed')))
        rec = np.array([(end, decision['tree_score'], decision['support_score'], self.workloads[workload],
                         container_id(decision), flags)], dtype=RECORD)
        self.stream.write(rec.tobytes())
        return True

    def flush(self):
        if self.stream is not None:
            self.stream.flush()

    def close(self):
        if self.stream is not None:
            self.stream.close(); self.stream = None

    def prune(self):
        """Delete hour files whose whole hour is older than the retention."""
        cutoff = self.clock() - self.retention
        removed = 0
        for f in self.path.glob('*.bin'):
            try:
                hour = time.mktime(time.strptime(f.stem + 'UTC', '%Y%m%d%H%Z')) - time.timezone
            except ValueError:
                continue
            if hour + 3600 < cutoff and int(hour // 3600) != self.hour:
                f.unlink(missing_ok=True); f.with_suffix('.json').unlink(missing_ok=True); removed += 1
        return removed


def read_buffer(paths, since: float, until: float):
    """{workload: structured array} of all records with since <= window_end < until (several workers' dirs)."""
    parts = {}
    for root in paths:
        for side in sorted(Path(root).glob('*.json')):
            meta = json.loads(side.read_text())
            data = np.fromfile(side.with_suffix('.bin'), dtype=RECORD) if side.with_suffix('.bin').exists() else np.empty(0, RECORD)
            data = data[(data['window_end'] >= since) & (data['window_end'] < until)]
            for i, workload in enumerate(meta['workloads']):
                sel = data[data['workload'] == i]
                if len(sel):
                    parts.setdefault(workload, []).append(sel)
    return {w: np.sort(np.concatenate(v), order='window_end') for w, v in parts.items()}


def calibration_from_buffer(paths, since, until, minimum_examples=1200, eligible_only=True):
    """Recalibrator over [since, until) from score buffers; same inputs as Recalibrator.from_rows on decisions."""
    from ..detector.recalibration import Recalibrator
    data = read_buffer(paths, since, until)
    tree, support = {}, {}
    for w, a in data.items():
        if eligible_only:
            a = a[(a['flags'] & ELIGIBLE) > 0]
        tree[w], support[w] = a['tree_score'].astype(np.float64), a['support_score'].astype(np.float64)
    return Recalibrator(tree, support, minimum_examples)


class OutputPolicy:
    def __init__(self, cfg: dict | None):
        cfg = dict(cfg or {})
        self.features = cfg.pop('features', 'full')
        self.decisions = cfg.pop('decisions', 'full')
        self.sample_every = int(cfg.pop('sample_every', 1000))
        if cfg or self.features not in ('full', 'off') or self.decisions not in ('full', 'positives') or self.sample_every < 1:
            raise ValueError('invalid outputs policy')
        self.seen = 0

    def keep_feature(self) -> bool:
        return self.features == 'full'

    def keep_decision(self, decision: dict) -> bool:
        if self.decisions == 'full':
            return True
        if decision.get('candidate_alert_preview') is True or decision.get('window_passed') is True:
            return True
        if decision.get('status') == SCORED:
            self.seen += 1
            return self.seen % self.sample_every == 0
        return False
