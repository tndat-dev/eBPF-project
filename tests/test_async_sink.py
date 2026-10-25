import json
import threading
import time

import pytest

from sentinel_pulse.common import atomic_json
from sentinel_pulse.pipeline.async_sink import AsyncSink, AsyncState


def test_every_line_is_written_in_order_and_close_drains(tmp_path):
    path = tmp_path / 'features.jsonl'
    with AsyncSink(path, max_lines=50, flush_seconds=.01, drop_cache_seconds=.02) as sink:
        for i in range(5000):
            sink.write(f'{i}\n')
        sink.flush()
    assert path.read_text().splitlines() == [str(i) for i in range(5000)]
    assert sink.stats['lines'] == 5000 and sink.stats['waits'] > 0          # a full queue waited, nothing dropped
    with pytest.raises(FileExistsError):
        AsyncSink(path)                                                      # same exclusive create as the worker


def test_lines_reach_the_file_without_close(tmp_path):
    path = tmp_path / 'decisions.jsonl'
    sink = AsyncSink(path, flush_seconds=.02, drop_cache_seconds=.05)
    sink.write('a\n')
    deadline = time.time() + 3
    while path.read_text() != 'a\n' and time.time() < deadline:
        time.sleep(.01)
    assert path.read_text() == 'a\n'
    time.sleep(.1)
    assert sink.stats['cache_drops'] >= 1
    sink.close(); sink.close()                                               # idempotent


def test_a_write_error_surfaces_in_the_scoring_loop(tmp_path):
    sink = AsyncSink(tmp_path / 'x.jsonl', flush_seconds=.01)
    sink.handle.close()                                                      # the shared file system goes away
    sink.write('a\n')
    deadline = time.time() + 3
    while sink.error is None and time.time() < deadline:
        time.sleep(.01)
    with pytest.raises(OSError, match='shared write failed'):
        sink.write('b\n')


def test_state_writer_keeps_the_newest_document(tmp_path):
    path = tmp_path / 'STATUS.json'
    gate, writes = threading.Event(), []

    def slow_write(p, doc):
        gate.wait(2); writes.append(doc['n']); atomic_json(p, doc)

    state = AsyncState(path, slow_write)
    for n in range(100):
        state.put(dict(n=n))
    gate.set()
    state.close(final=dict(n='final'))
    assert json.loads(path.read_text()) == dict(n='final')
    assert len(writes) < 100 and writes[-1] == 'final'                       # superseded states were skipped
