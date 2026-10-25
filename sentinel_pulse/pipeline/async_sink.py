"""Writes of the matched worker to shared storage, off the scoring loop (Pulse 5.26: the worker flushed its NFS
files at every frame, a latency risk; the page cache of those writes counts against the unit's MemoryMax).

``AsyncSink`` is a file whose lines are written by a background thread: ``write`` only queues, the thread writes,
flushes every ``flush_seconds`` and, every ``drop_cache_seconds``, makes the written data durable (``fdatasync``)
and drops it from the page cache (``POSIX_FADV_DONTNEED``). A full queue makes ``write`` wait (nothing is dropped)
and is counted. ``close`` drains the queue, fsyncs and closes, so a sealed segment holds every line.

``AsyncState`` keeps only the newest state document and writes it atomically from a background thread.
"""
from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path

_STOP = object()


class AsyncSink:
    def __init__(self, path: Path, max_lines: int = 200000, flush_seconds: float = 0.5, drop_cache_seconds: float = 30.0):
        self.path = Path(path)
        self.handle = self.path.open('x')
        self.queue = queue.Queue(max_lines)
        self.flush_seconds, self.drop_cache_seconds = flush_seconds, drop_cache_seconds
        self.stats = dict(lines=0, waits=0, max_queue=0, max_write_seconds=0.0, cache_drops=0)
        self.error = None
        self.thread = threading.Thread(target=self._run, name=f'sink-{self.path.name}', daemon=True)
        self.thread.start()

    def write(self, text: str):
        if self.error is not None:
            raise OSError(f'shared write failed: {self.error}')
        try:
            self.queue.put_nowait(text)
        except queue.Full:
            self.stats['waits'] += 1
            self.queue.put(text)
        self.stats['max_queue'] = max(self.stats['max_queue'], self.queue.qsize())

    def flush(self):
        """The background thread flushes; kept for the sink interface."""

    def fileno(self):
        return self.handle.fileno()

    def _run(self):
        last_flush = last_drop = time.monotonic()
        try:
            while True:
                try:
                    item = self.queue.get(timeout=self.flush_seconds)
                except queue.Empty:
                    item = None
                batch = [] if item is None else [item]
                while item is not _STOP and len(batch) < 4096:
                    try:
                        item = self.queue.get_nowait()
                    except queue.Empty:
                        break
                    batch.append(item)
                stop = bool(batch) and batch[-1] is _STOP
                lines = batch[:-1] if stop else batch
                t0 = time.monotonic()
                if lines:
                    self.handle.write(''.join(lines)); self.stats['lines'] += len(lines)
                now = time.monotonic()
                if stop or now - last_flush >= self.flush_seconds:
                    self.handle.flush(); last_flush = now
                if not stop and now - last_drop >= self.drop_cache_seconds:
                    self._drop_cache(); last_drop = now
                self.stats['max_write_seconds'] = max(self.stats['max_write_seconds'], time.monotonic() - t0)
                if stop:
                    return
        except (OSError, ValueError) as exc:          # ValueError: the file was closed under the thread
            self.error = str(exc) or type(exc).__name__

    def _drop_cache(self):
        self.handle.flush()
        os.fdatasync(self.handle.fileno())
        if hasattr(os, 'posix_fadvise'):
            os.posix_fadvise(self.handle.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        self.stats['cache_drops'] += 1

    def close(self):
        if self.thread.is_alive():
            self.queue.put(_STOP); self.thread.join()
        if not self.handle.closed:
            self.handle.flush(); os.fsync(self.handle.fileno()); self.handle.close()
        if self.error is not None:
            raise OSError(f'shared write failed: {self.error}')

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        return False


class AsyncState:
    """Newest-wins atomic JSON writer (worker STATUS.json on shared storage)."""

    def __init__(self, path: Path, write):
        self.path, self._write = Path(path), write
        self._doc, self._cond, self._stop = None, threading.Condition(), False
        self.thread = threading.Thread(target=self._run, name='state-writer', daemon=True)
        self.thread.start()

    def put(self, doc: dict):
        with self._cond:
            self._doc = dict(doc); self._cond.notify()

    def _run(self):
        while True:
            with self._cond:
                while self._doc is None and not self._stop:
                    self._cond.wait()
                doc, self._doc = self._doc, None
                stop = self._stop
            if doc is not None:
                try:
                    self._write(self.path, doc)
                except OSError:
                    pass                       # the next state retries; the loop never waits on shared storage
            if stop and doc is None:
                return

    def close(self, final: dict | None = None):
        with self._cond:
            if final is not None:
                self._doc = dict(final)
            self._stop = True; self._cond.notify()
        self.thread.join()
