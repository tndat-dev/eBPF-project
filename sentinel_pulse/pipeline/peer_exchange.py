"""Exchange per-window syscall-ID masks between the workers of a live run (peer novelty, Pulse 5.22 / 5.25).

Each worker serves its own windows to every subscriber and subscribes to every other worker, one JSON line per
window (``PeerNovelty.local`` builds the message). Only the scoring loop touches the novelty state; the sockets
live in threads and meet it through queues.

Failure is one-sided by design: a slow subscriber loses messages (counted) instead of slowing the scoring loop,
and a lost peer only means fewer peer windows, i.e. less discount, so the detector alerts more, never less.
"""
from __future__ import annotations

import json
import queue
import socket
import threading


class PeerExchange:
    def __init__(self, listen, peers, *, max_queue: int = 20000, retry_seconds: float = 2.0):
        self.listen = (str(listen[0]), int(listen[1]))
        self.peers = [(str(h), int(p)) for h, p in peers]
        self.max_queue, self.retry = int(max_queue), float(retry_seconds)
        self.inbound = queue.Queue(maxsize=self.max_queue)
        self.subscribers = []                       # list of queue.Queue, one per connected subscriber
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.counters = dict(published=0, sent_dropped=0, received=0, received_dropped=0, connects=0,
                             disconnects=0, subscribers_accepted=0)
        self.connected = {f'{h}:{p}': False for h, p in self.peers}
        self.server = None

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        self.server = socket.create_server(self.listen, reuse_port=False)
        self.server.settimeout(1.0)
        self.listen = self.server.getsockname()[:2]   # the bound port when 0 was asked (tests)
        threading.Thread(target=self._accept, daemon=True, name='peer-accept').start()
        for peer in self.peers:
            threading.Thread(target=self._follow, args=(peer,), daemon=True, name=f'peer-{peer[0]}').start()
        return self

    def close(self):
        self.stop.set()
        if self.server is not None:
            self.server.close()

    # ------------------------------------------------------------------ scoring-loop side
    def publish(self, messages):
        if not messages:
            return
        data = ''.join(json.dumps(m, separators=(',', ':')) + '\n' for m in messages).encode()
        with self.lock:
            targets = list(self.subscribers)
        self.counters['published'] += len(messages)
        for q in targets:
            try:
                q.put_nowait((len(messages), data))
            except queue.Full:
                self.counters['sent_dropped'] += len(messages)

    def drain(self):
        out = []
        while True:
            try:
                out.append(self.inbound.get_nowait())
            except queue.Empty:
                return out

    def stats(self):
        return dict(self.counters, peers_connected=dict(self.connected), subscribers=len(self.subscribers))

    # ------------------------------------------------------------------ threads
    def _accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            q = queue.Queue(maxsize=self.max_queue)
            with self.lock:
                self.subscribers.append(q)
            self.counters['subscribers_accepted'] += 1
            threading.Thread(target=self._serve, args=(conn, q), daemon=True, name='peer-serve').start()

    def _serve(self, conn, q):
        try:
            while not self.stop.is_set():
                try:
                    _, data = q.get(timeout=1.0)
                except queue.Empty:
                    continue
                conn.sendall(data)
        except OSError:
            pass
        finally:
            with self.lock:
                if q in self.subscribers:
                    self.subscribers.remove(q)
            conn.close()

    def _follow(self, peer):
        name = f'{peer[0]}:{peer[1]}'
        while not self.stop.is_set():
            try:
                with socket.create_connection(peer, timeout=self.retry) as conn:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    conn.settimeout(None)
                    self.connected[name] = True
                    self.counters['connects'] += 1
                    for line in conn.makefile('r', encoding='utf-8'):
                        if self.stop.is_set():
                            return
                        try:
                            self.inbound.put_nowait(json.loads(line))
                            self.counters['received'] += 1
                        except queue.Full:
                            self.counters['received_dropped'] += 1
            except (OSError, ValueError):
                pass
            if self.connected[name]:
                self.counters['disconnects'] += 1
            self.connected[name] = False
            self.stop.wait(self.retry)
