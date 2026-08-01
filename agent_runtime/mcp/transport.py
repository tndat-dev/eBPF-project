"""Bounded reconstruction of MCP JSON-RPC from TLS plaintext chunks.

OpenSSL uprobes expose application bytes, not message boundaries.  An HTTP
request or JSON-RPC batch can therefore be split across several SSL_write
calls.  This module is deliberately userspace-only and keeps a small bounded
buffer per controlled process before passing complete JSON bodies to the MCP
parser.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class TLSJSONReassembler:
    """Recover complete JSON-RPC documents from raw or HTTP TLS plaintext."""

    max_buffer_bytes: int = 16 * 1024
    _buffer: bytes = field(default=b"", init=False, repr=False)

    def feed(self, chunk: bytes) -> list[bytes]:
        if not chunk:
            return []
        self._buffer = (self._buffer + chunk)[-self.max_buffer_bytes :]
        documents: list[bytes] = []
        while self._buffer:
            if self._looks_like_http(self._buffer):
                document = self._pop_http_body()
                if document is None:
                    break
                if document:
                    documents.append(document)
                continue
            document = self._pop_raw_json()
            if document is None:
                break
            documents.append(document)
        return documents

    @staticmethod
    def _looks_like_http(buffer: bytes) -> bool:
        return buffer.startswith((b"POST ", b"PUT ", b"PATCH "))

    def _pop_http_body(self) -> bytes | None:
        marker = self._buffer.find(b"\r\n\r\n")
        if marker < 0:
            return None
        headers = self._buffer[:marker].decode("latin-1", errors="ignore")
        content_length = _content_length(headers)
        if content_length is None:
            # Unsupported framing must not poison following captures forever.
            self._buffer = self._buffer[marker + 4 :]
            return b""
        body_start = marker + 4
        body_end = body_start + content_length
        if len(self._buffer) < body_end:
            return None
        body = self._buffer[body_start:body_end]
        self._buffer = self._buffer[body_end:]
        return body

    def _pop_raw_json(self) -> bytes | None:
        stripped = self._buffer.lstrip()
        if stripped != self._buffer:
            self._buffer = stripped
        if not self._buffer:
            return b""
        if self._buffer[:1] not in {b"{", b"["}:
            # Scan forward only to a plausible document boundary.  This
            # prevents a non-MCP TLS stream from accumulating indefinitely.
            starts = [position for position in (self._buffer.find(b"{"), self._buffer.find(b"[")) if position >= 0]
            if not starts:
                self._buffer = b""
                return b""
            self._buffer = self._buffer[min(starts):]
        try:
            text = self._buffer.decode("utf-8")
            _, end = json.JSONDecoder().raw_decode(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        document = text[:end].encode("utf-8")
        self._buffer = text[end:].encode("utf-8")
        return document


def _content_length(headers: str) -> int | None:
    for line in headers.split("\r\n")[1:]:
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "content-length":
            try:
                length = int(value.strip())
            except ValueError:
                return None
            return length if 0 <= length <= 16 * 1024 else None
    return None
