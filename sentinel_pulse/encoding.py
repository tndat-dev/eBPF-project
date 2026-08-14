"""Stable compact encoding for high-volume one-second feature records."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib

import numpy as np


def schema_digest(columns) -> str:
    payload = json.dumps(list(columns), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def schema_record(columns) -> dict:
    return {
        "schema": "sentinel-pulse-feature-schema-v1",
        "feature_schema_sha256": schema_digest(columns),
        "vector_dim": len(columns),
        "columns": list(columns),
        "encoding": "float32-le+zlib-1+base64",
    }


def compact_record(record: dict) -> tuple[dict, dict]:
    result = dict(record)
    columns = result.pop("columns")
    vector = np.asarray(result.pop("vector"), dtype="<f4")
    schema = schema_record(columns)
    compressed = zlib.compress(vector.tobytes(order="C"), level=1)
    result["feature_schema_sha256"] = schema["feature_schema_sha256"]
    result["vector_dim"] = int(vector.size)
    result["vector_f32_zlib_b64"] = base64.b64encode(compressed).decode("ascii")
    return result, schema


def decode_vector(record: dict) -> np.ndarray:
    if "vector" in record:
        return np.asarray(record["vector"], dtype=np.float32)
    encoded = record.get("vector_f32_zlib_b64")
    if not encoded:
        raise ValueError("feature record has no supported vector encoding")
    raw = zlib.decompress(base64.b64decode(encoded, validate=True))
    vector = np.frombuffer(raw, dtype="<f4").astype(np.float32, copy=True)
    expected = int(record.get("vector_dim", -1))
    if expected < 0 or vector.size != expected:
        raise ValueError("decoded vector length mismatch")
    return vector
