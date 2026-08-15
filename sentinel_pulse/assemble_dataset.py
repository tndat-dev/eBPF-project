"""Assemble immutable multi-node Pulse captures under a preregistered contract."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import stat
import tempfile

from .integrity import sha256_file


def load_contract(path: Path) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    if contract.get("schema") != "sentinel-pulse-capture-contract-v1":
        raise ValueError("unsupported capture contract")
    if contract.get("normal_only") is not True:
        raise ValueError("training capture contract must be normal-only")
    intervals = sorted(contract.get("intervals", []), key=lambda item: float(item["start"]))
    if not intervals:
        raise ValueError("capture contract has no traffic interval")
    previous_end = None
    regimes = set()
    for item in intervals:
        start, end = float(item["start"]), float(item["end"])
        regime = str(item["regime"])
        if end <= start:
            raise ValueError(f"invalid interval for regime {regime}")
        if previous_end is not None and start < previous_end:
            raise ValueError("capture contract intervals overlap")
        if regime in regimes:
            raise ValueError(f"duplicate traffic regime: {regime}")
        previous_end = end
        regimes.add(regime)
    contract["intervals"] = intervals
    expected = contract.get("expected_nodes", [])
    if not expected or len(expected) != len(set(expected)):
        raise ValueError("expected_nodes must be a non-empty unique list")
    return contract


def parse_sources(values: list[str]) -> dict[str, Path]:
    result = {}
    for value in values:
        node, separator, raw_path = value.partition("=")
        if not separator or not node or not raw_path or node in result:
            raise ValueError(f"invalid or duplicate --capture value: {value}")
        path = Path(raw_path)
        if not path.is_file():
            raise ValueError(f"capture source does not exist: {path}")
        result[node] = path
    return result


def verify_source_manifests(
    contract_path: Path,
    contract: dict,
    sources: dict[str, Path],
    manifest_paths: dict[str, Path],
) -> dict[str, dict]:
    expected_nodes = set(map(str, contract["expected_nodes"]))
    if set(manifest_paths) != expected_nodes:
        raise ValueError(
            "capture manifest node set differs from contract: "
            f"expected={sorted(expected_nodes)}, observed={sorted(manifest_paths)}"
        )
    contract_sha256 = sha256_file(contract_path)
    campaign_start = min(float(item["start"]) for item in contract["intervals"])
    campaign_end = max(float(item["end"]) for item in contract["intervals"])
    manifests = {}
    for node in sorted(expected_nodes):
        source = sources[node]
        mode = source.stat().st_mode
        if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"capture source is not immutable/read-only: {source}")
        manifest_path = manifest_paths[node]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_schema = manifest.get("schema")
        if manifest_schema not in {
            "sentinel-pulse-node-capture-manifest-v1",
            "sentinel-pulse-node-capture-manifest-v2",
        }:
            raise ValueError(f"unsupported node capture manifest for {node}")
        expected = {
            "campaign_id": contract["campaign_id"],
            "contract_sha256": contract_sha256,
            "node_name": node,
            "capture_sha256": sha256_file(source),
            "capture_bytes": source.stat().st_size,
        }
        observed = {name: manifest.get(name) for name in expected}
        if observed != expected:
            raise ValueError(
                f"node capture manifest provenance mismatch for {node}: "
                f"expected={expected}, observed={observed}"
            )
        if float(manifest.get("campaign_start", -1)) != campaign_start:
            raise ValueError(f"node capture manifest start differs from contract for {node}")
        if float(manifest.get("campaign_end", -1)) != campaign_end:
            raise ValueError(f"node capture manifest end differs from contract for {node}")
        # V1 called the full first-to-last interval span "in_contract_rows",
        # including preregistered transition gaps. V2 names that value
        # campaign_span_rows. The assembler itself is the authority for rows
        # inside the disjoint measured intervals.
        if manifest_schema == "sentinel-pulse-node-capture-manifest-v1":
            campaign_span_rows = int(manifest.get("in_contract_rows", 0))
        else:
            campaign_span_rows = int(manifest.get("campaign_span_rows", 0))
        if campaign_span_rows <= 0:
            raise ValueError(f"node capture manifest has no campaign-span row for {node}")
        bad_integrity = {
            name: value
            for name, value in manifest.get("collector_max_integrity", {}).items()
            if int(value) != 0
        }
        if bad_integrity:
            raise ValueError(
                f"node capture manifest has non-zero integrity counters for {node}: "
                f"{bad_integrity}"
            )
        manifest["_campaign_span_rows"] = campaign_span_rows
        manifests[node] = manifest
    return manifests


def interval_for(record: dict, intervals: list[dict]) -> dict | None:
    start = float(record["window_start"])
    end = float(record["window_end"])
    for item in intervals:
        if start >= float(item["start"]) and end <= float(item["end"]):
            return item
    return None


def assemble(
    contract_path: Path,
    sources: dict[str, Path],
    source_manifest_paths: dict[str, Path],
    output: Path,
) -> dict:
    contract = load_contract(contract_path)
    expected_nodes = set(map(str, contract["expected_nodes"]))
    if set(sources) != expected_nodes:
        raise ValueError(
            f"capture node set differs from contract: expected={sorted(expected_nodes)}, "
            f"observed={sorted(sources)}"
        )
    source_manifests = verify_source_manifests(
        contract_path, contract, sources, source_manifest_paths
    )
    campaign_start = min(float(item["start"]) for item in contract["intervals"])
    campaign_end = max(float(item["end"]) for item in contract["intervals"])
    if output.exists():
        raise ValueError(f"refusing to overwrite immutable dataset: {output}")
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    if manifest_path.exists():
        raise ValueError(f"refusing to overwrite immutable dataset manifest: {manifest_path}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    rows = 0
    excluded = 0
    by_node = Counter()
    by_regime = Counter()
    span_by_node = Counter()
    schema_hash = None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            for source_node, source_path in sorted(sources.items()):
                source_rows = 0
                source_span_rows = 0
                with source_path.open(encoding="utf-8") as source:
                    for line_number, line in enumerate(source, 1):
                        record = json.loads(line)
                        if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                            current_hash = record.get("feature_schema_sha256")
                            if schema_hash is None:
                                schema_hash = current_hash
                                destination.write(json.dumps(record, separators=(",", ":")) + "\n")
                            elif current_hash != schema_hash:
                                raise ValueError(
                                    f"{source_path}:{line_number}: feature schema drift"
                                )
                            continue
                        if record.get("schema") != "sentinel-pulse-feature-v1":
                            raise ValueError(f"{source_path}:{line_number}: unsupported record")
                        source_rows += 1
                        if str(record.get("node_name")) != source_node:
                            raise ValueError(
                                f"{source_path}:{line_number}: node identity does not match source"
                            )
                        window_start = float(record["window_start"])
                        window_end = float(record["window_end"])
                        if window_start >= campaign_start and window_end <= campaign_end:
                            source_span_rows += 1
                            span_by_node[source_node] += 1
                        interval = interval_for(record, contract["intervals"])
                        if interval is None:
                            excluded += 1
                            continue
                        if record.get("feature_schema_sha256") != schema_hash:
                            raise ValueError(
                                f"{source_path}:{line_number}: row schema differs from header"
                            )
                        record["campaign_id"] = contract["campaign_id"]
                        record["traffic_regime"] = interval["regime"]
                        destination.write(json.dumps(record, separators=(",", ":")) + "\n")
                        rows += 1
                        by_node[source_node] += 1
                        by_regime[str(interval["regime"])] += 1
                node_manifest = source_manifests[source_node]
                if source_rows != int(node_manifest["rows"]):
                    raise ValueError(
                        f"capture row count differs from node manifest for {source_node}"
                    )
                if source_span_rows != int(node_manifest["_campaign_span_rows"]):
                    raise ValueError(
                        f"campaign-span row count differs from node manifest for {source_node}"
                    )
            destination.flush()
            os.fsync(destination.fileno())
        if rows == 0 or schema_hash is None:
            raise ValueError("assembled dataset has no in-contract feature row")
        os.replace(temporary_name, output)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    manifest = {
        "schema": "sentinel-pulse-dataset-manifest-v1",
        "campaign_id": contract["campaign_id"],
        "normal_only": True,
        "contract": str(contract_path),
        "contract_sha256": sha256_file(contract_path),
        "dataset": str(output),
        "dataset_sha256": sha256_file(output),
        "feature_schema_sha256": schema_hash,
        "rows": rows,
        "excluded_outside_contract": excluded,
        "rows_by_node": dict(sorted(by_node.items())),
        "campaign_span_rows_by_node": dict(sorted(span_by_node.items())),
        "source_manifest_schema": {
            node: source_manifests[node]["schema"] for node in sorted(source_manifests)
        },
        "rows_by_regime": dict(sorted(by_regime.items())),
        "source_sha256": {
            node: {"path": str(path), "sha256": sha256_file(path)}
            for node, path in sorted(sources.items())
        },
        "source_manifest_sha256": {
            node: {
                "path": str(source_manifest_paths[node]),
                "sha256": sha256_file(source_manifest_paths[node]),
            }
            for node in sorted(source_manifest_paths)
        },
    }
    manifest_temporary = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    manifest_temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(manifest_temporary, manifest_path)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--capture", action="append", required=True, metavar="NODE=PATH")
    parser.add_argument(
        "--capture-manifest", action="append", required=True, metavar="NODE=PATH"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = assemble(
        args.contract,
        parse_sources(args.capture),
        parse_sources(args.capture_manifest),
        args.output,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
