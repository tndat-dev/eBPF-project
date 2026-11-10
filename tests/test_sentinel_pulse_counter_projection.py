import re
from pathlib import Path


from sentinel_pulse.collector.features import TRACKED_SYSCALLS

ROOT = Path(__file__).resolve().parents[1]
EBPF = ROOT / "sentinel_pulse" / "ebpf"


def test_projection_tracked_order_matches_249_feature_schema():
    rows = re.findall(r"X\((\d+), (\d+)\)", (EBPF / "pulse_counter_ids.h").read_text())
    assert [(int(i), int(s)) for i, s in rows] == [
        (identifier, slot) for slot, identifier in enumerate(TRACKED_SYSCALLS)
    ]


def test_map_abi_is_verified_before_attach_and_both_builds_exist():
    makefile = (EBPF / "Makefile").read_text()
    assert "matched: check-deps" in makefile and "tokens: check-deps" in makefile
    loader = (EBPF / "pulse_counter_loader.c").read_text()
    assert loader.index("counter map layout does not match loader") < loader.index(
        'bpf_program__attach_raw_tracepoint(program, "sys_enter")'
    )


def test_kernel_counts_every_syscall_id_once():
    kernel = (EBPF / "pulse_counter.bpf.c").read_text()
    assert "counters->full_counts[syscall_id]++;" in kernel
    assert kernel.count("full_counts[") == 2      # the declaration and the one increment
