import re
import shutil
import subprocess
from pathlib import Path


from sentinel_pulse.features import TRACKED_SYSCALLS

ROOT = Path(__file__).resolve().parents[1]
EBPF = ROOT / "sentinel_pulse" / "ebpf"


def test_projection_preserves_all_syscall_histograms_and_rejects_overflow(tmp_path):
    cc = shutil.which("cc")
    assert cc, "C compiler required to validate the collector projection"
    binary = tmp_path / "projection-test"
    subprocess.run([
        cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", str(EBPF), str(ROOT / "tests/c/pulse_counter_projection.c"),
        "-o", str(binary),
    ], check=True, capture_output=True, text=True, timeout=30)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=5)
    assert "1024 IDs x 4 CPUs" in result.stdout
    assert "PASS" in result.stdout


def test_projection_tracked_order_matches_249_feature_schema():
    rows = re.findall(r"X\((\d+), (\d+)\)", (EBPF / "pulse_counter_ids.h").read_text())
    assert [(int(i), int(s)) for i, s in rows] == [
        (identifier, slot) for slot, identifier in enumerate(TRACKED_SYSCALLS)
    ]


def test_projection_is_opt_in_and_map_abi_is_verified_before_attach():
    makefile = (EBPF / "Makefile").read_text()
    assert "all: check-deps pulse_counter.bpf.o pulse_counter_loader" in makefile
    assert "-DPULSE_PROJECTED_COUNTERS" in makefile
    loader = (EBPF / "pulse_counter_loader.c").read_text()
    assert loader.index("counter map layout does not match loader") < loader.index(
        'bpf_program__attach_raw_tracepoint(program, "sys_enter")'
    )


def test_projection_kernel_tracked_writes_expand_constant_cases():
    kernel = (EBPF / "pulse_counter.bpf.c").read_text()
    assert "case number: counters->tracked[slot]++; return 1;" in kernel
    assert "PULSE_TRACKED_ROWS(PULSE_CASE)" in kernel
    assert "if (!increment_projected_tracked(counters, syscall_id))" in kernel






