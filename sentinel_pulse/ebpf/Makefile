CLANG ?= clang
CC ?= cc
ARCH ?= x86
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

.PHONY: check-deps

check-deps:
	@command -v $(CLANG) >/dev/null || { echo "missing clang" >&2; exit 1; }
	@command -v $(CC) >/dev/null || { echo "missing C compiler" >&2; exit 1; }
	@command -v bpftool >/dev/null || { echo "missing bpftool" >&2; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "missing kernel BTF" >&2; exit 1; }
	@test -r /usr/include/bpf/libbpf.h || { echo "missing libbpf headers" >&2; exit 1; }

# Isolated proof of the pre-sys_enter seccomp visibility boundary. No default
# collector, map layout, installed binary or frozen candidate is changed.
.PHONY: visibility
visibility: check-deps
	@test -n "$(VISIBILITY_BUILD_DIR)" || { echo 'explicit VISIBILITY_BUILD_DIR required' >&2; exit 2; }
	mkdir -p "$(VISIBILITY_BUILD_DIR)"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$(VISIBILITY_BUILD_DIR)/vmlinux.h"
	$(CLANG) $(BPF_CFLAGS) -I"$(VISIBILITY_BUILD_DIR)" -c visibility_probe.bpf.c -o "$(VISIBILITY_BUILD_DIR)/visibility_probe.bpf.o"
	$(CC) -O2 -Wall -Wextra -Werror visibility_probe.c -o "$(VISIBILITY_BUILD_DIR)/visibility_probe" -lbpf -lelf -lz

# The matched observable, the probe of the final system: full syscall-ID counts per cgroup, the transition sketch
# and the seccomp skip hook. The legacy, projected-only and tracked-slot variants and the exec-intent counters are at
# tag archive/pre-audit-20261110.
.PHONY: matched
matched: check-deps
	@test -n "$(MATCHED_BUILD_DIR)" || { echo 'explicit MATCHED_BUILD_DIR required' >&2; exit 2; }
	mkdir -p "$(MATCHED_BUILD_DIR)"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$(MATCHED_BUILD_DIR)/vmlinux.h"
	$(CLANG) $(BPF_CFLAGS) -I"$(MATCHED_BUILD_DIR)" -c pulse_counter.bpf.c -o "$(MATCHED_BUILD_DIR)/pulse_counter_extended.bpf.o"
	$(CC) -O2 -Wall -Wextra -Werror pulse_counter_loader.c -o "$(MATCHED_BUILD_DIR)/pulse_counter_extended_loader" -lbpf -lelf -lz
	$(CC) -O2 -Wall -Wextra -Werror seccomp_fixture.c -o "$(MATCHED_BUILD_DIR)/seccomp_fixture" -lbpf -lelf -lz

# Token probe of the lidds-ml token branch (reports/Thiết kế probe token Pulse.md): the matched observable plus the
# select1f tokens (one raw_tp/sys_exit program) and the per-window 4-gram map.
.PHONY: tokens
tokens: check-deps
	@test -n "$(TOKENS_BUILD_DIR)" || { echo 'explicit TOKENS_BUILD_DIR required' >&2; exit 2; }
	mkdir -p "$(TOKENS_BUILD_DIR)"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$(TOKENS_BUILD_DIR)/vmlinux.h"
	$(CLANG) $(BPF_CFLAGS) -I"$(TOKENS_BUILD_DIR)" -DPULSE_TOKENS -c pulse_counter.bpf.c -o "$(TOKENS_BUILD_DIR)/pulse_counter_tokens.bpf.o"
	$(CC) -O2 -Wall -Wextra -Werror -DPULSE_TOKENS pulse_counter_loader.c -o "$(TOKENS_BUILD_DIR)/pulse_counter_tokens_loader" -lbpf -lelf -lz
	$(CC) -O2 -Wall -Wextra -Werror seccomp_fixture.c -o "$(TOKENS_BUILD_DIR)/seccomp_fixture" -lbpf -lelf -lz
	$(CC) -O2 -Wall -Wextra -Werror ../../testbed/bench/syscall_bench.c -o "$(TOKENS_BUILD_DIR)/syscall_bench"
