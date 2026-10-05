CLANG ?= clang
CC ?= cc
ARCH ?= x86
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

.PHONY: all check-deps clean

all: check-deps pulse_counter.bpf.o pulse_counter_loader

check-deps:
	@command -v $(CLANG) >/dev/null || { echo "missing clang" >&2; exit 1; }
	@command -v $(CC) >/dev/null || { echo "missing C compiler" >&2; exit 1; }
	@command -v bpftool >/dev/null || { echo "missing bpftool" >&2; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "missing kernel BTF" >&2; exit 1; }
	@test -r /usr/include/bpf/libbpf.h || { echo "missing libbpf headers" >&2; exit 1; }

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

pulse_counter.bpf.o: pulse_counter.bpf.c pulse_counter_ids.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

pulse_counter_loader: pulse_counter_loader.c pulse_counter_ids.h pulse_counter_projection.h
	$(CC) -O2 -Wall -Wextra $< -o $@ -lbpf -lelf -lz

# Explicit opt-in; default/all and installed production binaries stay legacy.
.PHONY: projected
projected: check-deps pulse_counter_projected.bpf.o pulse_counter_projected_loader

pulse_counter_projected.bpf.o: pulse_counter.bpf.c pulse_counter_ids.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -DPULSE_PROJECTED_COUNTERS -c $< -o $@

pulse_counter_projected_loader: pulse_counter_loader.c pulse_counter_projection.h pulse_counter_ids.h
	$(CC) -O2 -Wall -Wextra -DPULSE_PROJECTED_COUNTERS $< -o $@ -lbpf -lelf -lz

clean:
	rm -f pulse_counter.bpf.o pulse_counter_loader vmlinux.h
