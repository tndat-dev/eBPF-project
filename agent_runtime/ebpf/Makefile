CLANG ?= clang
CC ?= cc
ARCH ?= x86
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

.PHONY: all check-deps clean

all: check-deps mcp_probe.bpf.o mcp_probe_loader

check-deps:
	@command -v $(CLANG) >/dev/null || { echo "missing $(CLANG): install clang" >&2; exit 1; }
	@command -v $(CC) >/dev/null || { echo "missing $(CC): install build-essential" >&2; exit 1; }
	@command -v bpftool >/dev/null || { echo "missing bpftool: install linux-tools-$(shell uname -r) or bpftool" >&2; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "missing kernel BTF at /sys/kernel/btf/vmlinux" >&2; exit 1; }
	@test -r /usr/include/bpf/libbpf.h || { echo "missing libbpf headers: install libbpf-dev" >&2; exit 1; }

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

mcp_probe.bpf.o: mcp_probe.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

mcp_probe_loader: mcp_probe_loader.c
	$(CC) -O2 -Wall -Wextra $< -o $@ -lbpf -lelf -lz

clean:
	rm -f mcp_probe.bpf.o mcp_probe_loader vmlinux.h
