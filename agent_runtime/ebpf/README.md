# Agent Runtime Sentinel V2 — eBPF Layer 1

Layer 1 must stay intentionally small:

1. attach uprobes to TLS functions such as `SSL_read` and `SSL_write`;
2. copy a bounded slice of decrypted bytes into a BPF ring buffer;
3. let userspace parse MCP JSON-RPC and build the behavior graph.

Do not parse JSON in eBPF. The verifier constraints and stack limits make full
JSON-RPC parsing the wrong place for kernel code. This directory is a scaffold
for the future libbpf/cilium-ebpf implementation; the current production V7
detector remains based on Tetragon syscall events.

`Makefile` now builds the BPF object and a minimal libbpf loader. The loader
resolves both OpenSSL 3 write symbols (`SSL_write`, `SSL_write_ex`), requires an explicit PID, and
prints metadata only, so it cannot silently collect plaintext from unrelated
host processes:

Prerequisites are checked before every build: `clang`, a C compiler, `bpftool`,
kernel BTF at `/sys/kernel/btf/vmlinux`, and libbpf headers. Run the check on
its own when preparing a host:

```bash
make check-deps
```

On Ubuntu, the usual development packages are `clang`, `build-essential`,
`bpftool`, `libbpf-dev`, and `libelf-dev`. The probe must be built against the
BTF of the host where it will be loaded.

```bash
make
sudo ./mcp_probe_loader --object mcp_probe.bpf.o \
  --libssl /usr/lib/x86_64-linux-gnu/libssl.so.3 --pid <controlled-pid>
```

Mặc định loader chỉ in metadata. Với một PID lab đã được xác định rõ, có thể
thêm `--emit-payload` và pipe trực tiếp vào `agent_runtime.ring_reader`; dữ liệu
plaintext không được ghi file. Reader reassemble HTTP/JSON bị phân mảnh theo PID
rồi chuyển document hoàn chỉnh sang MCP runtime. Không dùng cờ này cho process
ngoài scope thử nghiệm.
