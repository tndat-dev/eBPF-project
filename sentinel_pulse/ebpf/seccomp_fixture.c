// SPDX-License-Identifier: GPL-2.0
// [VI] Fixture của token_probe_proof.py: tái dùng process con có bộ lọc seccomp của visibility_probe.c (không gắn probe), để proof
// [VI] kiểm đường seccomp của build token (syscall bị chặn vẫn cho đúng một token).
/* Reuse the audited child-only filter and bounded fixture, without probes. */
#define main visibility_probe_unused_entrypoint
#include "visibility_probe.c"
#undef main
int main(void) { return fixture(); }
