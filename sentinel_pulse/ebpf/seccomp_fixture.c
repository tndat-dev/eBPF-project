// SPDX-License-Identifier: GPL-2.0
/* Reuse the audited child-only filter and bounded fixture, without probes. */
#define main visibility_probe_unused_entrypoint
#include "visibility_probe.c"
#undef main
int main(void) { return fixture(); }
