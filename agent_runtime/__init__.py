"""Agent Runtime Sentinel V2 components.

This package is the non-disruptive V2 extension path for the existing V1
eBPF/Tetragon + ML runtime sentinel.  V1 remains the production baseline; the
modules here add MCP-aware behavior graph primitives that can later be fed by
the eBPF TLS uprobe/ring-buffer collector.
"""

__all__ = ["mcp", "detector", "eval"]
