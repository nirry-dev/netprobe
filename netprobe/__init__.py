"""netprobe — dependency-free TCP recon that produces a graph, not a wall of text.

Scan only hosts you are authorized to test.
"""
from .graph import Edge, Graph, Node, build_graph
from .scanner import PortResult, scan, scan_sync
from .targets import parse_ports, parse_targets

__version__ = "0.1.0"
__all__ = [
    "scan",
    "scan_sync",
    "PortResult",
    "Graph",
    "Node",
    "Edge",
    "build_graph",
    "parse_targets",
    "parse_ports",
    "__version__",
]
