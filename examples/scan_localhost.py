"""Scan your own machine and print the recon graph as JSON.

    python examples/scan_localhost.py

Everything here talks only to 127.0.0.1 — safe to run anywhere.
"""
from netprobe import build_graph, parse_ports, scan_sync

results = scan_sync(["127.0.0.1"], parse_ports("top"), timeout=1.0)
print(build_graph(results).to_json())
