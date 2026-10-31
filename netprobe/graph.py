"""A tiny normalized recon graph: hosts and the services they expose.

Every probe result becomes nodes and edges in one model, so results compose and
feed downstream tools (or a Graphviz render) instead of being terminal text.
This is the idea the whole tool is built around.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Node:
    id: str
    kind: str  # "host" | "service"
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str  # e.g. "exposes"
    attrs: dict = field(default_factory=dict)


class Graph:
    """Append-only graph with node de-duplication (attrs merge) and edge de-duplication."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple, Edge] = {}

    def add_node(self, node: Node) -> Node:
        existing = self._nodes.get(node.id)
        if existing is not None:
            existing.attrs.update(node.attrs)
            if node.label and not existing.label:
                existing.label = node.label
            return existing
        self._nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> Edge:
        key = (edge.src, edge.dst, edge.kind)
        existing = self._edges.get(key)
        if existing is not None:
            existing.attrs.update(edge.attrs)
            return existing
        self._edges[key] = edge
        return edge

    @property
    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "kind": n.kind, "label": n.label, "attrs": n.attrs}
                for n in self._nodes.values()
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "kind": e.kind, "attrs": e.attrs}
                for e in self._edges.values()
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_dot(self) -> str:
        lines = [
            "digraph netprobe {",
            "  rankdir=LR;",
            '  node [fontname="monospace"];',
        ]
        for n in self._nodes.values():
            shape = "box" if n.kind == "host" else "ellipse"
            lines.append(f'  "{n.id}" [label="{_dot_escape(n.label)}", shape={shape}];')
        for e in self._edges.values():
            lines.append(f'  "{e.src}" -> "{e.dst}" [label="{_dot_escape(e.kind)}"];')
        lines.append("}")
        return "\n".join(lines)


def _dot_escape(s) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def build_graph(results) -> Graph:
    """Build a host->service graph from an iterable of open ``PortResult``s."""
    g = Graph()
    for r in results:
        if not getattr(r, "is_open", True):
            continue
        host_id = f"host:{r.host}"
        g.add_node(Node(host_id, "host", r.host))

        svc_id = f"svc:{r.host}:{r.port}"
        attrs = {"port": r.port, "service": r.service or "tcp"}
        if r.banner:
            attrs["banner"] = r.banner
        attrs.update(r.info or {})
        g.add_node(Node(svc_id, "service", f"{r.port}/{r.service or 'tcp'}", attrs))

        g.add_edge(Edge(host_id, svc_id, "exposes", {"port": r.port}))
    return g
