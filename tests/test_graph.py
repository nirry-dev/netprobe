import json
import unittest

from netprobe.graph import Edge, Graph, Node, build_graph
from netprobe.scanner import PortResult


class GraphOps(unittest.TestCase):
    def test_node_merge(self):
        g = Graph()
        g.add_node(Node("h", "host", "H", {"a": 1}))
        g.add_node(Node("h", "host", "", {"b": 2}))
        self.assertEqual(len(g.nodes), 1)
        self.assertEqual(g.nodes[0].attrs, {"a": 1, "b": 2})

    def test_edge_dedupe_merges_attrs(self):
        g = Graph()
        g.add_edge(Edge("a", "b", "exposes"))
        g.add_edge(Edge("a", "b", "exposes", {"port": 80}))
        self.assertEqual(len(g.edges), 1)
        self.assertEqual(g.edges[0].attrs, {"port": 80})

    def test_dot_escapes_quotes(self):
        g = Graph()
        g.add_node(Node("n", "service", 'a"b'))
        self.assertIn(r"\"", g.to_dot())


class BuildGraph(unittest.TestCase):
    def test_from_results(self):
        results = [
            PortResult("10.0.0.1", 22, True, "ssh", "SSH-2.0-x"),
            PortResult("10.0.0.1", 443, True, "https", "", {"cert_cn": "x.test", "tls": "TLSv1.3"}),
        ]
        g = build_graph(results)
        self.assertEqual(sorted(n.kind for n in g.nodes), ["host", "service", "service"])
        self.assertEqual(len(g.edges), 2)
        doc = json.loads(g.to_json())
        self.assertEqual(len(doc["nodes"]), 3)
        svc = next(n for n in doc["nodes"] if n["id"] == "svc:10.0.0.1:443")
        self.assertEqual(svc["attrs"]["cert_cn"], "x.test")

    def test_skips_closed(self):
        g = build_graph([PortResult("h", 1, False)])
        self.assertEqual(len(g.nodes), 0)


if __name__ == "__main__":
    unittest.main()
