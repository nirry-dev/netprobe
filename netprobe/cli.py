"""Command-line interface: ``netprobe scan <targets> -p <ports>``."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .graph import build_graph
from .scanner import scan_sync
from .targets import parse_ports, parse_targets


def _detail(result) -> str:
    info = result.info or {}
    for key in ("title", "server", "cert_cn", "location"):
        if info.get(key):
            return str(info[key])
    if result.banner:
        return result.banner
    if info.get("tls"):
        return info["tls"]
    return ""


def _print_table(results, stream) -> None:
    if not results:
        print("no open ports found", file=stream)
        return
    hosts = sorted({r.host for r in results})
    print(f"{len(results)} open port(s) across {len(hosts)} host(s)\n", file=stream)
    print(f"  {'HOST':<18}{'PORT':<7}{'SERVICE':<14}DETAIL", file=stream)
    for r in results:
        print(
            f"  {r.host:<18}{r.port:<7}{(r.service or 'tcp'):<14}{_detail(r)[:72]}",
            file=stream,
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description=(
            "Dependency-free TCP recon that produces a graph, not a wall of text. "
            "Scan only hosts you are authorized to test."
        ),
    )
    parser.add_argument("--version", action="version", version=f"netprobe {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="scan hosts and ports")
    scan_p.add_argument("targets", nargs="+", help="host, IP, or CIDR (e.g. 10.0.0.0/28)")
    scan_p.add_argument(
        "-p", "--ports", default="top",
        help="'top' (default), 'all', a range '1-1024', a list '22,80,443', or a mix",
    )
    scan_p.add_argument(
        "-c", "--concurrency", type=int, default=512,
        help="max simultaneous connections (default 512)",
    )
    scan_p.add_argument(
        "-t", "--timeout", type=float, default=2.0,
        help="per-connection timeout in seconds (default 2.0)",
    )
    scan_p.add_argument(
        "--no-fingerprint", action="store_true",
        help="only test openness; skip banner/HTTP/TLS probing",
    )
    out = scan_p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="emit the recon graph as JSON")
    out.add_argument("--dot", action="store_true", help="emit the recon graph as Graphviz dot")

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 2

    hosts: list[str] = []
    for spec in args.targets:
        try:
            hosts.extend(parse_targets(spec))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    ports = parse_ports(args.ports)
    if not ports:
        print("error: no valid ports in --ports", file=sys.stderr)
        return 2

    results = scan_sync(
        hosts,
        ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        fingerprint=not args.no_fingerprint,
    )

    if args.json:
        print(build_graph(results).to_json())
    elif args.dot:
        print(build_graph(results).to_dot())
    else:
        _print_table(results, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
