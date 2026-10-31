"""Parse scan targets (hosts / CIDRs) and port specifications."""
from __future__ import annotations

import ipaddress

# A compact "top ports" list — the TCP services most worth a first look.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 587, 631, 636, 993, 995, 1025, 1433, 1521, 1723, 2049,
    2375, 2376, 3000, 3306, 3389, 4433, 5000, 5432, 5900, 5985, 6379,
    8000, 8008, 8080, 8081, 8088, 8180, 8443, 8888, 9200, 9443, 11211,
    27017,
]


def parse_ports(spec: str) -> list[int]:
    """Turn a port spec into a sorted list of unique, in-range ports.

    Accepts ``"top"`` (the default list), ``"all"`` (1-65535), a range
    ``"1-1024"``, a list ``"22,80,443"``, or any comma-separated mix. Ports
    outside 1-65535 are dropped; a reversed range is read either way round.
    """
    spec = (spec or "").strip().lower()
    if spec in ("", "top"):
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_targets(spec: str, max_hosts: int = 4096) -> list[str]:
    """Expand one target into a list of host strings.

    A single IP or a hostname passes through unchanged; a CIDR such as
    ``10.0.0.0/28`` expands to its usable host addresses. An expansion larger
    than ``max_hosts`` raises ``ValueError`` rather than quietly scanning a
    whole continent.
    """
    spec = spec.strip()
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        # Not an IP/CIDR — treat it as a hostname and let the resolver handle it.
        return [spec]
    if net.num_addresses == 1:
        return [str(net.network_address)]
    out: list[str] = []
    for host in net.hosts():
        out.append(str(host))
        if len(out) > max_hosts:
            raise ValueError(
                f"{spec} expands to more than {max_hosts} hosts; narrow the range"
            )
    return out
