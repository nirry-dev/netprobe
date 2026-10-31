"""Asynchronous TCP connect scanning.

A bounded pool of coroutines each try to open one ``(host, port)``. Openness is
a successful TCP connect — a connect scan, not a raw-socket SYN scan — so it
needs no special privileges and behaves the same on every platform. Open ports
are then handed to the fingerprinter.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .fingerprint import fingerprint, identify


@dataclass
class PortResult:
    host: str
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    info: dict = field(default_factory=dict)


async def _connect_ok(host, port, timeout) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout)
    except (OSError, asyncio.TimeoutError):
        pass
    return True


async def _scan_one(host, port, timeout, sem, do_fingerprint) -> PortResult:
    async with sem:
        if not await _connect_ok(host, port, timeout):
            return PortResult(host, port, False)
        result = PortResult(host, port, True)
        if do_fingerprint:
            try:
                fp = await fingerprint(host, port, timeout)
                result.service = fp["service"]
                result.banner = fp["banner"]
                result.info = fp["info"]
            except Exception:
                result.service = identify(port, "")
        else:
            result.service = identify(port, "")
        return result


async def scan(hosts, ports, concurrency: int = 512, timeout: float = 2.0, fingerprint: bool = True):
    """Scan every ``(host, port)`` pair; return the open ports as ``PortResult``s.

    Results are sorted by ``(host, port)``; closed or filtered ports are dropped.
    ``concurrency`` bounds the number of sockets open at once.
    """
    sem = asyncio.Semaphore(max(1, concurrency))
    tasks = [
        asyncio.create_task(_scan_one(host, port, timeout, sem, fingerprint))
        for host in hosts
        for port in ports
    ]
    open_results: list[PortResult] = []
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result.is_open:
            open_results.append(result)
    open_results.sort(key=lambda r: (r.host, r.port))
    return open_results


def scan_sync(hosts, ports, **kwargs):
    """Blocking convenience wrapper around :func:`scan`."""
    return asyncio.run(scan(hosts, ports, **kwargs))
