# netprobe

**Dependency-free TCP recon that produces a graph, not a wall of text.**

An async connect scanner that finds open ports, fingerprints what's behind them
(banner, HTTP, TLS certificate), and writes the whole thing into one normalized
**host → service graph** you can hand to another tool. Pure Python standard
library — no nmap, no scapy, no pip dependencies, no root.

```bash
netprobe scan 10.0.0.0/28 -p top
```
```
7 open port(s) across 3 host(s)

  HOST              PORT   SERVICE       DETAIL
  10.0.0.1          22     ssh           SSH-2.0-OpenSSH_9.6
  10.0.0.1          443    https         gateway.lan  (TLSv1.3)
  10.0.0.12         80     http          Directory listing for /
  10.0.0.12         5432   postgres
```

> **Authorized use only.** netprobe connects to the hosts you point it at and
> reads what they volunteer. Only scan machines you own or have explicit
> permission to test.

---

## Why this exists

Most scanners end at a list: a flat table of `host:port → service` that you then
copy into a notebook, a spreadsheet, or the next tool by hand. But recon is
rarely one pass — you scan, you learn something, you scan again, and you want the
second result to *merge into* the first rather than replace it. The useful shape
for that isn't a list, it's a **graph**: hosts, the services they expose, and the
facts attached to each.

So that's what netprobe emits. Every probe result becomes nodes and edges in one
model, and the model exports to JSON or Graphviz. The scanning is deliberately
ordinary; the thing worth keeping is that the output composes.

## How it works

**1. A connect scan, bounded by a semaphore.** Openness is just a successful TCP
`connect()` — no raw sockets, no privileges, identical behavior on Linux,
macOS, and Windows. `asyncio` opens thousands of these concurrently; a single
`asyncio.Semaphore` caps how many sockets are live at once. That semaphore is the
entire concurrency design.

**2. Best-effort fingerprinting, never exploitation.** An open port gets one
light probe: read a greeting banner (SSH, SMTP, IMAP, … announce themselves),
send a single HTTP `GET` for web services, or complete a TLS handshake to read
the certificate. Service identity comes from banner signatures first, then the
port's conventional default.

**3. Results become a graph.** Each finding adds a `host` node, a `service` node
carrying its attributes (banner, HTTP title/server, TLS cert CN/SANs), and an
`exposes` edge between them. Re-scan and the nodes merge instead of duplicating.

```
 10.0.0.1 ──exposes──▶ 22/ssh      {banner: "SSH-2.0-OpenSSH_9.6"}
          ├─exposes──▶ 443/https   {cert_cn: gateway.lan, tls: TLSv1.3}
 10.0.0.12 ─exposes──▶ 80/http     {title: "...", server: nginx}
           └─exposes──▶ 5432/postgres
```

## Install

```bash
pip install netprobe          # once published
# or, from a checkout:
pip install -e .
```

No dependencies. Python 3.9+.

## Use

**From the shell:**

```bash
# Default "top ports" sweep of a host or a whole subnet:
netprobe scan 192.168.1.0/24

# Specific ports, a range, or a mix; tune concurrency and timeout:
netprobe scan example.com -p 22,80,443,8000-8100 -c 1000 -t 1.5

# Just find open ports, skip the fingerprinting:
netprobe scan 10.0.0.5 -p all --no-fingerprint

# Emit the recon graph for another tool, or for Graphviz:
netprobe scan 10.0.0.0/28 --json > recon.json
netprobe scan 10.0.0.0/28 --dot  | dot -Tsvg -o recon.svg
```

**From Python:**

```python
from netprobe import scan_sync, build_graph, parse_ports

results = scan_sync(["10.0.0.0/28"], parse_ports("top"), timeout=1.5)
for r in results:
    print(r.host, r.port, r.service, r.info.get("title", ""))

graph = build_graph(results)
print(graph.to_json())      # nodes + edges, ready to persist or merge
print(graph.to_dot())       # Graphviz
```

`scan` is also available as an `async` coroutine if you're already in an event
loop.

## Design notes & limitations

Honest about the edges, because a recon tool that hides them is dangerous:

- **Connect scan, not SYN.** It completes the handshake, so it needs no root —
  but it's noisier (it shows up in the target's logs) and slower than a
  half-open SYN scan. That was the right trade for a portable, dependency-free
  tool; raw-socket SYN is a deliberate non-goal.
- **TCP only.** No UDP, which would mean per-service payloads to get any answer
  at all — out of scope for v0.
- **Fingerprinting reconnects.** The openness sweep and the probe are separate
  connections, so an open port costs a second `connect()`. Keeping the two
  independent made both far simpler to reason about; reusing the socket is a
  natural optimization later.
- **TLS certificates only show when they validate.** Python's `getpeercert()`
  returns a parsed certificate *only* after the chain verifies. For a
  self-signed or internal cert the handshake still succeeds, but you get
  `cert_verified: false` and no parsed fields — netprobe tells you TLS is spoken,
  not what the cert claims. Reading an unverified cert's contents needs a DER
  parser the standard library doesn't expose.
- **Fingerprints are advisory.** Banner/port identification is pattern-matching;
  a service can run on an odd port or lie about itself. The graph records what it
  saw, not a verdict.
- **No reachability, pivoting, or exploitation.** It identifies what's listening.
  That's the whole job.

## Learning notes

*What I set out to learn, and what actually surprised me — this repo is partly a
notebook.*

- **Model recon as a graph from the first line.** My first version printed a
  table and I bolted on "export" later; it was always lossy. Starting from
  nodes-and-edges and treating the table as *one* view of the graph made
  re-scans merge for free and gave downstream tools something real to consume.
  The data model was the design decision that mattered.
- **A semaphore is the whole async scanning story.** I expected to need batching,
  backpressure, and tuning. In practice `asyncio` plus one `Semaphore` to bound
  live sockets covered all of it in a few lines — the hard part of concurrency
  here was deciding *not* to add machinery.
- **`CERT_NONE` returns an empty certificate, and that cost me an hour.** I wanted
  to inspect certs without a trust store, set `verify_mode = CERT_NONE`, and got
  `{}` back every time — `getpeercert()` only populates after validation. The fix
  that fit the goal: try a verifying handshake to read the cert, and fall back to
  an unverified one purely to confirm TLS is there.
- **One `read()` is one TCP segment, not one response.** An HTTP server sent its
  headers and body in separate segments; my single `reader.read()` grabbed the
  headers, so the page `<title>` silently went missing. Reading to EOF under a
  timeout fixed it — a reminder that a stream gives you bytes when it has them,
  not messages.
- **Connect vs SYN is a values choice, so write it down.** SYN scanning is
  faster and quieter, but needs raw sockets and root and turns portability into a
  per-platform problem. I chose the boring, privilege-free connect scan and
  documented the trade rather than smuggling in a dependency.

## Tests

```bash
pip install -e .
python -m unittest discover -s tests -v
```

The suite runs offline: it stands up real banner and HTTP servers on ephemeral
ports and drives them through the actual scanner end to end, plus unit tests for
port/target parsing, the graph's merge/de-duplication, and the fingerprint
parsers (HTTP headers, TLS cert fields, banner signatures).

## License

MIT © Nirry
