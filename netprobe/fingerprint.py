"""Lightweight, best-effort service fingerprinting over an open TCP port.

Everything here is a plain read or a single tiny request — a banner grab, one
HTTP GET, or a TLS handshake to read the certificate. No exploitation; just
identification.
"""
from __future__ import annotations

import asyncio
import re
import ssl

# Ports we treat as cleartext HTTP, as TLS, and the HTTPS subset of the TLS set.
HTTP_PORTS = {80, 81, 591, 2080, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8180, 8888}
TLS_PORTS = {443, 465, 636, 989, 990, 992, 993, 995, 4433, 8443, 9443}
HTTPS_PORTS = {443, 4433, 8443, 9443}

PORT_SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8080: "http-proxy", 8180: "http",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

_BANNER_SIGS = [
    (re.compile(rb"^SSH-"), "ssh"),
    (re.compile(rb"^220[- ].*(?:FTP|FileZilla|vsFTPd|ProFTPD)", re.I), "ftp"),
    (re.compile(rb"^220[- ].*SMTP", re.I), "smtp"),
    (re.compile(rb"^220[- ]"), "smtp/ftp"),
    (re.compile(rb"^\+OK"), "pop3"),
    (re.compile(rb"^\* OK"), "imap"),
    (re.compile(rb"^HTTP/\d", re.I), "http"),
    (re.compile(rb"^RFB "), "vnc"),
    (re.compile(rb"redis_version|^-ERR|^\+PONG", re.I), "redis"),
]


def identify(port: int, banner) -> str:
    """Guess a service from its banner first, then fall back to the port's default."""
    data = banner.encode("latin1", "ignore") if isinstance(banner, str) else (banner or b"")
    for rx, name in _BANNER_SIGS:
        if rx.search(data):
            return name
    return PORT_SERVICE.get(port, "")


def _cap(timeout: float) -> float:
    return min(timeout, 3.0)


async def _read_some(reader, timeout: float, n: int = 1024) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout) or b""
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return b""


async def _read_all(reader, timeout: float, cap: int = 65536) -> bytes:
    """Read until EOF (or ``cap`` bytes / ``timeout``), so a response split across
    several TCP segments — headers in one, body in the next — arrives whole."""
    chunks: list[bytes] = []
    total = 0
    try:
        while total < cap:
            chunk = await asyncio.wait_for(reader.read(4096), timeout)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        pass
    return b"".join(chunks)


async def _open(host, port, timeout, ctx=None):
    coro = asyncio.open_connection(
        host, port, ssl=ctx, server_hostname=(host if ctx else None)
    )
    return await asyncio.wait_for(coro, timeout)


async def _close(writer, timeout: float) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        pass


async def _tls_open(host, port, timeout):
    """Open a TLS connection and read what we can of the certificate.

    A verifying handshake is tried first, because ``getpeercert()`` only returns
    a parsed certificate when the chain validated — a CERT_NONE handshake hands
    back an empty dict. If verification fails (self-signed, expired, wrong name)
    we fall back to an unverified handshake just to confirm TLS is spoken.
    Returns ``(reader, writer, cert, version, verified)``.
    """
    verifying = ssl.create_default_context()
    verifying.check_hostname = False
    try:
        reader, writer = await _open(host, port, timeout, verifying)
        so = writer.get_extra_info("ssl_object")
        cert = so.getpeercert() if so else {}
        return reader, writer, cert, (so.version() if so else None), True
    except (ssl.SSLError, ssl.CertificateError, asyncio.TimeoutError, OSError):
        pass

    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await _open(host, port, timeout, unverified)
        so = writer.get_extra_info("ssl_object")
        return reader, writer, {}, (so.version() if so else None), False
    except (ssl.SSLError, asyncio.TimeoutError, OSError):
        return None, None, {}, None, False


def _cert_info(cert: dict) -> dict:
    out: dict = {}
    if not cert:
        return out
    subject = dict(x[0] for x in cert.get("subject", ()))
    if subject.get("commonName"):
        out["cert_cn"] = subject["commonName"]
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if sans:
        out["cert_sans"] = sans[:8]
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    if issuer.get("organizationName"):
        out["cert_issuer"] = issuer["organizationName"]
    if cert.get("notAfter"):
        out["cert_expires"] = cert["notAfter"]
    return out


async def _http_probe(host, reader, writer, timeout) -> bytes:
    request = (
        "GET / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        "User-Agent: netprobe/0.1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        writer.write(request.encode("latin1", "ignore"))
        await writer.drain()
    except (OSError, ssl.SSLError):
        return b""
    return await _read_all(reader, _cap(timeout))


def _http_info(data: bytes) -> dict:
    out: dict = {}
    if not data:
        return out
    text = data.decode("latin1", "ignore")
    head = text.partition("\r\n\r\n")[0]
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", text)
    if m:
        out["http_status"] = int(m.group(1))
    for line in head.split("\r\n")[1:]:
        low = line.lower()
        if low.startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()[:80]
        elif low.startswith("location:"):
            out["location"] = line.split(":", 1)[1].strip()[:160]
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if title:
        out["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:120]
    return out


def _clean(data: bytes, n: int = 160) -> str:
    if not data:
        return ""
    s = data.decode("latin1", "ignore")
    s = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in s)
    return re.sub(r"\s+", " ", s).strip()[:n]


async def fingerprint(host: str, port: int, timeout: float) -> dict:
    """Best-effort probe of one open port. Returns ``{service, banner, info}``."""
    info: dict = {}
    writer = None
    try:
        if port in TLS_PORTS:
            reader, writer, cert, version, verified = await _tls_open(host, port, timeout)
            if writer is None:
                return {"service": PORT_SERVICE.get(port, ""), "banner": "", "info": info}
            if version:
                info["tls"] = version
            info["cert_verified"] = verified
            info.update(_cert_info(cert))
        else:
            try:
                reader, writer = await _open(host, port, timeout)
            except (OSError, asyncio.TimeoutError):
                return {"service": PORT_SERVICE.get(port, ""), "banner": "", "info": info}

        if port in HTTP_PORTS or port in HTTPS_PORTS:
            data = await _http_probe(host, reader, writer, timeout)
        else:
            # Many services greet first (SSH, SMTP, IMAP, ...); read that.
            data = await _read_some(reader, min(timeout, 1.5))
            if not data:
                # Nothing volunteered — it may still be HTTP on a nonstandard port.
                data = await _http_probe(host, reader, writer, timeout)

        if data.startswith(b"HTTP/"):
            info.update(_http_info(data))

        banner = _clean(data)
        service = identify(port, data) or PORT_SERVICE.get(port, "")
        if not service and port in HTTPS_PORTS:
            service = "https"
        return {"service": service, "banner": banner, "info": info}
    finally:
        await _close(writer, timeout)
