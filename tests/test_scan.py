import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from netprobe.scanner import scan_sync


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class BannerServer(threading.Thread):
    """A TCP server that greets each client with a banner, like SSH or SMTP."""

    def __init__(self, banner=b"SSH-2.0-netprobe_test\r\n"):
        super().__init__(daemon=True)
        self.banner = banner
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            try:
                conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>netprobe test</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Server", "netprobe-test/1.0")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ScanTests(unittest.TestCase):
    def test_banner_port_is_identified(self):
        srv = BannerServer()
        srv.start()
        try:
            results = scan_sync(["127.0.0.1"], [srv.port], timeout=2.0)
        finally:
            srv.stop()
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertTrue(r.is_open)
        self.assertEqual(r.service, "ssh")
        self.assertIn("SSH-2.0-netprobe_test", r.banner)

    def test_http_port_fingerprint(self):
        httpd = HTTPServer(("127.0.0.1", 0), _QuietHandler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            results = scan_sync(["127.0.0.1"], [port], timeout=2.0)
        finally:
            httpd.shutdown()
        self.assertEqual(len(results), 1)
        info = results[0].info
        self.assertEqual(info.get("http_status"), 200)
        self.assertEqual(info.get("title"), "netprobe test")
        self.assertEqual(info.get("server"), "netprobe-test/1.0")

    def test_closed_port(self):
        results = scan_sync(["127.0.0.1"], [_free_port()], timeout=1.0)
        self.assertEqual(results, [])

    def test_no_fingerprint_skips_banner(self):
        srv = BannerServer()
        srv.start()
        try:
            results = scan_sync(["127.0.0.1"], [srv.port], timeout=2.0, fingerprint=False)
        finally:
            srv.stop()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_open)
        self.assertEqual(results[0].banner, "")


if __name__ == "__main__":
    unittest.main()
