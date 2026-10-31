import unittest

from netprobe.fingerprint import _cert_info, _clean, _http_info, identify


class Identify(unittest.TestCase):
    def test_ssh_banner(self):
        self.assertEqual(identify(22, b"SSH-2.0-OpenSSH_8.9\r\n"), "ssh")

    def test_http_banner(self):
        self.assertEqual(identify(8080, b"HTTP/1.1 200 OK"), "http")

    def test_port_fallback(self):
        self.assertEqual(identify(3306, b""), "mysql")

    def test_unknown(self):
        self.assertEqual(identify(65000, b""), "")

    def test_accepts_str(self):
        self.assertEqual(identify(21, "220 ProFTPD 1.3"), "ftp")


class HttpInfo(unittest.TestCase):
    def test_parse(self):
        raw = (
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><head><title>  Hi  There </title></head>"
        )
        info = _http_info(raw)
        self.assertEqual(info["http_status"], 200)
        self.assertEqual(info["server"], "nginx/1.25")
        self.assertEqual(info["title"], "Hi There")

    def test_empty(self):
        self.assertEqual(_http_info(b""), {})


class Clean(unittest.TestCase):
    def test_strips_control_chars(self):
        self.assertEqual(_clean(b"ab\x00\x01cd\r\n"), "ab cd")


class CertInfo(unittest.TestCase):
    def test_parse(self):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "notAfter": "Jan  1 00:00:00 2027 GMT",
        }
        info = _cert_info(cert)
        self.assertEqual(info["cert_cn"], "example.com")
        self.assertEqual(info["cert_issuer"], "Let's Encrypt")
        self.assertEqual(info["cert_sans"], ["example.com", "www.example.com"])
        self.assertIn("2027", info["cert_expires"])


if __name__ == "__main__":
    unittest.main()
