import unittest

from netprobe.targets import TOP_PORTS, parse_ports, parse_targets


class ParsePorts(unittest.TestCase):
    def test_top_default(self):
        self.assertEqual(parse_ports("top"), list(TOP_PORTS))
        self.assertEqual(parse_ports(""), list(TOP_PORTS))

    def test_list_sorted_unique(self):
        self.assertEqual(parse_ports("80,22,443,22"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_mixed(self):
        self.assertEqual(parse_ports("22,80,20-22"), [20, 21, 22, 80])

    def test_reversed_range(self):
        self.assertEqual(parse_ports("23-20"), [20, 21, 22, 23])

    def test_out_of_range_dropped(self):
        self.assertEqual(parse_ports("0,70000,443"), [443])

    def test_all(self):
        p = parse_ports("all")
        self.assertEqual((p[0], p[-1], len(p)), (1, 65535, 65535))


class ParseTargets(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(parse_targets("10.0.0.5"), ["10.0.0.5"])

    def test_hostname_passthrough(self):
        self.assertEqual(parse_targets("example.com"), ["example.com"])

    def test_cidr_expands_usable_hosts(self):
        self.assertEqual(parse_targets("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])

    def test_slash31(self):
        self.assertEqual(parse_targets("10.0.0.0/31"), ["10.0.0.0", "10.0.0.1"])

    def test_too_big_raises(self):
        with self.assertRaises(ValueError):
            parse_targets("10.0.0.0/8", max_hosts=1000)


if __name__ == "__main__":
    unittest.main()
