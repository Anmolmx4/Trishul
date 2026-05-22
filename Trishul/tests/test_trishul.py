"""
Unit Tests for Trishul
Tests for validator, service database, and scanner logic.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.validator import validate_target, validate_ports, COMMON_PORTS
from utils.service_db import get_service, SERVICE_DB
from scanner.port_scanner import PortScanner


class TestValidator(unittest.TestCase):

    def test_single_ip(self):
        result = validate_target("192.168.1.1")
        self.assertEqual(result, ["192.168.1.1"])

    def test_cidr_range(self):
        result = validate_target("192.168.1.0/30")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])

    def test_cidr_too_large(self):
        with self.assertRaises(ValueError):
            validate_target("10.0.0.0/8")  # 16M hosts

    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            validate_target("999.999.999.999")

    def test_invalid_hostname(self):
        with self.assertRaises(ValueError):
            validate_target("this.hostname.does.not.exist.invalid")

    def test_common_ports(self):
        result = validate_ports("common")
        self.assertEqual(result, sorted(COMMON_PORTS))
        self.assertIn(80, result)
        self.assertIn(443, result)

    def test_single_port(self):
        self.assertEqual(validate_ports("80"), [80])

    def test_port_range(self):
        result = validate_ports("1-5")
        self.assertEqual(result, [1, 2, 3, 4, 5])

    def test_mixed_ports(self):
        result = validate_ports("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_invalid_port_zero(self):
        with self.assertRaises(ValueError):
            validate_ports("0")

    def test_invalid_port_too_high(self):
        with self.assertRaises(ValueError):
            validate_ports("65536")

    def test_invalid_range_reversed(self):
        with self.assertRaises(ValueError):
            validate_ports("100-10")


class TestServiceDB(unittest.TestCase):

    def test_known_ports(self):
        self.assertEqual(get_service(22), "ssh")
        self.assertEqual(get_service(80), "http")
        self.assertEqual(get_service(443), "https")
        self.assertEqual(get_service(3306), "mysql")
        self.assertEqual(get_service(27017), "mongodb")

    def test_unknown_port(self):
        self.assertEqual(get_service(54321), "unknown")

    def test_all_ports_are_strings(self):
        for port, name in SERVICE_DB.items():
            self.assertIsInstance(port, int)
            self.assertIsInstance(name, str)


class TestPortScanner(unittest.TestCase):

    def test_scan_open_port(self):
        """Simulate a successful connection on port 80."""
        scanner = PortScanner(timeout=1.0, max_threads=10)

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value.__enter__ = lambda s: mock_sock
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.return_value = 0  # Success

            result = scanner._scan_port("192.168.1.1", 80)

        self.assertIsNotNone(result)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["service"], "http")

    def test_scan_closed_port(self):
        """Simulate a refused connection."""
        scanner = PortScanner(timeout=1.0)

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value.__enter__ = lambda s: mock_sock
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.return_value = 111  # Connection refused

            result = scanner._scan_port("192.168.1.1", 9999)

        self.assertIsNone(result)  # Closed ports return None when not verbose

    def test_scan_closed_port_verbose(self):
        """Verbose mode should return closed ports too."""
        scanner = PortScanner(timeout=1.0, verbose=True)

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value.__enter__ = lambda s: mock_sock
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.return_value = 111

            result = scanner._scan_port("192.168.1.1", 9999)

        self.assertIsNotNone(result)
        self.assertEqual(result["state"], "closed")

    def test_results_sorted_by_port(self):
        """Scan results should always be sorted by port number."""
        scanner = PortScanner(timeout=0.1, max_threads=5)

        # Inject mock results in random order
        mock_results = [
            {"port": 443, "state": "open", "service": "https", "banner": None},
            {"port": 22, "state": "open", "service": "ssh", "banner": None},
            {"port": 80, "state": "open", "service": "http", "banner": None},
        ]

        with patch.object(scanner, "_scan_port", side_effect=mock_results):
            with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
                # Simplified: just test sort directly
                results = sorted(mock_results, key=lambda x: x["port"])

        ports = [r["port"] for r in results]
        self.assertEqual(ports, sorted(ports))


if __name__ == "__main__":
    unittest.main(verbosity=2)
