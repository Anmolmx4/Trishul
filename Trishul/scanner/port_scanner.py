"""
Port Scanner Core Module
Handles TCP connect scanning with threading and optional banner grabbing.
"""

import socket
import concurrent.futures
from typing import List, Dict, Optional
from utils.service_db import SERVICE_DB


class PortScanner:
    """
    Multi-threaded TCP connect port scanner with optional banner grabbing.
    Uses ThreadPoolExecutor for concurrent scanning across port ranges.
    """

    def __init__(
        self,
        timeout: float = 1.0,
        max_threads: int = 100,
        grab_banner: bool = False,
        verbose: bool = False
    ):
        self.timeout = timeout
        self.max_threads = max_threads
        self.grab_banner = grab_banner
        self.verbose = verbose

    def scan(self, host: str, ports: List[int]) -> List[Dict]:
        """
        Scan a list of ports on a given host concurrently.

        Args:
            host: Target hostname or IP address
            ports: List of port numbers to scan

        Returns:
            List of dicts with port scan results, sorted by port number
        """
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port, host, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)

        results.sort(key=lambda x: x["port"])
        return results

    def _scan_port(self, host: str, port: int) -> Optional[Dict]:
        """
        Attempt a TCP connection to a single port.

        Args:
            host: Target hostname or IP
            port: Target port number

        Returns:
            Dict with port info if open (or verbose), None if closed/filtered and not verbose
        """
        state = "closed"
        banner = None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))

                if result == 0:
                    state = "open"
                    if self.grab_banner:
                        banner = self._grab_banner(sock, port)
                else:
                    state = "closed"

        except socket.timeout:
            state = "filtered"
        except socket.gaierror:
            state = "error"
        except OSError:
            state = "closed"

        if state == "open" or self.verbose:
            return {
                "port": port,
                "state": state,
                "service": SERVICE_DB.get(port, "unknown"),
                "banner": banner,
            }
        return None

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """
        Attempt to grab a service banner from an open port.

        Args:
            sock: Connected socket object
            port: Port number (used to send protocol-specific probes)

        Returns:
            Banner string if grabbed, None otherwise
        """
        try:
            # Send HTTP request for web ports
            if port in (80, 8080, 8000, 8888):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            # Send SMTP EHLO for mail ports
            elif port in (25, 587, 465):
                sock.send(b"EHLO trishul\r\n")
            # Send SSH version probe
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b"\r\n")

            sock.settimeout(2.0)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            # Clean up multi-line banners
            return banner.split("\n")[0][:100] if banner else None

        except (socket.timeout, OSError, UnicodeDecodeError):
            return None
