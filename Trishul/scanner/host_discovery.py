"""
Host Discovery Module
Uses ICMP ping and TCP probes to discover live hosts on a subnet.
"""

import socket
import subprocess
import platform
import concurrent.futures
from typing import List


class HostDiscovery:
    """
    Discovers live hosts on a network using ping sweeps and TCP probing.
    Falls back to TCP connect if ICMP is unavailable (e.g., no root privileges).
    """

    PROBE_PORTS = [80, 443, 22, 445, 3389]  # Common ports to probe if ping fails

    def __init__(self, timeout: float = 1.0, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads
        self._ping_cmd = self._get_ping_cmd()

    def _get_ping_cmd(self) -> List[str]:
        """Return the OS-appropriate ping command with a single packet."""
        if platform.system().lower() == "windows":
            return ["ping", "-n", "1", "-w", "1000"]
        return ["ping", "-c", "1", "-W", "1"]

    def ping_sweep(self, hosts: List[str]) -> List[str]:
        """
        Perform a concurrent ping sweep across a list of hosts.

        Args:
            hosts: List of IP address strings

        Returns:
            List of responsive (live) IP addresses
        """
        live_hosts = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_host = {
                executor.submit(self._is_host_alive, host): host
                for host in hosts
            }
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                if future.result():
                    live_hosts.append(host)

        return sorted(live_hosts, key=lambda ip: [int(x) for x in ip.split(".")])

    def _is_host_alive(self, host: str) -> bool:
        """
        Check if a host is alive via ping, falling back to TCP probing.

        Args:
            host: IP address string

        Returns:
            True if host responds, False otherwise
        """
        # Try ICMP ping first
        if self._ping(host):
            return True

        # Fallback: try TCP connect on common ports
        return self._tcp_probe(host)

    def _ping(self, host: str) -> bool:
        """
        Send a single ICMP ping to a host.

        Args:
            host: Target IP address

        Returns:
            True if ping succeeds, False otherwise
        """
        try:
            cmd = self._ping_cmd + [host]
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _tcp_probe(self, host: str) -> bool:
        """
        Probe common TCP ports to check if a host is reachable.

        Args:
            host: Target IP address

        Returns:
            True if any probe port responds, False otherwise
        """
        for port in self.PROBE_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((host, port)) == 0:
                        return True
            except OSError:
                continue
        return False

    def resolve_hostname(self, hostname: str) -> str:
        """
        Resolve a hostname to an IP address.

        Args:
            hostname: DNS hostname string

        Returns:
            Resolved IP address string

        Raises:
            ValueError: If hostname cannot be resolved
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve hostname '{hostname}': {e}")
