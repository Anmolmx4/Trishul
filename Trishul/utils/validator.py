"""
Input Validation Utilities
Validates and parses target hosts, CIDR ranges, and port specifications.
"""

import ipaddress
import socket
import re
from typing import List

# Most commonly scanned ports in penetration testing
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 443,
    445, 500, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723, 3306,
    3389, 5432, 5900, 6379, 6881, 8080, 8443, 8888, 9200, 27017
]


def validate_target(target: str) -> List[str]:
    """
    Parse and validate a target specification into a list of IP addresses.

    Accepts:
        - Single IP address: "192.168.1.1"
        - Hostname: "scanme.nmap.org"
        - CIDR notation: "192.168.1.0/24"

    Args:
        target: Target specification string

    Returns:
        List of IP address strings to scan

    Raises:
        ValueError: If the target cannot be parsed or resolved
    """
    target = target.strip()

    # CIDR range (e.g. 192.168.1.0/24)
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            # Limit to /16 to prevent accidental huge scans
            if network.num_addresses > 65536:
                raise ValueError(
                    f"Network {target} is too large ({network.num_addresses} hosts). "
                    "Use /16 or smaller."
                )
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation '{target}': {e}")

    # Single IP address
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    # Hostname — attempt DNS resolution
    try:
        ip = socket.gethostbyname(target)
        return [ip]
    except socket.gaierror:
        raise ValueError(
            f"Cannot resolve target '{target}'. "
            "Ensure the hostname is correct and DNS is reachable."
        )


def validate_ports(ports_spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of integers.

    Accepts:
        - "common" → predefined list of common ports
        - Single port: "80"
        - Range: "1-1024"
        - Comma-separated: "22,80,443,8080"
        - Mixed: "22,80-90,443"

    Args:
        ports_spec: Port specification string

    Returns:
        Sorted list of unique port numbers

    Raises:
        ValueError: If any port spec is invalid or out of range
    """
    ports_spec = ports_spec.strip().lower()

    if ports_spec == "common":
        return sorted(COMMON_PORTS)

    ports = set()

    for segment in ports_spec.split(","):
        segment = segment.strip()

        if not segment:
            continue

        if "-" in segment:
            # Port range like "1-1024"
            parts = segment.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range '{segment}'")
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(f"Port range '{segment}' contains non-numeric values")

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port range '{segment}' is out of valid range (1-65535)")
            if start > end:
                raise ValueError(f"Port range start {start} > end {end}")

            ports.update(range(start, end + 1))

        elif re.match(r"^\d+$", segment):
            # Single port
            port = int(segment)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port {port} is out of valid range (1-65535)")
            ports.add(port)

        else:
            raise ValueError(f"Unrecognized port specification: '{segment}'")

    if not ports:
        raise ValueError("No valid ports specified")

    return sorted(ports)
