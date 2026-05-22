"""
Service Database
Maps well-known port numbers to their associated service names.
Based on IANA service name and transport protocol port number registry.
"""

SERVICE_DB: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    43: "whois",
    53: "dns",
    67: "dhcp",
    68: "dhcp-client",
    69: "tftp",
    79: "finger",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "lpd",
    520: "rip",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    3306: "mysql",
    3389: "rdp",
    4444: "metasploit",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    6881: "bittorrent",
    7001: "weblogic",
    8080: "http-alt",
    8443: "https-alt",
    8888: "jupyter/alt-http",
    9200: "elasticsearch",
    9300: "elasticsearch-cluster",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb-shard",
    50000: "db2",
}


def get_service(port: int) -> str:
    """
    Look up service name for a port number.

    Args:
        port: TCP/UDP port number

    Returns:
        Service name string, or 'unknown' if not in database
    """
    return SERVICE_DB.get(port, "unknown")
