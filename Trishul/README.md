# Trishul 🔱

A multi-threaded network port scanner and reconnaissance tool built in Python. Trishul performs TCP connect scanning, banner grabbing, host discovery, and report generation — designed for authorized network security assessments.

## Features

- **Multi-threaded TCP port scanning** — concurrent scanning using `ThreadPoolExecutor` for fast results across large port ranges
- **Host discovery** — ICMP ping sweep with TCP fallback to find live hosts on a subnet
- **Banner grabbing** — identifies running services by probing open ports for service banners (HTTP, SSH, SMTP, etc.)
- **Flexible port targeting** — single ports, ranges, comma-separated lists, or a curated list of 35 common ports
- **CIDR range support** — scan entire subnets (e.g. `192.168.1.0/24`)
- **Report generation** — outputs JSON and human-readable `.txt` reports with scan metadata and findings
- **Colored CLI output** — clear, readable terminal output with log levels

## Project Structure

```
trishul/
├── main.py                    # CLI entry point
├── scanner/
│   ├── port_scanner.py        # Core TCP connect scanner
│   └── host_discovery.py      # Ping sweep & TCP probing
├── utils/
│   ├── validator.py           # Input parsing & validation
│   ├── service_db.py          # Port → service name mapping (70+ services)
│   └── logger.py              # Colored console logger
├── reports/
│   └── report_generator.py    # JSON + text report output
├── tests/
│   └── test_trishul.py       # Unit tests
└── requirements.txt
```

## Installation

```bash
git clone https://github.com/Anmolmx4/trishul.git
cd trishul
pip install -r requirements.txt
```

No external dependencies are required for core functionality — Trishul uses only the Python standard library (`socket`, `concurrent.futures`, `subprocess`, `ipaddress`, `json`).

## Usage

```bash
# Scan common ports on a single host
python main.py -t 192.168.1.1

# Scan a specific port range
python main.py -t 192.168.1.1 -p 1-1024

# Scan specific ports with banner grabbing
python main.py -t scanme.nmap.org -p 22,80,443 -b

# Discover live hosts on a subnet, then scan them
python main.py -t 192.168.1.0/24 --discover -p common

# Full scan with report output
python main.py -t 10.0.0.1 -p 1-10000 --report -o my_scan

# Verbose mode (shows closed/filtered ports too)
python main.py -t 192.168.1.1 -p 1-1024 -v
```

### Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target IP, hostname, or CIDR range |
| `-p`, `--ports` | Port spec: `80`, `1-1024`, `22,80,443`, or `common` |
| `-b`, `--banner` | Attempt to grab service banners |
| `--discover` | Run ping sweep before scanning (for subnets) |
| `--timeout` | Connection timeout in seconds (default: 1.0) |
| `--threads` | Concurrent threads (default: 100) |
| `--report` | Generate JSON + text report |
| `-o`, `--output` | Report base filename (default: `trishul_report`) |
| `-v`, `--verbose` | Show closed/filtered ports too |

## Running Tests

```bash
python -m pytest tests/ -v
# or
python -m pytest tests/ --cov=. --cov-report=term-missing
```

## How It Works

### TCP Connect Scan
Trishul uses **TCP connect scanning** (not raw SYN scanning), which means:
- No root/admin privileges required
- Uses the OS TCP stack — `socket.connect_ex()` returns `0` on success
- Filtered ports time out; closed ports return an error code immediately

### Threading Model
Port scanning is I/O-bound. Trishul uses `concurrent.futures.ThreadPoolExecutor` to run hundreds of socket connections concurrently, reducing scan time by orders of magnitude vs sequential scanning.

### Banner Grabbing
For open ports, Trishul sends protocol-appropriate probes:
- HTTP ports (80, 8080): `HEAD / HTTP/1.0`
- SMTP ports (25, 587): `EHLO trishul`
- SSH (22): reads the version banner sent automatically
- Others: sends `\r\n` and reads whatever the service responds with

## Ethical Use

> ⚠️ Only scan networks and systems you own or have explicit written permission to test. Unauthorized port scanning may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation in other jurisdictions.

## License

MIT License
