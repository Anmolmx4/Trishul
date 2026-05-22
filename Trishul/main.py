#!/usr/bin/env python3
"""
Trishul - Advanced Network Port Scanner
A cybersecurity tool for network reconnaissance and vulnerability assessment.
"""

import argparse
import sys
import time
from scanner.port_scanner import PortScanner
from scanner.host_discovery import HostDiscovery
from utils.validator import validate_target, validate_ports
from utils.logger import setup_logger
from reports.report_generator import ReportGenerator

BANNER = r"""
  ______     _      __           _  
 /_  __/____(_)____/ /_  __  __ / / 
  / / / ___/ / ___/ __ \/ / / // /  
 / / / /  / (__  ) / / / /_/ // /___
/_/ /_/  /_/____/_/ /_/\__,_//_____/

       🔱  T R I S H U L  🔱
  The Three-Pronged Network Recon Tool
  Version 1.0.0 | Use responsibly & ethically
"""

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Trishul 🔱 - Network Port Scanner & Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t 192.168.1.1                     # Scan common ports
  python main.py -t 192.168.1.1 -p 1-1024           # Scan port range
  python main.py -t 192.168.1.0/24 --discover        # Host discovery
  python main.py -t scanme.nmap.org -p 80,443 -b    # Grab banners
  python main.py -t 10.0.0.1 -p 1-65535 --report    # Full scan + report
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="common",
                        help="Port range: '80', '1-1024', '80,443,8080', or 'common' (default)")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="Attempt to grab service banners")
    parser.add_argument("--discover", action="store_true",
                        help="Run host discovery on a subnet before scanning")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--report", action="store_true",
                        help="Generate a JSON + text report after scanning")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output (show closed ports too)")
    parser.add_argument("-o", "--output", default="trishul_report",
                        help="Output file name for report (without extension)")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_arguments()
    logger = setup_logger(verbose=args.verbose)

    # Validate inputs
    try:
        targets = validate_target(args.target)
        ports = validate_ports(args.ports)
    except ValueError as e:
        logger.error(f"Input validation failed: {e}")
        sys.exit(1)

    logger.info(f"Targets: {args.target}")
    logger.info(f"Ports: {len(ports)} ports to scan")
    logger.info(f"Threads: {args.threads} | Timeout: {args.timeout}s")
    print("-" * 60)

    all_results = {}
    start_time = time.time()

    # Optional host discovery
    if args.discover and len(targets) > 1:
        logger.info("Running host discovery...")
        discoverer = HostDiscovery(timeout=args.timeout)
        targets = discoverer.ping_sweep(targets)
        logger.info(f"Discovered {len(targets)} live host(s)")
        print("-" * 60)

    # Run port scan
    scanner = PortScanner(
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banner=args.banner,
        verbose=args.verbose
    )

    for target in targets:
        logger.info(f"Scanning {target}...")
        results = scanner.scan(target, ports)
        all_results[target] = results

        # Print results to console
        open_ports = [r for r in results if r["state"] == "open"]
        logger.info(f"Found {len(open_ports)} open port(s) on {target}")
        for port_info in open_ports:
            banner_str = f"  [{port_info['banner']}]" if port_info.get("banner") else ""
            print(f"  {port_info['port']:>5}/tcp  OPEN  {port_info['service']:<20}{banner_str}")

    elapsed = time.time() - start_time
    print("-" * 60)
    logger.info(f"Scan complete in {elapsed:.2f}s")

    # Optional report generation
    if args.report:
        reporter = ReportGenerator()
        reporter.generate(all_results, args.output, elapsed)
        logger.info(f"Report saved: {args.output}.json + {args.output}.txt")


if __name__ == "__main__":
    main()
