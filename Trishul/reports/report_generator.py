"""
Report Generator Module
Produces JSON and human-readable text reports from scan results.
"""

import json
import datetime
from typing import Dict, List, Any


class ReportGenerator:
    """
    Generates structured scan reports in JSON and plain-text formats.
    Reports include open ports, services, banners, and scan metadata.
    """

    def generate(
        self,
        results: Dict[str, List[Dict]],
        output_name: str,
        elapsed: float
    ) -> None:
        """
        Generate both JSON and text reports from scan results.

        Args:
            results: Dict mapping host IPs to lists of port scan result dicts
            output_name: Base filename (without extension) for output files
            elapsed: Total scan duration in seconds
        """
        report_data = self._build_report_data(results, elapsed)
        self._write_json(report_data, output_name)
        self._write_text(report_data, output_name)

    def _build_report_data(
        self,
        results: Dict[str, List[Dict]],
        elapsed: float
    ) -> Dict[str, Any]:
        """
        Structure raw scan results into a report-ready dictionary.

        Args:
            results: Raw scan results by host
            elapsed: Scan duration

        Returns:
            Structured report dictionary
        """
        summary = {
            "total_hosts": len(results),
            "total_open_ports": sum(
                len([p for p in ports if p["state"] == "open"])
                for ports in results.values()
            ),
            "hosts_with_open_ports": sum(
                1 for ports in results.values()
                if any(p["state"] == "open" for p in ports)
            )
        }

        hosts_data = {}
        for host, ports in results.items():
            open_ports = [p for p in ports if p["state"] == "open"]
            hosts_data[host] = {
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "total_scanned": len(ports),
            }

        return {
            "metadata": {
                "tool": "Trishul",
                "version": "1.0.0",
                "scan_time": datetime.datetime.now().isoformat(),
                "duration_seconds": round(elapsed, 2),
            },
            "summary": summary,
            "hosts": hosts_data,
        }

    def _write_json(self, data: Dict[str, Any], output_name: str) -> None:
        """Write report data as formatted JSON."""
        path = f"{output_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _write_text(self, data: Dict[str, Any], output_name: str) -> None:
        """Write a human-readable plain-text report."""
        path = f"{output_name}.txt"
        lines = []
        meta = data["metadata"]
        summary = data["summary"]

        lines.append("=" * 60)
        lines.append("           TRISHUL SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated:  {meta['scan_time']}")
        lines.append(f"Duration:   {meta['duration_seconds']}s")
        lines.append(f"Hosts:      {summary['total_hosts']} scanned, "
                     f"{summary['hosts_with_open_ports']} with open ports")
        lines.append(f"Open Ports: {summary['total_open_ports']} total")
        lines.append("=" * 60)
        lines.append("")

        for host, host_data in data["hosts"].items():
            lines.append(f"HOST: {host}")
            lines.append(f"  Scanned {host_data['total_scanned']} ports | "
                         f"{host_data['total_open']} open")
            lines.append(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<20} BANNER")
            lines.append(f"  {'-'*60}")

            if host_data["open_ports"]:
                for p in host_data["open_ports"]:
                    banner = p.get("banner") or ""
                    lines.append(
                        f"  {p['port']:<8} {'open':<10} {p['service']:<20} {banner}"
                    )
            else:
                lines.append("  No open ports found.")
            lines.append("")

        lines.append("=" * 60)
        lines.append("Scan complete. Use responsibly and ethically.")
        lines.append("=" * 60)

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
