"""
ReconX - Shodan Service Discovery Module
Queries Shodan for exposed services, open ports, and banners
"""

import socket
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


class ShodanScanner:
    def __init__(self, domain, api_key, verbose=False, logger=None):
        self.domain = domain
        self.api_key = api_key
        self.verbose = verbose
        self.logger = logger

    def run(self):
        """Resolve domain IPs and query Shodan for each."""
        console.print("[bold]▸ Resolving IPs and querying Shodan...[/bold]")
        results = {"hosts": [], "summary": {}}

        try:
            import shodan
        except ImportError:
            console.print(
                "[yellow]  ⚠ Shodan library not installed. "
                "Install: pip install shodan[/yellow]"
            )
            return results

        api = shodan.Shodan(self.api_key)

        # Resolve the domain to IPs
        ips = self._resolve_ips()
        if not ips:
            console.print(f"[yellow]  ⚠ Could not resolve any IPs for {self.domain}[/yellow]")
            return results

        for ip in ips:
            host_data = self._query_host(api, ip)
            if host_data:
                results["hosts"].append(host_data)

        results["summary"] = self._build_summary(results["hosts"])
        return results

    def _resolve_ips(self):
        """Resolve domain to IP addresses."""
        ips = set()
        try:
            info = socket.getaddrinfo(self.domain, None)
            for item in info:
                ips.add(item[4][0])
        except socket.gaierror as e:
            if self.logger:
                self.logger.warning(f"DNS resolution failed for {self.domain}: {e}")
        return list(ips)

    def _query_host(self, api, ip):
        """Query a single IP on Shodan."""
        try:
            host = api.host(ip)
            data = {
                "ip": ip,
                "hostnames": host.get("hostnames", []),
                "org": host.get("org", "Unknown"),
                "country": host.get("country_name", "Unknown"),
                "city": host.get("city", "Unknown"),
                "isp": host.get("isp", "Unknown"),
                "asn": host.get("asn", ""),
                "last_update": host.get("last_update", ""),
                "ports": [],
                "vulns": list(host.get("vulns", [])),
            }

            for item in host.get("data", []):
                port_info = {
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": item.get("data", "")[:200],  # truncate banner
                    "cpe": item.get("cpe", []),
                    "ssl": bool(item.get("ssl")),
                }
                data["ports"].append(port_info)

            if self.verbose:
                self._print_host_table(data)

            return data

        except Exception as e:
            err = str(e)
            if "No information available" in err:
                console.print(f"  [dim]→ {ip}: no Shodan data[/dim]")
            elif "Invalid API key" in err:
                console.print("[red]  ✗ Invalid Shodan API key[/red]")
            else:
                if self.logger:
                    self.logger.debug(f"Shodan query for {ip}: {e}")
            return None

    def _print_host_table(self, host):
        table = Table(
            title=f"{host['ip']} ({host['org']})",
            box=box.SIMPLE,
            show_header=True
        )
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Protocol", width=8)
        table.add_column("Product", style="green")
        table.add_column("Version")
        table.add_column("SSL", width=5)

        for p in host["ports"]:
            table.add_row(
                str(p["port"]),
                p["transport"],
                p["product"] or "—",
                p["version"] or "—",
                "✓" if p["ssl"] else ""
            )
        console.print(table)

        if host["vulns"]:
            console.print(
                f"  [red bold]CVEs:[/red bold] "
                f"{', '.join(host['vulns'][:5])}"
                f"{'...' if len(host['vulns']) > 5 else ''}"
            )

    def _build_summary(self, hosts):
        all_ports = set()
        all_vulns = set()
        orgs = set()
        for h in hosts:
            for p in h.get("ports", []):
                all_ports.add(p["port"])
            all_vulns.update(h.get("vulns", []))
            orgs.add(h.get("org", ""))
        return {
            "total_hosts": len(hosts),
            "unique_ports": sorted(all_ports),
            "total_vulns": len(all_vulns),
            "vuln_ids": list(all_vulns),
            "organizations": list(orgs),
        }
