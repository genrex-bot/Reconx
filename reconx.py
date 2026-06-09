#!/usr/bin/env python3
"""
ReconX - Automated Passive + Active Reconnaissance Tool
Author: Your Name
GitHub: https://github.com/yourusername/reconx
License: MIT
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from modules.subdomain_enum import SubdomainEnumerator
from modules.harvester import HarvesterModule
from modules.shodan_scan import ShodanScanner
from modules.fingerprint import TechFingerprinter
from reports.generator import ReportGenerator
from utils.logger import setup_logger
from utils.helpers import validate_domain, print_banner
from utils.config_loader import load_config, check_api_keys

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - Automated Passive + Active Recon Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconx.py -d example.com
  python reconx.py -d example.com --passive-only
  python reconx.py -d example.com --modules subdomains,emails
  python reconx.py -d example.com --output /tmp/reports --shodan-key YOUR_KEY
  python reconx.py -d example.com --format html
  python reconx.py -d example.com --threads 20 --verbose

Modules:
  subdomains   Enumerate subdomains using Sublist3r + DNS brute force
  emails       OSINT email harvesting via theHarvester
  shodan       Exposed services & banners via Shodan API
  fingerprint  Technology stack fingerprinting (Wappalyzer/BuiltWith)

Notes:
  - Use only on domains you own or have explicit written permission to test.
  - Shodan module requires a valid API key (--shodan-key or SHODAN_API_KEY env var).
  - Active recon (DNS brute force) generates real network traffic to the target.
        """
    )

    # Target
    parser.add_argument(
        "-d", "--domain",
        required=True,
        metavar="DOMAIN",
        help="Target domain (e.g. example.com)"
    )

    # Scan mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--passive-only",
        action="store_true",
        help="Run passive recon only (no DNS brute force)"
    )
    mode_group.add_argument(
        "--active-only",
        action="store_true",
        help="Run active recon only (DNS brute force, port scanning)"
    )

    # Module selection
    parser.add_argument(
        "--modules",
        metavar="MODULE1,MODULE2",
        default="subdomains,emails,shodan,fingerprint",
        help="Comma-separated list of modules to run (default: all)"
    )

    # Shodan
    parser.add_argument(
        "--shodan-key",
        metavar="API_KEY",
        default=os.environ.get("SHODAN_API_KEY", ""),
        help="Shodan API key (or set SHODAN_API_KEY env var)"
    )

    # Output
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="reports/output",
        help="Output directory for reports (default: reports/output)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "pdf", "both", "json"],
        default="both",
        help="Report format (default: both)"
    )

    # Tuning
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Number of threads for DNS brute force (default: 10)"
    )
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        default=None,
        help="Custom wordlist for DNS brute force (default: built-in)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="Request timeout in seconds (default: 10)"
    )

    # Misc
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ReconX v1.0.0"
    )

    return parser.parse_args()


def run_recon(args, logger):
    results = {
        "target": args.domain,
        "scan_start": datetime.now().isoformat(),
        "scan_mode": "passive" if args.passive_only else "active" if args.active_only else "full",
        "subdomains": [],
        "emails": [],
        "shodan": {},
        "technologies": {},
        "errors": []
    }

    modules = [m.strip() for m in args.modules.split(",")]

    # ── Subdomains ──────────────────────────────────────────────
    if "subdomains" in modules:
        console.rule("[bold cyan]Subdomain Enumeration")
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            passive_only=args.passive_only,
            threads=args.threads,
            wordlist=args.wordlist,
            timeout=args.timeout,
            verbose=args.verbose,
            logger=logger
        )
        results["subdomains"] = enumerator.run()
        console.print(f"[green]✓[/green] Found [bold]{len(results['subdomains'])}[/bold] subdomains\n")

    # ── Email / OSINT ────────────────────────────────────────────
    if "emails" in modules:
        console.rule("[bold cyan]Email & OSINT Harvesting")
        harvester = HarvesterModule(
            domain=args.domain,
            verbose=args.verbose,
            logger=logger
        )
        results["emails"] = harvester.run()
        console.print(f"[green]✓[/green] Found [bold]{len(results['emails'])}[/bold] email addresses\n")

    # ── Shodan ───────────────────────────────────────────────────
    if "shodan" in modules:
        console.rule("[bold cyan]Shodan Service Discovery")
        if not args.shodan_key:
            console.print("[yellow]⚠[/yellow]  Shodan key not set — skipping. Use --shodan-key or set SHODAN_API_KEY.\n")
            results["errors"].append("Shodan API key missing")
        else:
            scanner = ShodanScanner(
                domain=args.domain,
                api_key=args.shodan_key,
                verbose=args.verbose,
                logger=logger
            )
            results["shodan"] = scanner.run()
            host_count = len(results["shodan"].get("hosts", []))
            console.print(f"[green]✓[/green] Found [bold]{host_count}[/bold] exposed hosts\n")

    # ── Fingerprinting ───────────────────────────────────────────
    if "fingerprint" in modules:
        console.rule("[bold cyan]Technology Fingerprinting")
        fingerprinter = TechFingerprinter(
            domain=args.domain,
            subdomains=results.get("subdomains", []),
            timeout=args.timeout,
            verbose=args.verbose,
            logger=logger
        )
        results["technologies"] = fingerprinter.run()
        tech_count = len(results["technologies"])
        console.print(f"[green]✓[/green] Identified [bold]{tech_count}[/bold] technologies\n")

    results["scan_end"] = datetime.now().isoformat()
    return results


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    logger = setup_logger(verbose=args.verbose)

    # Load config (config.ini → env var → CLI flag — CLI wins)
    config = load_config()
    if not args.shodan_key and config.get("shodan_api_key"):
        args.shodan_key = config["shodan_api_key"]
    if args.threads == 10 and config.get("threads"):
        args.threads = config["threads"]
    if args.timeout == 10 and config.get("timeout"):
        args.timeout = config["timeout"]

    # Validate domain
    if not validate_domain(args.domain):
        console.print(f"[red]✗[/red] Invalid domain: [bold]{args.domain}[/bold]")
        sys.exit(1)

    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{args.domain}[/cyan]\n"
        f"[bold white]Mode:[/bold white]   {'Passive only' if args.passive_only else 'Active only' if args.active_only else 'Full (Passive + Active)'}\n"
        f"[bold white]Modules:[/bold white] {args.modules}\n"
        f"[bold white]Report:[/bold white]  {args.format.upper()} → {args.output}",
        title="[bold cyan]ReconX Scan Config",
        border_style="cyan"
    ))

    start_time = time.time()

    try:
        results = run_recon(args, logger)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠[/yellow]  Scan interrupted by user.")
        sys.exit(0)

    elapsed = round(time.time() - start_time, 2)

    # ── Generate Reports ─────────────────────────────────────────
    console.rule("[bold cyan]Generating Reports")
    os.makedirs(args.output, exist_ok=True)

    generator = ReportGenerator(
        results=results,
        output_dir=args.output,
        domain=args.domain,
        logger=logger
    )

    report_files = []
    if args.format in ("html", "both"):
        html_path = generator.generate_html()
        report_files.append(("HTML", html_path))

    if args.format in ("pdf", "both"):
        pdf_path = generator.generate_pdf()
        report_files.append(("PDF", pdf_path))

    if args.format == "json":
        json_path = os.path.join(args.output, f"{args.domain}_recon.json")
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2)
        report_files.append(("JSON", json_path))

    # ── Summary ──────────────────────────────────────────────────
    console.print()
    table = Table(title="Scan Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Category", style="bold white")
    table.add_column("Count", justify="right", style="green")

    table.add_row("Subdomains found", str(len(results.get("subdomains", []))))
    table.add_row("Emails harvested", str(len(results.get("emails", []))))
    table.add_row("Shodan hosts", str(len(results.get("shodan", {}).get("hosts", []))))
    table.add_row("Technologies detected", str(len(results.get("technologies", {}))))
    table.add_row("Errors", str(len(results.get("errors", []))))
    table.add_row("Scan duration", f"{elapsed}s")

    console.print(table)
    console.print()

    for fmt, path in report_files:
        console.print(f"[green]✓[/green] {fmt} report saved → [bold]{path}[/bold]")

    console.print(f"\n[bold green]Recon complete in {elapsed}s[/bold green]\n")


if __name__ == "__main__":
    main()
