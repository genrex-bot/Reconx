"""
ReconX - Email & OSINT Harvesting Module
Wraps theHarvester for email, host, and OSINT gathering
"""

import subprocess
import re
import os
import json
from rich.console import Console

console = Console()

# Sources supported by theHarvester (passive OSINT)
HARVESTER_SOURCES = [
    "bing", "duckduckgo", "google", "yahoo",
    "crtsh", "dnsdumpster", "hackertarget",
    "rapiddns", "urlscan", "otx"
]


class HarvesterModule:
    def __init__(self, domain, verbose=False, logger=None):
        self.domain = domain
        self.verbose = verbose
        self.logger = logger
        self.emails = []
        self.hosts = []
        self.ips = []

    def run(self):
        """Run theHarvester across all sources, return deduplicated emails."""
        console.print("[bold]▸ Running theHarvester (passive OSINT)...[/bold]")

        all_emails = set()
        all_hosts = set()

        for source in HARVESTER_SOURCES:
            emails, hosts = self._harvest_source(source)
            all_emails.update(emails)
            all_hosts.update(hosts)

        self.emails = sorted(all_emails)
        self.hosts = sorted(all_hosts)

        if self.verbose:
            for email in self.emails:
                console.print(f"  [dim]→[/dim] {email}")

        return self.emails

    def _harvest_source(self, source):
        """Run theHarvester for a single source, parse results."""
        emails = set()
        hosts = set()

        try:
            out_file = f"/tmp/harvester_{source}.json"
            cmd = [
                "theHarvester",
                "-d", self.domain,
                "-b", source,
                "-f", out_file.replace(".json", ""),
                "-l", "200"   # limit results
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse JSON output if available
            if os.path.exists(out_file):
                try:
                    with open(out_file) as f:
                        data = json.load(f)
                    emails.update(data.get("emails", []))
                    hosts.update(data.get("hosts", []))
                except Exception:
                    pass
                os.remove(out_file)

            # Also parse stdout as fallback
            if result.stdout:
                emails.update(self._parse_emails(result.stdout))
                hosts.update(self._parse_hosts(result.stdout))

            if self.verbose:
                e_count = len(emails)
                h_count = len(hosts)
                if e_count or h_count:
                    console.print(
                        f"  [dim]{source}:[/dim] "
                        f"[green]{e_count} emails[/green], "
                        f"[cyan]{h_count} hosts[/cyan]"
                    )

        except FileNotFoundError:
            if source == HARVESTER_SOURCES[0]:  # only warn once
                console.print(
                    "[yellow]  ⚠ theHarvester not found. "
                    "Install: pip install theHarvester[/yellow]"
                )
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]  ⚠ theHarvester timed out for source: {source}[/yellow]")
        except Exception as e:
            if self.logger:
                self.logger.debug(f"theHarvester [{source}] error: {e}")

        return emails, hosts

    def _parse_emails(self, text):
        """Extract email addresses from raw text output."""
        pattern = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        found = re.findall(pattern, text)
        # Filter to target domain only
        return {e.lower() for e in found if self.domain in e}

    def _parse_hosts(self, text):
        """Extract hostnames from raw text output."""
        pattern = rf"[\w\-]+(?:\.[\w\-]+)*\.{re.escape(self.domain)}"
        found = re.findall(pattern, text)
        return {h.lower() for h in found}
