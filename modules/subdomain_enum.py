"""
ReconX - Subdomain Enumeration Module
Uses Sublist3r (passive) + DNS brute force (active)
"""

import dns.resolver
import concurrent.futures
import subprocess
import os
import sys
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# Built-in wordlist for DNS brute force
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "dev", "staging", "test", "api", "app", "portal", "admin",
    "dashboard", "blog", "shop", "store", "cdn", "static", "assets",
    "images", "img", "media", "upload", "downloads", "files", "docs",
    "support", "help", "kb", "forum", "community", "git", "gitlab",
    "github", "jenkins", "ci", "jira", "confluence", "wiki", "internal",
    "intranet", "extranet", "login", "sso", "auth", "oauth", "id",
    "ns1", "ns2", "mx1", "mx2", "smtp1", "smtp2", "relay", "gateway",
    "monitor", "nagios", "zabbix", "grafana", "prometheus", "kibana",
    "elastic", "redis", "db", "database", "mysql", "postgres", "mongo",
    "backup", "bak", "old", "new", "v2", "beta", "alpha", "demo",
    "sandbox", "uat", "prod", "production", "live", "web", "web1", "web2",
    "server", "srv", "host", "node", "proxy", "lb", "loadbalancer",
    "cloud", "aws", "azure", "gcp", "s3", "bucket", "k8s", "docker",
]


class SubdomainEnumerator:
    def __init__(self, domain, passive_only=False, threads=10,
                 wordlist=None, timeout=10, verbose=False, logger=None):
        self.domain = domain
        self.passive_only = passive_only
        self.threads = threads
        self.wordlist_path = wordlist
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logger
        self.found = set()

    def run(self):
        """Main entry — runs passive then active recon."""
        self._run_sublist3r()

        if not self.passive_only:
            self._run_dns_bruteforce()

        subdomains = sorted(self.found)
        if self.verbose:
            for sub in subdomains:
                console.print(f"  [dim]→[/dim] {sub}")
        return subdomains

    # ── Passive: Sublist3r ───────────────────────────────────────

    def _run_sublist3r(self):
        console.print("[bold]▸ Running Sublist3r (passive)...[/bold]")
        try:
            result = subprocess.run(
                ["sublist3r", "-d", self.domain, "-o", "/tmp/sublist3r_out.txt", "-n"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if os.path.exists("/tmp/sublist3r_out.txt"):
                with open("/tmp/sublist3r_out.txt") as f:
                    for line in f:
                        sub = line.strip().lower()
                        if sub and self.domain in sub:
                            self.found.add(sub)
                os.remove("/tmp/sublist3r_out.txt")
            if self.verbose and result.stdout:
                console.print(f"[dim]{result.stdout[:500]}[/dim]")
        except FileNotFoundError:
            console.print("[yellow]  ⚠ Sublist3r not found. Install: pip install sublist3r[/yellow]")
            if self.logger:
                self.logger.warning("Sublist3r not installed — falling back to DNS bruteforce only")
        except subprocess.TimeoutExpired:
            console.print("[yellow]  ⚠ Sublist3r timed out after 120s[/yellow]")
        except Exception as e:
            console.print(f"[red]  ✗ Sublist3r error: {e}[/red]")

    # ── Active: DNS Brute Force ──────────────────────────────────

    def _load_wordlist(self):
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            with open(self.wordlist_path) as f:
                return [line.strip() for line in f if line.strip()]
        return DEFAULT_WORDLIST

    def _resolve(self, subdomain):
        """Try to resolve a subdomain. Returns subdomain string or None."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(subdomain, "A")
            if answers:
                return subdomain
        except Exception:
            return None

    def _run_dns_bruteforce(self):
        wordlist = self._load_wordlist()
        candidates = [f"{word}.{self.domain}" for word in wordlist]
        console.print(f"[bold]▸ DNS brute force ({len(candidates)} candidates, {self.threads} threads)...[/bold]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Resolving...", total=len(candidates))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._resolve, c): c for c in candidates}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.found.add(result)
                        if self.verbose:
                            console.print(f"  [green]+[/green] {result}")
                    progress.advance(task)
