"""ReconX - Helper utilities"""

import re
from rich.console import Console
from rich.text import Text

console = Console()

BANNER = r"""
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
"""

TAGLINE = "  Automated Passive + Active Recon Tool  |  v1.0.0"
WARNING = "  ⚠  For authorized use only. Unauthorized scanning is illegal."


def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"[dim]{TAGLINE}[/dim]")
    console.print(f"[yellow]{WARNING}[/yellow]")
    console.print()


def validate_domain(domain: str) -> bool:
    """Validate that the input looks like a real domain name."""
    # Strip protocol if user accidentally included it
    domain = domain.lower().strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]  # strip paths

    pattern = r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
    return bool(re.match(pattern, domain))


def sanitize_domain(domain: str) -> str:
    """Strip protocol and path from a domain string."""
    domain = domain.lower().strip()
    domain = re.sub(r"^https?://", "", domain)
    return domain.split("/")[0]
