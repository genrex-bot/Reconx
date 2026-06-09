"""
ReconX - Config Loader
Priority order:
  1. CLI flag (--shodan-key etc.)
  2. Environment variable (SHODAN_API_KEY)
  3. config.ini file
"""

import os
import configparser
from pathlib import Path

CONFIG_FILE = Path(__file__).parent.parent / "config.ini"
EXAMPLE_FILE = Path(__file__).parent.parent / "config.example.ini"


def load_config():
    """
    Load settings from config.ini if it exists.
    Returns a dict of all resolved config values.
    """
    cfg = configparser.ConfigParser()

    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)
    elif EXAMPLE_FILE.exists():
        # Silently read example as fallback (keys will be placeholder strings)
        cfg.read(EXAMPLE_FILE)

    def get(section, key, env_var=None, fallback=""):
        # 1. Environment variable wins
        if env_var and os.environ.get(env_var):
            return os.environ[env_var]
        # 2. config.ini value (skip placeholder)
        try:
            val = cfg.get(section, key)
            if val and "YOUR_" not in val and val.strip():
                return val.strip()
        except (configparser.NoSectionError, configparser.NoOptionError):
            pass
        # 3. Fallback default
        return fallback

    return {
        "shodan_api_key":       get("api_keys", "SHODAN_API_KEY",       "SHODAN_API_KEY"),
        "hunter_api_key":       get("api_keys", "HUNTER_API_KEY",       "HUNTER_API_KEY"),
        "securitytrails_key":   get("api_keys", "SECURITYTRAILS_API_KEY","SECURITYTRAILS_API_KEY"),
        "virustotal_key":       get("api_keys", "VIRUSTOTAL_API_KEY",    "VIRUSTOTAL_API_KEY"),
        "threads":          int(get("settings", "threads",               fallback="10")),
        "timeout":          int(get("settings", "timeout",               fallback="10")),
        "report_format":        get("settings", "report_format",         fallback="both"),
        "output_dir":           get("settings", "output_dir",            fallback="reports/output"),
    }


def check_api_keys(config, required=None):
    """
    Warn the user about missing API keys.
    `required` is a list of key names to check, e.g. ["shodan_api_key"]
    Returns True if all required keys are present.
    """
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    required = required or []
    missing = [k for k in required if not config.get(k)]

    if missing:
        lines = []
        for key in missing:
            lines.append(f"  [bold red]✗[/bold red] [bold]{key}[/bold] is not set")

        lines.append("")
        lines.append("[dim]Set it in [bold]config.ini[/bold] (copy config.example.ini),[/dim]")
        lines.append("[dim]or export as an environment variable:[/dim]")

        if "shodan_api_key" in missing:
            lines.append("[dim]  export SHODAN_API_KEY=your_key_here[/dim]")

        console.print(Panel(
            "\n".join(lines),
            title="[yellow]Missing API Keys[/yellow]",
            border_style="yellow"
        ))
        return False

    return True
