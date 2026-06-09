# ReconX 🔍

> Automated Passive + Active Reconnaissance CLI Tool

ReconX is a modular reconnaissance framework that automates subdomain enumeration, OSINT email harvesting, Shodan service discovery, and technology fingerprinting — outputting polished HTML and PDF reports.

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

> ⚠️ **For authorized use only.** Only scan domains you own or have explicit written permission to test. Unauthorized scanning may be illegal.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

---

## Features

| Module | Method | Description |
|--------|--------|-------------|
| **Subdomains** | Passive + Active | Sublist3r (OSINT) + DNS brute force |
| **Emails / OSINT** | Passive | theHarvester across 10+ sources |
| **Shodan** | Passive API | Exposed ports, banners, CVEs |
| **Fingerprinting** | Active | Server, CMS, frameworks, CDN, headers |
| **Reports** | — | HTML (dark theme) + PDF (printable) |

---

## Installation

### Prerequisites

- Python 3.9+

```bash
# 1. Clone the repo
git clone https://github.com/genrex-bot/reconx.git
cd reconx

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install external tools
pip install sublist3r theHarvester
```

---

## API Key Setup

> **Important:** API keys are set by **each user on their own machine**.
> Never put a real key in the code or commit it to GitHub.

ReconX uses the following external APIs. Each one is optional — if a key is missing, that module is skipped with a warning and everything else still runs.

---

### 🔑 Shodan API *(used by: `--modules shodan`)*

Shodan finds exposed services, open ports, and known CVEs for a target's IP.

**Step 1 — Get your key (free)**
1. Go to [https://account.shodan.io/register](https://account.shodan.io/register) and create a free account
2. After logging in, go to [https://account.shodan.io/](https://account.shodan.io/)
3. Your API key is shown at the top of the dashboard — copy it

> The free tier is enough. Host lookups don't require paid scan credits.

**Step 2 — Set your key**

```bash
# Copy the config template
cp config.example.ini config.ini

# Open config.ini and replace the placeholder with your key
SHODAN_API_KEY = paste_your_key_here
```

Or use an environment variable instead:

```bash
export SHODAN_API_KEY=paste_your_key_here
```

Or pass it directly at runtime:

```bash
python reconx.py -d example.com --shodan-key paste_your_key_here
```

---

### 🔑 theHarvester Sources *(used by: `--modules emails`)*

theHarvester is a standalone tool — it does **not** need an API key for most sources (Bing, DuckDuckGo, CRT.sh, etc.). However some premium sources inside theHarvester support optional keys.

**Install theHarvester:**

```bash
pip install theHarvester
```

That's it — it works out of the box for passive OSINT with no key required.

---

### 🔑 Sublist3r *(used by: `--modules subdomains`)*

Sublist3r scrapes public sources for subdomains. It requires **no API key**.

**Install:**

```bash
pip install sublist3r
```

---

### Config file overview

After running `cp config.example.ini config.ini`, your `config.ini` looks like this:

```ini
[api_keys]
SHODAN_API_KEY = your_key_here   ← only key needed right now

[settings]
threads = 10       ← DNS brute force thread count
timeout = 10       ← request timeout in seconds
report_format = both
output_dir = reports/output
```

> `config.ini` is in `.gitignore` — it will **never** be committed to GitHub. Only `config.example.ini` (which has placeholder text) is committed.

---

### Key priority order

If you set a key in multiple places, ReconX uses this priority:

```
--shodan-key flag  >  SHODAN_API_KEY env var  >  config.ini
```

---

## Usage

### Basic full scan

```bash
python reconx.py -d example.com
```

### Passive only (no DNS brute force, no active requests)

```bash
python reconx.py -d example.com --passive-only
```

### Run specific modules only

```bash
python reconx.py -d example.com --modules subdomains,emails
```

### With Shodan

```bash
python reconx.py -d example.com --shodan-key YOUR_KEY
```

### Custom output directory and format

```bash
python reconx.py -d example.com --output /tmp/reports --format pdf
```

### Custom DNS wordlist + more threads

```bash
python reconx.py -d example.com --wordlist wordlist.txt --threads 30
```

### Full verbose scan

```bash
python reconx.py -d example.com --verbose
```

---

## All CLI Flags

```
usage: reconx [-h] -d DOMAIN [--passive-only | --active-only]
              [--modules MODULE1,MODULE2] [--shodan-key API_KEY]
              [--output DIR] [--format {html,pdf,both,json}]
              [--threads N] [--wordlist FILE] [--timeout SEC]
              [--verbose] [--no-banner] [--version]

Options:
  -d, --domain       Target domain (required)
  --passive-only     Passive recon only (no DNS brute force)
  --active-only      Active recon only
  --modules          Comma-separated module list (default: all)
  --shodan-key       Shodan API key
  -o, --output       Output directory (default: reports/output)
  -f, --format       Report format: html | pdf | both | json
  --threads          DNS brute force thread count (default: 10)
  --wordlist         Custom wordlist file for DNS brute force
  --timeout          Request timeout in seconds (default: 10)
  -v, --verbose      Verbose output
  --no-banner        Suppress ASCII banner
  --version          Show version
```

---

## Reports

Reports are saved to `reports/output/` by default:

```
reports/output/
├── example.com_20240615_143022_recon.html   ← dark-themed, interactive
└── example.com_20240615_143022_recon.pdf    ← printable PDF
```

---

## Project Structure

```
reconx/
├── reconx.py                  # CLI entry point
├── requirements.txt
├── config.example.ini         # Config template (commit this)
├── config.ini                 # Your actual keys (DO NOT commit — gitignored)
├── modules/
│   ├── subdomain_enum.py      # Sublist3r + DNS brute force
│   ├── harvester.py           # theHarvester OSINT
│   ├── shodan_scan.py         # Shodan API
│   └── fingerprint.py         # Technology detection
├── reports/
│   ├── generator.py           # HTML + PDF report builder
│   └── output/                # Generated reports (gitignored)
├── utils/
│   ├── config_loader.py       # Loads keys from config/env/CLI
│   ├── logger.py
│   └── helpers.py
└── logs/                      # Scan logs (gitignored)
```

---

## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. The author is not responsible for any misuse or damage caused by this tool. Always obtain explicit written permission before scanning any domain or system you do not own.

---

## License

MIT License — see [LICENSE](LICENSE)
