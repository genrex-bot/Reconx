"""
ReconX - Technology Fingerprinting Module
Detects CMS, frameworks, servers, analytics, CDNs using
header analysis + Wappalyzer patterns + BuiltWith API
"""

import re
import requests
import concurrent.futures
from urllib.parse import urlparse
from rich.console import Console

console = Console()

# Signature-based fingerprinting patterns
# Format: { "Technology": [("header/body", "regex_pattern"), ...] }
TECH_SIGNATURES = {
    # Web Servers
    "Apache": [("header:server", r"apache", True)],
    "Nginx": [("header:server", r"nginx", True)],
    "IIS": [("header:server", r"microsoft-iis", True)],
    "LiteSpeed": [("header:server", r"litespeed", True)],
    "Cloudflare": [("header:server", r"cloudflare", True), ("header:cf-ray", r".", True)],

    # CMS
    "WordPress": [
        ("body", r"/wp-content/", False),
        ("body", r"/wp-includes/", False),
        ("header:x-powered-by", r"wordpress", True),
    ],
    "Drupal": [
        ("body", r"Drupal", False),
        ("header:x-generator", r"drupal", True),
    ],
    "Joomla": [("body", r"/components/com_", False)],
    "Magento": [("body", r"Mage\.Cookies|magento", False)],
    "Shopify": [("body", r"cdn\.shopify\.com", False)],
    "Ghost": [("body", r'content="Ghost', False)],
    "Wix": [("body", r"wix\.com", False)],

    # JavaScript Frameworks
    "React": [("body", r"__REACT_DEVTOOLS|react\.development\.js|react\.production", False)],
    "Vue.js": [("body", r"vue\.js|__vue__", False)],
    "Angular": [("body", r"ng-version|angular\.min\.js", False)],
    "Next.js": [("body", r"__NEXT_DATA__|/_next/static", False)],
    "Nuxt.js": [("body", r"__nuxt__|/_nuxt/", False)],

    # Backend Frameworks
    "Django": [("header:x-frame-options", r".", True), ("body", r"csrfmiddlewaretoken", False)],
    "Laravel": [("header:set-cookie", r"laravel_session", True)],
    "Ruby on Rails": [("header:x-powered-by", r"phusion passenger", True)],
    "ASP.NET": [("header:x-aspnet-version", r".", True), ("header:x-powered-by", r"asp\.net", True)],
    "Express.js": [("header:x-powered-by", r"express", True)],

    # Analytics / CDN
    "Google Analytics": [("body", r"google-analytics\.com/analytics|gtag\('config'", False)],
    "Google Tag Manager": [("body", r"googletagmanager\.com/gtm", False)],
    "Cloudflare CDN": [("header:cf-cache-status", r".", True)],
    "Fastly": [("header:x-served-by", r"cache", True)],
    "AWS CloudFront": [("header:via", r"cloudfront", True)],

    # Security Headers
    "HSTS": [("header:strict-transport-security", r".", True)],
    "CSP": [("header:content-security-policy", r".", True)],
    "WAF (Generic)": [("header:x-sucuri-id", r".", True)],
    "ModSecurity": [("header:server", r"mod_security", True)],
}


class TechFingerprinter:
    def __init__(self, domain, subdomains=None, timeout=10, verbose=False, logger=None):
        self.domain = domain
        self.subdomains = subdomains or []
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logger

    def run(self):
        """Fingerprint the main domain + key subdomains."""
        targets = self._build_targets()
        console.print(f"[bold]▸ Fingerprinting {len(targets)} targets...[/bold]")

        all_tech = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self._fingerprint_url, url): url for url in targets}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    detected = future.result()
                    if detected:
                        all_tech[url] = detected
                        if self.verbose:
                            techs = ", ".join(detected.keys())
                            console.print(f"  [dim]→[/dim] {url}: [cyan]{techs}[/cyan]")
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Fingerprint error for {url}: {e}")

        return all_tech

    def _build_targets(self):
        targets = [f"https://{self.domain}", f"http://{self.domain}"]
        # Include a sample of interesting subdomains
        interesting = ["www", "api", "admin", "portal", "app", "dashboard", "mail", "webmail"]
        for sub in self.subdomains[:20]:  # cap at 20
            host = sub.split(".")[0]
            if host in interesting or not self.subdomains:
                targets.append(f"https://{sub}")
        return list(dict.fromkeys(targets))  # deduplicate preserving order

    def _fingerprint_url(self, url):
        """Fetch URL and run signature matching."""
        detected = {}
        try:
            resp = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (compatible; ReconX/1.0; "
                        "+https://github.com/yourusername/reconx)"
                    )
                }
            )
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body = resp.text

            for tech, patterns in TECH_SIGNATURES.items():
                for (target, pattern, case_insensitive) in patterns:
                    if self._matches(target, pattern, headers, body, case_insensitive):
                        meta = {}
                        # Try to extract version hints
                        version = self._extract_version(tech, headers, body)
                        if version:
                            meta["version"] = version
                        detected[tech] = meta
                        break  # first match wins per technology

        except requests.exceptions.SSLError:
            # Try HTTP fallback
            pass
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Request error for {url}: {e}")

        return detected

    def _matches(self, target, pattern, headers, body, case_insensitive):
        flags = re.IGNORECASE if case_insensitive else 0
        if target.startswith("header:"):
            key = target[7:]
            value = headers.get(key, "")
            return bool(re.search(pattern, value, flags))
        elif target == "body":
            return bool(re.search(pattern, body, flags))
        return False

    def _extract_version(self, tech, headers, body):
        """Attempt to extract a version string for known technologies."""
        extractors = {
            "WordPress": (r'<meta name="generator" content="WordPress ([^"]+)"', body),
            "Drupal": (r'<meta name="Generator" content="Drupal ([^";]+)', body),
            "Nginx": (r"nginx/([\d.]+)", headers.get("server", "")),
            "Apache": (r"Apache/([\d.]+)", headers.get("server", "")),
            "IIS": (r"IIS/([\d.]+)", headers.get("server", "")),
            "ASP.NET": (r"([\d.]+)", headers.get("x-aspnet-version", "")),
        }
        extractor = extractors.get(tech)
        if extractor:
            pattern, text = extractor
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
