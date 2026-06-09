"""
ReconX - Report Generator
Produces professional HTML and PDF recon reports
"""

import os
import json
from datetime import datetime
from rich.console import Console

console = Console()


class ReportGenerator:
    def __init__(self, results, output_dir, domain, logger=None):
        self.results = results
        self.output_dir = output_dir
        self.domain = domain
        self.logger = logger
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── HTML Report ──────────────────────────────────────────────

    def generate_html(self):
        filename = f"{self.domain}_{self.timestamp}_recon.html"
        path = os.path.join(self.output_dir, filename)

        html = self._build_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        if self.logger:
            self.logger.info(f"HTML report saved: {path}")
        return path

    def _build_html(self):
        r = self.results
        subdomains = r.get("subdomains", [])
        emails = r.get("emails", [])
        shodan = r.get("shodan", {})
        tech = r.get("technologies", {})
        errors = r.get("errors", [])

        scan_start = r.get("scan_start", "N/A")
        scan_end = r.get("scan_end", "N/A")

        # Duration
        try:
            from datetime import datetime
            s = datetime.fromisoformat(scan_start)
            e = datetime.fromisoformat(scan_end)
            duration = str(e - s).split(".")[0]
        except Exception:
            duration = "N/A"

        sub_rows = "\n".join(
            f"<tr><td>{i+1}</td><td>{s}</td></tr>"
            for i, s in enumerate(subdomains)
        ) or "<tr><td colspan='2'>No subdomains found</td></tr>"

        email_rows = "\n".join(
            f"<tr><td>{i+1}</td><td>{e}</td></tr>"
            for i, e in enumerate(emails)
        ) or "<tr><td colspan='2'>No emails found</td></tr>"

        # Shodan hosts
        shodan_hosts = shodan.get("hosts", [])
        shodan_rows = ""
        for h in shodan_hosts:
            ports = ", ".join(
                f"{p['port']}/{p['transport']}" for p in h.get("ports", [])
            )
            vulns = ", ".join(h.get("vulns", [])) or "None"
            shodan_rows += f"""
            <tr>
                <td>{h.get('ip','')}</td>
                <td>{h.get('org','')}</td>
                <td>{h.get('country','')}</td>
                <td>{ports}</td>
                <td class="{'vuln-cell' if h.get('vulns') else ''}">{vulns}</td>
            </tr>"""
        if not shodan_rows:
            shodan_rows = "<tr><td colspan='5'>No Shodan data</td></tr>"

        # Technology table
        tech_rows = ""
        all_tech = {}
        for url, techs in tech.items():
            for t, meta in techs.items():
                if t not in all_tech:
                    all_tech[t] = {"urls": [], "version": meta.get("version", "")}
                all_tech[t]["urls"].append(url)
        for t, info in sorted(all_tech.items()):
            tech_rows += f"""
            <tr>
                <td>{t}</td>
                <td>{info['version'] or '—'}</td>
                <td>{len(info['urls'])}</td>
            </tr>"""
        if not tech_rows:
            tech_rows = "<tr><td colspan='3'>No technologies detected</td></tr>"

        error_section = ""
        if errors:
            items = "\n".join(f"<li>{e}</li>" for e in errors)
            error_section = f"<div class='errors'><strong>Warnings:</strong><ul>{items}</ul></div>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconX Report — {self.domain}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #00d4ff; --red: #f85149; --green: #3fb950;
    --yellow: #d29922; --text: #c9d1d9; --muted: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; }}
  header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 2rem; }}
  header h1 {{ color: var(--accent); font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; }}
  header h1 span {{ color: var(--muted); font-weight: 400; }}
  .meta {{ display: flex; gap: 2rem; margin-top: 1rem; flex-wrap: wrap; }}
  .meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
  .meta-item label {{ font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .meta-item value {{ font-size: 0.9rem; color: var(--text); }}
  main {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .stat .lbl {{ font-size: 0.8rem; color: var(--muted); margin-top: 4px; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }}
  .section-header {{ padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.6rem; }}
  .section-header h2 {{ font-size: 1rem; font-weight: 600; }}
  .badge {{ background: var(--accent); color: #000; border-radius: 20px; padding: 2px 10px; font-size: 0.75rem; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: rgba(255,255,255,0.03); padding: 10px 16px; text-align: left; color: var(--muted); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 16px; border-bottom: 1px solid rgba(48,54,61,0.5); }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .vuln-cell {{ color: var(--red); font-weight: 500; }}
  .errors {{ background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.3); border-radius: 6px; padding: 1rem 1.5rem; margin-top: 1.5rem; font-size: 0.875rem; color: var(--yellow); }}
  .errors ul {{ margin-left: 1.2rem; margin-top: 0.4rem; }}
  footer {{ text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
</style>
</head>
<body>
<header>
  <h1>ReconX <span>/ {self.domain}</span></h1>
  <div class="meta">
    <div class="meta-item"><label>Target</label><value>{self.domain}</value></div>
    <div class="meta-item"><label>Scan Start</label><value>{scan_start}</value></div>
    <div class="meta-item"><label>Duration</label><value>{duration}</value></div>
    <div class="meta-item"><label>Mode</label><value>{r.get('scan_mode','full').capitalize()}</value></div>
  </div>
</header>

<main>
  <div class="stats-grid">
    <div class="stat"><div class="num">{len(subdomains)}</div><div class="lbl">Subdomains</div></div>
    <div class="stat"><div class="num">{len(emails)}</div><div class="lbl">Emails</div></div>
    <div class="stat"><div class="num">{len(shodan_hosts)}</div><div class="lbl">Shodan Hosts</div></div>
    <div class="stat"><div class="num">{len(all_tech)}</div><div class="lbl">Technologies</div></div>
    <div class="stat"><div class="num">{shodan.get('summary', {}).get('total_vulns', 0) if isinstance(shodan, dict) else 0}</div><div class="lbl">CVEs Found</div></div>
  </div>

  <div class="section">
    <div class="section-header"><h2>Subdomains</h2><span class="badge">{len(subdomains)}</span></div>
    <table><thead><tr><th>#</th><th>Subdomain</th></tr></thead>
    <tbody>{sub_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header"><h2>Emails & OSINT</h2><span class="badge">{len(emails)}</span></div>
    <table><thead><tr><th>#</th><th>Email Address</th></tr></thead>
    <tbody>{email_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header"><h2>Shodan — Exposed Services</h2><span class="badge">{len(shodan_hosts)}</span></div>
    <table><thead><tr><th>IP</th><th>Organization</th><th>Country</th><th>Open Ports</th><th>CVEs</th></tr></thead>
    <tbody>{shodan_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header"><h2>Technology Fingerprint</h2><span class="badge">{len(all_tech)}</span></div>
    <table><thead><tr><th>Technology</th><th>Version</th><th>Detected On</th></tr></thead>
    <tbody>{tech_rows}</tbody></table>
  </div>

  {error_section}
</main>

<footer>Generated by ReconX &bull; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &bull; For authorized use only</footer>
</body>
</html>"""

    # ── PDF Report ───────────────────────────────────────────────

    def generate_pdf(self):
        filename = f"{self.domain}_{self.timestamp}_recon.pdf"
        path = os.path.join(self.output_dir, filename)

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, PageBreak
            )

            doc = SimpleDocTemplate(
                path,
                pagesize=A4,
                topMargin=2*cm, bottomMargin=2*cm,
                leftMargin=2*cm, rightMargin=2*cm
            )

            styles = getSampleStyleSheet()
            # Custom styles
            title_style = ParagraphStyle(
                "Title", parent=styles["Title"],
                fontSize=20, textColor=colors.HexColor("#00d4ff"),
                spaceAfter=6
            )
            h2_style = ParagraphStyle(
                "H2", parent=styles["Heading2"],
                fontSize=12, textColor=colors.HexColor("#00d4ff"),
                spaceBefore=16, spaceAfter=6
            )
            normal = styles["Normal"]
            small = ParagraphStyle("Small", parent=normal, fontSize=8, textColor=colors.grey)
            muted = ParagraphStyle("Muted", parent=normal, fontSize=9, textColor=colors.HexColor("#8b949e"))

            # Table style helper
            def base_table_style():
                return TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#8b949e")),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ])

            r = self.results
            subdomains = r.get("subdomains", [])
            emails = r.get("emails", [])
            shodan = r.get("shodan", {})
            tech = r.get("technologies", {})

            story = []

            # Title
            story.append(Paragraph(f"ReconX Reconnaissance Report", title_style))
            story.append(Paragraph(f"Target: {self.domain}", h2_style))
            story.append(Paragraph(
                f"Scan Date: {r.get('scan_start','N/A')} | Mode: {r.get('scan_mode','full').capitalize()}",
                muted
            ))
            story.append(HRFlowable(width="100%", color=colors.HexColor("#30363d"), spaceAfter=12))

            # Summary stats
            story.append(Paragraph("Summary", h2_style))
            stats_data = [
                ["Category", "Count"],
                ["Subdomains found", str(len(subdomains))],
                ["Emails harvested", str(len(emails))],
                ["Shodan hosts", str(len(shodan.get("hosts", [])))],
                ["Technologies detected", str(len(tech))],
                ["CVEs found", str(shodan.get("summary", {}).get("total_vulns", 0))],
            ]
            stats_table = Table(stats_data, colWidths=[10*cm, 5*cm])
            stats_table.setStyle(base_table_style())
            story.append(stats_table)

            # Subdomains
            story.append(Paragraph(f"Subdomains ({len(subdomains)})", h2_style))
            if subdomains:
                # 3-column layout for compactness
                rows = [["Subdomain", "Subdomain", "Subdomain"]]
                chunk = [subdomains[i:i+3] for i in range(0, len(subdomains), 3)]
                for group in chunk:
                    while len(group) < 3:
                        group.append("")
                    rows.append(group)
                sub_table = Table(rows, colWidths=[5.5*cm, 5.5*cm, 5.5*cm])
                sub_table.setStyle(base_table_style())
                story.append(sub_table)
            else:
                story.append(Paragraph("No subdomains found.", muted))

            # Emails
            story.append(Paragraph(f"Emails & OSINT ({len(emails)})", h2_style))
            if emails:
                email_data = [["#", "Email Address"]]
                for i, e in enumerate(emails, 1):
                    email_data.append([str(i), e])
                email_table = Table(email_data, colWidths=[1*cm, 15*cm])
                email_table.setStyle(base_table_style())
                story.append(email_table)
            else:
                story.append(Paragraph("No emails found.", muted))

            # Shodan
            story.append(PageBreak())
            story.append(Paragraph(f"Shodan — Exposed Services", h2_style))
            shodan_hosts = shodan.get("hosts", [])
            if shodan_hosts:
                sh_data = [["IP", "Org", "Country", "Ports", "CVEs"]]
                for h in shodan_hosts:
                    ports = ", ".join(
                        f"{p['port']}/{p['transport']}" for p in h.get("ports", [])[:5]
                    )
                    vulns = ", ".join(h.get("vulns", [])[:3]) or "None"
                    sh_data.append([
                        h.get("ip", ""), h.get("org", "")[:20],
                        h.get("country", ""), ports[:30], vulns[:30]
                    ])
                sh_table = Table(sh_data, colWidths=[3*cm, 4*cm, 3*cm, 4*cm, 3*cm])
                sh_table.setStyle(base_table_style())
                story.append(sh_table)
            else:
                story.append(Paragraph("No Shodan data available (key not set or no results).", muted))

            # Technologies
            story.append(Paragraph("Technology Fingerprint", h2_style))
            all_tech = {}
            for url, techs in tech.items():
                for t, meta in techs.items():
                    if t not in all_tech:
                        all_tech[t] = {"urls": [], "version": meta.get("version", "")}
                    all_tech[t]["urls"].append(url)

            if all_tech:
                t_data = [["Technology", "Version", "Detected On"]]
                for t, info in sorted(all_tech.items()):
                    t_data.append([t, info["version"] or "—", str(len(info["urls"])) + " target(s)"])
                t_table = Table(t_data, colWidths=[6*cm, 4*cm, 7*cm])
                t_table.setStyle(base_table_style())
                story.append(t_table)
            else:
                story.append(Paragraph("No technologies detected.", muted))

            # Footer note
            story.append(Spacer(1, 24))
            story.append(HRFlowable(width="100%", color=colors.HexColor("#30363d")))
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                "Generated by ReconX — For authorized use only. "
                f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                small
            ))

            doc.build(story)

        except ImportError:
            console.print("[yellow]  ⚠ reportlab not installed. Install: pip install reportlab[/yellow]")
            return None
        except Exception as e:
            console.print(f"[red]  ✗ PDF generation error: {e}[/red]")
            if self.logger:
                self.logger.error(f"PDF generation failed: {e}")
            return None

        if self.logger:
            self.logger.info(f"PDF report saved: {path}")
        return path
