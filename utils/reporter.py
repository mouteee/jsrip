"""
Multi-format report generator for jsrip scan results.
"""

import json
import csv
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generate reports in multiple formats (JSON, Markdown, HTML, PDF, CSV)."""
    
    def __init__(self, output_dir, logger):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Output directory path
            logger: Logger instance
        """
        self.output_dir = Path(output_dir)
        self.logger = logger
        self.reports_dir = self.output_dir / 'reports'
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, results, format_type):
        """
        Generate a report in the specified format.
        
        Args:
            results: Scan results dictionary
            format_type: Report format ('json', 'md', 'html', 'pdf', 'csv')
        """
        self.logger.info(f"Generating {format_type.upper()} report...")
        
        try:
            if format_type == 'json':
                self._generate_json(results)
            elif format_type == 'md':
                self._generate_markdown(results)
            elif format_type == 'html':
                self._generate_html(results)
            elif format_type == 'pdf':
                self._generate_pdf(results)
            elif format_type == 'csv':
                self._generate_csv(results)
            else:
                self.logger.warning(f"Unknown report format: {format_type}")
        except Exception as e:
            self.logger.error(f"Error generating {format_type} report: {e}")
    
    def _generate_json(self, results):
        """Generate JSON report."""
        output_file = self.reports_dir / 'report.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        self.logger.info(f"✓ JSON report: {output_file}")
    
    def _generate_markdown(self, results):
        """Generate Markdown report."""
        output_file = self.reports_dir / 'report.md'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("# jsrip Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Scan Info
            scan_info = results.get('scan_info', {})
            f.write("## Scan Information\n\n")
            f.write(f"- **Start Time:** {scan_info.get('start_time', 'N/A')}\n")
            f.write(f"- **End Time:** {scan_info.get('end_time', 'N/A')}\n")
            f.write(f"- **Duration:** {scan_info.get('duration', 'N/A')}\n")
            f.write(f"- **URLs Analyzed:** {scan_info.get('urls_count', 0)}\n\n")
            
            # Statistics
            stats = results.get('statistics', {})
            f.write("## Statistics\n\n")
            f.write(f"- **JavaScript Files:** {stats.get('js_files_downloaded', 0)}\n")
            f.write(f"- **Secrets Found:** {stats.get('secrets_found', 0)}\n")
            f.write(f"- **Endpoints Discovered:** {stats.get('endpoints_discovered', 0)}\n")
            f.write(f"- **Unique Domains:** {len(stats.get('unique_domains', []))}\n\n")
            
            # Secrets
            secrets = results.get('findings', {}).get('secrets', [])
            if secrets:
                f.write("## Secrets Found\n\n")
                f.write("| Type | Value | File | Confidence | Entropy |\n")
                f.write("|------|-------|------|------------|----------|\n")
                
                for secret in secrets:
                    value = secret.get('value', '')
                    # Truncate long values
                    if len(value) > 50:
                        value = value[:47] + '...'
                    
                    f.write(f"| {secret.get('type', 'N/A')} | "
                           f"`{value}` | "
                           f"{secret.get('file', 'N/A')} | "
                           f"{secret.get('confidence', 'N/A')} | "
                           f"{secret.get('entropy', 'N/A')} |\n")
                
                f.write("\n")
                
                # Secret details
                f.write("### Secret Details\n\n")
                for i, secret in enumerate(secrets, 1):
                    f.write(f"#### {i}. {secret.get('type', 'Unknown')}\n\n")
                    f.write(f"- **File:** `{secret.get('file', 'N/A')}`\n")
                    f.write(f"- **Value:** `{secret.get('value', 'N/A')}`\n")
                    f.write(f"- **Confidence:** {secret.get('confidence', 'N/A')}\n")
                    f.write(f"- **Entropy:** {secret.get('entropy', 'N/A')}\n")
                    
                    if 'also_in' in secret:
                        f.write(f"- **Also found in:** {', '.join(secret['also_in'])}\n")
                    
                    context = secret.get('context', '')
                    if context:
                        f.write(f"\n**Context:**\n```javascript\n{context}\n```\n")
                    f.write("\n")
            else:
                f.write("## Secrets Found\n\nNo secrets detected.\n\n")
            
            # Endpoints
            endpoints = results.get('findings', {}).get('endpoints', [])
            if endpoints:
                f.write("## Endpoints Discovered\n\n")
                for endpoint in endpoints:
                    f.write(f"- `{endpoint.get('url', 'N/A')}` ")
                    f.write(f"(from: {endpoint.get('source_file', 'N/A')})\n")
                f.write("\n")
            else:
                f.write("## Endpoints Discovered\n\nNo endpoints found.\n\n")
            
            # JS Files
            js_files = results.get('findings', {}).get('js_files', [])
            if js_files:
                f.write("## JavaScript Files\n\n")
                f.write("| Filename | URL | Size | SHA256 |\n")
                f.write("|----------|-----|------|--------|\n")
                
                for js_file in js_files:
                    f.write(f"| {js_file.get('filename', 'N/A')} | "
                           f"{js_file.get('url', 'N/A')} | "
                           f"{js_file.get('size', 0)} bytes | "
                           f"`{js_file.get('sha256', 'N/A')[:16]}...` |\n")
                f.write("\n")
        
        self.logger.info(f"✓ Markdown report: {output_file}")
    
    def _generate_html(self, results):
        """Generate HTML report."""
        output_file = self.reports_dir / 'report.html'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>jsrip Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .section {
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #667eea;
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .secret-detail {
            background: #f9f9f9;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }
        .secret-detail code {
            background: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .confidence-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .confidence-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .confidence-low {
            color: #3498db;
        }
        .context {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 jsrip Analysis Report</h1>
        <p>Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    </div>
""")
            
            # Statistics
            stats = results.get('statistics', {})
            f.write("""
    <div class="stats-grid">
        <div class="stat-card">
            <h3>JavaScript Files</h3>
            <div class="value">""" + str(stats.get('js_files_downloaded', 0)) + """</div>
        </div>
        <div class="stat-card">
            <h3>Secrets Found</h3>
            <div class="value">""" + str(stats.get('secrets_found', 0)) + """</div>
        </div>
        <div class="stat-card">
            <h3>Endpoints</h3>
            <div class="value">""" + str(stats.get('endpoints_discovered', 0)) + """</div>
        </div>
        <div class="stat-card">
            <h3>Unique Domains</h3>
            <div class="value">""" + str(len(stats.get('unique_domains', []))) + """</div>
        </div>
    </div>
""")
            
            # Secrets
            secrets = results.get('findings', {}).get('secrets', [])
            if secrets:
                f.write("""
    <div class="section">
        <h2>🔐 Secrets Found</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>File</th>
                <th>Confidence</th>
                <th>Entropy</th>
            </tr>
""")
                for secret in secrets:
                    confidence_class = f"confidence-{secret.get('confidence', 'low')}"
                    f.write(f"""
            <tr>
                <td><strong>{secret.get('type', 'N/A')}</strong></td>
                <td>{secret.get('file', 'N/A')}</td>
                <td class="{confidence_class}">{secret.get('confidence', 'N/A').upper()}</td>
                <td>{secret.get('entropy', 'N/A')}</td>
            </tr>
""")
                f.write("        </table>\n")
                
                # Secret details
                f.write("        <h3>Detailed Findings</h3>\n")
                
                for i, secret in enumerate(secrets, 1):
                    confidence_class = f"confidence-{secret.get('confidence', 'low')}"
                    value = secret.get('value', 'N/A')
                    if len(value) > 100:
                        value = value[:97] + '...'
                    
                    f.write(f"""
        <div class="secret-detail">
            <h4>{i}. {secret.get('type', 'Unknown')}</h4>
            <p><strong>File:</strong> <code>{secret.get('file', 'N/A')}</code></p>
            <p><strong>Value:</strong> <code>{value}</code></p>
            <p><strong>Confidence:</strong> <span class="{confidence_class}">{secret.get('confidence', 'N/A').upper()}</span></p>
            <p><strong>Entropy:</strong> {secret.get('entropy', 'N/A')}</p>
""")
                    
                    if 'also_in' in secret:
                        f.write(f"            <p><strong>Also found in:</strong> {', '.join(secret['also_in'])}</p>\n")
                    
                    context = secret.get('context', '')
                    if context:
                        # Escape HTML
                        context = context.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        f.write(f"""
            <p><strong>Context:</strong></p>
            <div class="context">{context}</div>
""")
                    f.write("        </div>\n")
                
                f.write("    </div>\n")
            
            # Endpoints
            endpoints = results.get('findings', {}).get('endpoints', [])
            if endpoints:
                f.write("""
    <div class="section">
        <h2>🌐 Endpoints Discovered</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Source File</th>
            </tr>
""")
                for endpoint in endpoints:
                    f.write(f"""
            <tr>
                <td><code>{endpoint.get('url', 'N/A')}</code></td>
                <td>{endpoint.get('source_file', 'N/A')}</td>
            </tr>
""")
                f.write("        </table>\n    </div>\n")
            
            # JS Files
            js_files = results.get('findings', {}).get('js_files', [])
            if js_files:
                f.write("""
    <div class="section">
        <h2>📄 JavaScript Files</h2>
        <table>
            <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>SHA256</th>
            </tr>
""")
                for js_file in js_files:
                    size = js_file.get('size', 0)
                    if size > 1024 * 1024:
                        size_str = f"{size / (1024 * 1024):.2f} MB"
                    elif size > 1024:
                        size_str = f"{size / 1024:.2f} KB"
                    else:
                        size_str = f"{size} bytes"
                    
                    sha256 = js_file.get('sha256', 'N/A')
                    if len(sha256) > 16:
                        sha256 = sha256[:16] + '...'
                    
                    f.write(f"""
            <tr>
                <td><code>{js_file.get('filename', 'N/A')}</code></td>
                <td>{size_str}</td>
                <td><code>{sha256}</code></td>
            </tr>
""")
                f.write("        </table>\n    </div>\n")
            
            f.write("""
</body>
</html>
""")
        
        self.logger.info(f"✓ HTML report: {output_file}")
    
    def _generate_pdf(self, results):
        """Generate PDF report using markdown2pdf conversion."""
        try:
            # First generate markdown
            self._generate_markdown(results)
            
            # Try to convert to PDF using various methods
            md_file = self.reports_dir / 'report.md'
            pdf_file = self.reports_dir / 'report.pdf'
            
            # Method 1: Try using markdown-pdf (if installed)
            try:
                import subprocess
                subprocess.run(
                    ['markdown-pdf', str(md_file), '-o', str(pdf_file)],
                    check=True,
                    capture_output=True
                )
                self.logger.info(f"✓ PDF report: {pdf_file}")
                return
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass
            
            # Method 2: Try using pandoc (if installed)
            try:
                import subprocess
                subprocess.run(
                    ['pandoc', str(md_file), '-o', str(pdf_file)],
                    check=True,
                    capture_output=True
                )
                self.logger.info(f"✓ PDF report: {pdf_file}")
                return
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass
            
            # Method 3: Try using weasyprint (Python library)
            try:
                from weasyprint import HTML
                html_file = self.reports_dir / 'report.html'
                if html_file.exists():
                    HTML(filename=str(html_file)).write_pdf(str(pdf_file))
                    self.logger.info(f"✓ PDF report: {pdf_file}")
                    return
            except ImportError:
                pass
            
            # If all methods fail
            self.logger.warning(
                "PDF generation requires one of: markdown-pdf, pandoc, or weasyprint. "
                "Markdown and HTML reports have been generated instead."
            )
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
    
    def _generate_csv(self, results):
        """Generate CSV reports for secrets and endpoints."""
        try:
            # Secrets CSV
            secrets = results.get('findings', {}).get('secrets', [])
            if secrets:
                secrets_file = self.reports_dir / 'secrets.csv'
                with open(secrets_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Type', 'Value', 'File', 'Confidence', 'Entropy', 'Context'])
                    
                    for secret in secrets:
                        writer.writerow([
                            secret.get('type', ''),
                            secret.get('value', ''),
                            secret.get('file', ''),
                            secret.get('confidence', ''),
                            secret.get('entropy', ''),
                            secret.get('context', '')[:500]  # Limit context length
                        ])
                
                self.logger.info(f"✓ Secrets CSV: {secrets_file}")
            
            # Endpoints CSV
            endpoints = results.get('findings', {}).get('endpoints', [])
            if endpoints:
                endpoints_file = self.reports_dir / 'endpoints.csv'
                with open(endpoints_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Source File'])
                    
                    for endpoint in endpoints:
                        writer.writerow([
                            endpoint.get('url', ''),
                            endpoint.get('source_file', '')
                        ])
                
                self.logger.info(f"✓ Endpoints CSV: {endpoints_file}")
            
            # JS Files CSV
            js_files = results.get('findings', {}).get('js_files', [])
            if js_files:
                js_files_file = self.reports_dir / 'js_files.csv'
                with open(js_files_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Filename', 'URL', 'Size', 'SHA256', 'Source Page'])
                    
                    for js_file in js_files:
                        writer.writerow([
                            js_file.get('filename', ''),
                            js_file.get('url', ''),
                            js_file.get('size', ''),
                            js_file.get('sha256', ''),
                            js_file.get('source_page', '')
                        ])
                
                self.logger.info(f"✓ JS Files CSV: {js_files_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating CSV reports: {e}")