import os
import json
from datetime import datetime

def generate_html_report(scan_results, output_path="scan_results.html"):
    """
    Generates a standalone HTML report from the scan results.
    """
    
    # safe extraction of data with defaults
    summary = scan_results.get("summary", {})
    vulnerabilities = scan_results.get("vulnerabilities", [])
    
    total_files = summary.get("total_files", 0)
    total_issues = summary.get("total_issues", 0)
    scan_duration = summary.get("scan_duration", 0)
    
    # Generate the vulnerability rows using a standard python loop
    vuln_rows_html = ""
    if not vulnerabilities:
        vuln_rows_html = """
        <div class="no-issues">
            <h3>✅ No vulnerabilities found</h3>
            <p>Great job! Your code passed all security checks.</p>
        </div>
        """
    else:
        for vuln in vulnerabilities:
            # Color code severity
            severity_class = vuln.get('severity', 'low').lower()
            
            vuln_rows_html += f"""
            <div class="vuln-card {severity_class}">
                <div class="vuln-header">
                    <span class="severity-badge {severity_class}">{vuln.get('severity', 'UNKNOWN').upper()}</span>
                    <span class="vuln-type">{vuln.get('type', 'Unknown Issue')}</span>
                </div>
                <div class="vuln-body">
                    <p><strong>Description:</strong> {vuln.get('description', 'No description provided')}</p>
                    <p><strong>File:</strong> <code>{vuln.get('file', 'N/A')}</code> : Line {vuln.get('line', '?')}</p>
                    <div class="code-snippet">
                        <pre>{vuln.get('code', '')}</pre>
                    </div>
                    <p class="recommendation"><strong>Fix:</strong> {vuln.get('recommendation', 'Review manually')}</p>
                </div>
            </div>
            """

    # Complete HTML Template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f4f6f8; }}
        .header {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; border: 1px solid #e1e4e8; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #0366d6; }}
        .stat-label {{ color: #586069; font-size: 14px; }}
        
        .vuln-card {{ background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 15px; overflow: hidden; border-left: 5px solid #ccc; }}
        .vuln-card.high {{ border-left-color: #d73a49; }}
        .vuln-card.medium {{ border-left-color: #f9c513; }}
        .vuln-card.low {{ border-left-color: #2ea44f; }}
        
        .vuln-header {{ padding: 12px 20px; background: #f6f8fa; border-bottom: 1px solid #eaecef; display: flex; align-items: center; gap: 15px; }}
        .vuln-body {{ padding: 20px; }}
        
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: #fff; }}
        .severity-badge.high {{ background: #d73a49; }}
        .severity-badge.medium {{ background: #b08800; color: white; }}
        .severity-badge.low {{ background: #2ea44f; }}
        
        .code-snippet {{ background: #f6f8fa; padding: 10px; border-radius: 4px; overflow-x: auto; margin: 10px 0; border: 1px solid #eaecef; }}
        .recommendation {{ background: #eefcfd; padding: 10px; border-left: 4px solid #0366d6; margin-top: 15px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Code Review Report</h1>
        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary-grid">
            <div class="stat-card">
                <div class="stat-value">{total_issues}</div>
                <div class="stat-label">Issues Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_files}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{scan_duration:.2f}s</div>
                <div class="stat-label">Scan Duration</div>
            </div>
        </div>
    </div>

    <div class="results-container">
        {vuln_rows_html}
    </div>
</body>
</html>
    """

    # Write file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"✅ HTML Report generated: {output_path}")
    except Exception as e:
        print(f"❌ Failed to generate HTML report: {e}")

