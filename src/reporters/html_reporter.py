import os
from datetime import datetime

def generate_html_report(results: list, output_file: str = "report.html"):
    """Generate a styled HTML report from scan results"""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate summary stats
    total_files = len(results)
    total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
    critical = sum(sum(1 for v in r.get('vulnerabilities', []) if v['severity'] == 'Critical') for r in results)
    high = sum(sum(1 for v in r.get('vulnerabilities', []) if v['severity'] == 'High') for r in results)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report</title>
        <style>
            :root {{
                --primary: #2c3e50;
                --secondary: #34495e;
                --accent: #3498db;
                --bg: #f5f6fa;
                --critical: #e74c3c;
                --high: #e67e22;
                --medium: #f1c40f;
                --low: #2ecc71;
            }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: var(--bg); color: #333; }}
            .header {{ background: var(--primary); color: white; padding: 2rem; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); text-align: center; }}
            .stat-number {{ font-size: 2.5rem; font-weight: bold; color: var(--primary); }}
            .stat-label {{ color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; font-size: 0.9rem; }}
            .vuln-card {{ background: white; margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
            .vuln-header {{ padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #eee; }}
            .severity-badge {{ padding: 5px 12px; border-radius: 15px; color: white; font-weight: bold; font-size: 0.9rem; }}
            .severity-Critical {{ background: var(--critical); }}
            .severity-High {{ background: var(--high); }}
            .severity-Medium {{ background: var(--medium); color: #333; }}
            .severity-Low {{ background: var(--low); }}
            .vuln-body {{ padding: 20px; }}
            .code-block {{ background: #282c34; color: #abb2bf; padding: 15px; border-radius: 5px; font-family: 'Consolas', monospace; overflow-x: auto; margin: 10px 0; }}
            .meta-info {{ display: flex; gap: 20px; color: #666; font-size: 0.9rem; margin-bottom: 10px; }}
            .fix-box {{ background: #e8f6f3; border-left: 4px solid #1abc9c; padding: 15px; margin-top: 15px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>🛡️ Security Scan Report</h1>
                <p>Generated on {timestamp}</p>
            </div>
        </div>

        <div class="container">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_files}</div>
                    <div class="stat-label">Files Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: var(--critical)">{critical}</div>
                    <div class="stat-label">Critical Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: var(--high)">{high}</div>
                    <div class="stat-label">High Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_vulns}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
            </div>

            {% for result in results %}
                {% if result.vulnerabilities %}
                <h2 style="margin-top: 40px; color: var(--secondary);">📄 {result.file}</h2>
                {% for vuln in result.vulnerabilities %}
                <div class="vuln-card">
                    <div class="vuln-header">
                        <h3>{vuln.type}</h3>
                        <span class="severity-badge severity-{vuln.severity}">{vuln.severity}</span>
                    </div>
                    <div class="vuln-body">
                        <div class="meta-info">
                            <span>📍 Line {vuln.line}</span>
                            <span>🔍 Detection: {vuln.detection_method}</span>
                            <span>🤖 Confidence: {vuln.confidence}</span>
                        </div>
                        <p>{vuln.description}</p>
                        
                        <div class="code-block">
                            {vuln.code_snippet}
                        </div>

                        <div class="fix-box">
                            <strong>💡 Recommendation:</strong><br>
                            {vuln.fix_recommendation}
                        </div>
                    </div>
                </div>
                {% endfor %}
                {% endif %}
            {% endfor %}
        </div>
    </body>
    </html>
    """
    
    # Simple template engine replacer to avoid Jinja2 dependency complexity for now
    # We reconstruct the string manually for the loop part since f-strings don't do loops
    
    report_body = ""
    for result in results:
        if not result.get('vulnerabilities'):
            continue
            
        report_body += f'<h2 style="margin-top: 40px; color: var(--secondary);">📄 {result["file"]}</h2>'
        
        for vuln in result['vulnerabilities']:
            sev_class = vuln['severity']
            report_body += f"""
            <div class="vuln-card">
                <div class="vuln-header">
                    <h3>{vuln['type']}</h3>
                    <span class="severity-badge severity-{sev_class}">{sev_class}</span>
                </div>
                <div class="vuln-body">
                    <div class="meta-info">
                        <span>📍 Line {vuln['line']}</span>
                        <span>🔍 {vuln.get('detection_method', 'Pattern')}</span>
                    </div>
                    <p>{vuln['description']}</p>
                    <div class="code-block">{vuln.get('code_snippet', '').replace('<', '&lt;')}</div>
                    <div class="fix-box">
                        <strong>💡 Recommendation:</strong><br>
                        {vuln.get('fix_recommendation', 'No specific fix provided')}
                    </div>
                </div>
            </div>
            """

    # Combine parts
    final_html = html_content.split('{% for result in results %}')[0] + report_body + html_content.split('{% endfor %}')[-1].replace('{% endfor %}', '').replace('{% endif %}', '')
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(final_html)
        
    print(f"   📄 HTML report generated: {output_file}")
