import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
from .analyzers.security_analyzer import SecurityCodeAnalyzer
from .reporters.html_reporter import generate_html_report
import json

console = Console()

def scan(path: str, output: str = "report.json", severity: str = "medium", use_ml: bool = True):
    """Scan code for security vulnerabilities"""
    
    console.print("╔════════════════════════════════════════════╗", style="bold blue")
    console.print("║  Classical ML Security Code Analyzer      ║", style="bold blue")
    console.print("║  Pattern + AST + ML Detection             ║", style="bold blue")
    console.print("╚════════════════════════════════════════════╝", style="bold blue")
    
    console.print(f"\n🎯 Target: {path}", style="cyan")
    console.print(f"🤖 ML Enabled: {use_ml}\n", style="cyan")
    
    try:
        analyzer = SecurityCodeAnalyzer(use_ml=use_ml)
    except Exception as e:
        console.print(f"\n❌ Error initializing analyzer: {str(e)}", style="bold red")
        return
    
    path_obj = Path(path)
    
    if not path_obj.exists():
        console.print(f"\n❌ Error: Path '{path}' does not exist", style="bold red")
        return
    
    if path_obj.is_file():
        results = [analyzer.analyze_file(str(path_obj))]
    else:
        results = analyzer.analyze_directory(str(path_obj))
    
    display_results(results, severity)
    save_results(results, output)

def display_results(results: list, min_severity: str):
    """Display results in formatted table"""
    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    min_level = severity_order.get(min_severity.lower(), 2)
    
    table = Table(title="Security Vulnerabilities Found")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Line", style="yellow")
    table.add_column("Method", style="green")
    table.add_column("Confidence", style="blue")
    
    total_vulns = 0
    
    for result in results:
        if 'vulnerabilities' not in result:
            continue
        
        for vuln in result['vulnerabilities']:
            severity = vuln.get('severity', 'low').lower()
            
            if severity_order.get(severity, 1) >= min_level:
                confidence = vuln.get('confidence', vuln.get('ml_confidence', 0.5))
                
                table.add_row(
                    Path(result.get('file', 'N/A')).name,
                    vuln.get('type', 'Unknown')[:30],
                    vuln.get('severity', 'Unknown'),
                    str(vuln.get('line', 'N/A')),
                    vuln.get('detection_method', 'Unknown')[:15],
                    f"{confidence:.2f}"
                )
                total_vulns += 1
    
    console.print(table)
    console.print(f"\n🎯 Total vulnerabilities found: {total_vulns}")
    
    if total_vulns == 0:
        console.print("✨ No vulnerabilities detected!", style="bold green")

def save_results(results: list, output_path: str):
    """Save results to JSON and HTML files"""
    try:
        # Save JSON Report
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save HTML Report
        if output_path.endswith('.json'):
            html_path = output_path.replace('.json', '.html')
        else:
            html_path = output_path + '.html'
            
        generate_html_report(results, html_path)
        
        console.print(f"\n✅ Reports saved:", style="bold green")
        console.print(f"   📄 JSON: {output_path}")
        console.print(f"   🌐 HTML: {html_path}")
        
    except Exception as e:
        console.print(f"\n⚠️  Warning: Could not save report: {str(e)}", style="yellow")

def main():
    console.print("\n╔════════════════════════════════════════════╗", style="bold cyan")
    console.print("║  Security Code Analyzer - Interactive    ║", style="bold cyan")
    console.print("╚════════════════════════════════════════════╝\n", style="bold cyan")
    
    # Get path from user
    path = input("📁 Enter path to file or directory to scan: ").strip()
    
    if not path:
        console.print("❌ No path provided!", style="bold red")
        return
    
    # Ask for optional parameters
    use_ml_input = input("🤖 Use ML classifier? (Y/n): ").strip().lower()
    use_ml = use_ml_input != 'n'
    
    severity_input = input("⚠️  Minimum severity level (low/medium/high/critical) [medium]: ").strip().lower()
    severity = severity_input if severity_input in ['low', 'medium', 'high', 'critical'] else 'medium'
    
    output_input = input("💾 Output file name [report.json]: ").strip()
    output = output_input if output_input else 'report.json'
    
    console.print("\n" + "="*50 + "\n")
    
    # Run scan
    scan(path, output, severity, use_ml)

if __name__ == "__main__":
    main()
