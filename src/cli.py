import typer
import json
import os
import sys
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Import your analyzer and reporter
# Ensure these match your actual file structure
from .analyzers.security_analyzer import SecurityCodeAnalyzer
from .reporters.html_reporter import generate_html_report

# Initialize Typer app and Rich console
app = typer.Typer(help="Automated Security Code Review CLI")
console = Console()

@app.command()
def scan(
    target_path: str = typer.Argument(..., help="Path to the source code file or directory to scan"),
    output: str = typer.Option("scan_results.json", "--output", "-o", help="Path to save the JSON output"),
    severity: str = typer.Option("low", "--severity", "-s", help="Minimum severity level (low, medium, high)"),
    generate_html: bool = typer.Option(True, "--html/--no-html", help="Generate an HTML report alongside the JSON")
):
    """
    Run a security scan on the specified source code.
    """
    target = Path(target_path)
    
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Path '{target_path}' does not exist.")
        raise typer.Exit(code=1)

    console.print(Panel.fit(f"🚀 Starting Security Scan on: [bold]{target}[/bold]", border_style="blue"))

    try:
        # 1. Initialize Analyzer
        # Pass the severity level string directly if your analyzer expects a string
        analyzer = SecurityCodeAnalyzer(min_severity=severity)
        
        # 2. Run Analysis
        # The analyzer should handle directory walking if target is a dir
        results = analyzer.scan_directory(str(target)) if target.is_dir() else analyzer.scan_file(str(target))
        
        # 3. Save JSON Report
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        
        console.print(f"[green]✔ JSON report saved to:[/green] {output}")

        # 4. Generate HTML Report
        if generate_html:
            # Determine HTML filename
            html_path = str(Path(output).with_suffix('.html'))
            
            console.print("[yellow]⚡ Generating HTML report...[/yellow]")
            generate_html_report(results, output_path=html_path)
            
            console.print(f"[bold green]✔ HTML report generated successfully:[/bold green] {html_path}")

    except Exception as e:
        console.print(f"[bold red]❌ An error occurred during the scan:[/bold red] {e}")
        # Only uncomment for deep debugging:
        # import traceback
        # traceback.print_exc()
        raise typer.Exit(code=1)

def main():
    """Entry point for the CLI."""
    app()

if __name__ == "__main__":
    main()
