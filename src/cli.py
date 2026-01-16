import typer
import json
import os
import sys
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from .analyzers.security_analyzer import SecurityCodeAnalyzer
from .reporters.html_reporter import generate_html_report
from .utils.logger import setup_logger
from .config import config

# Initialize Typer app and Rich console
app = typer.Typer(help="Automated Security Code Review CLI")
console = Console()

@app.command()
def scan(
    target_path: str = typer.Argument(..., help="Path to the source code file or directory to scan"),
    output: str = typer.Option(config.DEFAULT_REPORT_OUTPUT, "--output", "-o", help="Path to save the JSON output"),
    severity: str = typer.Option(config.DEFAULT_MIN_SEVERITY, "--severity", "-s", help="Minimum severity level (low, medium, high, critical)"),
    generate_html: bool = typer.Option(config.GENERATE_HTML_DEFAULT, "--html/--no-html", help="Generate an HTML report alongside the JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging")
):
    """
    Run a security scan on the specified source code.
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    logger = setup_logger("security_analyzer", level=log_level)
    
    target = Path(target_path)
    
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Path '{target_path}' does not exist.")
        logger.error(f"Path does not exist: {target_path}")
        raise typer.Exit(code=1)

    console.print(Panel.fit(f"Starting Security Scan on: [bold]{target}[/bold]", border_style="blue"))
    logger.info(f"Starting security scan on: {target}")

    try:
        # 1. Initialize Analyzer
        analyzer = SecurityCodeAnalyzer(use_ml=True, min_severity=severity)
        
        # 2. Run Analysis
        if target.is_dir():
            results = analyzer.scan_directory(str(target))
        else:
            results = [analyzer.scan_file(str(target))]
        
        # 3. Save JSON Report
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        
        console.print(f"[green]DONE: JSON report saved to:[/green] {output}")
        logger.info(f"JSON report saved to: {output}")

        # 4. Generate HTML Report
        if generate_html:
            html_path = str(Path(output).with_suffix('.html'))
            
            console.print("[yellow]Generating HTML report...[/yellow]")
            logger.info("Generating HTML report")
            generate_html_report(results, output_path=html_path)
            
            console.print(f"[bold green]SUCCESS: HTML report generated successfully:[/bold green] {html_path}")
            logger.info(f"HTML report saved to: {html_path}")
        
        # Summary
        total_files = len(results)
        total_vulns = sum(r.get('summary', {}).get('total_vulnerabilities', 0) for r in results)
        console.print(f"\n[bold]Scan Complete:[/bold] {total_files} file(s) scanned, {total_vulns} issue(s) found")
        logger.info(f"Scan complete: {total_files} files, {total_vulns} issues")

    except Exception as e:
        console.print(f"[bold red]ERROR: An error occurred during the scan:[/bold red] {e}")
        logger.exception("Scan failed with exception")
        raise typer.Exit(code=1)

def main():
    """Entry point for the CLI."""
    app()

if __name__ == "__main__":
    main()
