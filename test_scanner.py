#!/usr/bin/env python3
"""
Quick functional test script for the security code analyzer
"""
import json
from pathlib import Path
from src.analyzers.security_analyzer import SecurityCodeAnalyzer
from src.reporters.html_reporter import generate_html_report

def test_file(file_path: str, output_name: str):
    """Test scanning a single file"""
    print(f"\n{'='*60}")
    print(f"Testing: {file_path}")
    print(f"{'='*60}")
    
    try:
        # Initialize analyzer
        analyzer = SecurityCodeAnalyzer(use_ml=True, min_severity="low")
        
        # Run scan
        result = analyzer.scan_file(file_path)
        
        # Print summary
        summary = result.get('summary', {})
        print(f"\nScan Results:")
        print(f"  File: {result.get('file', 'N/A')}")
        print(f"  Language: {result.get('language', 'N/A')}")
        print(f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"    Critical: {summary.get('critical', 0)}")
        print(f"    High: {summary.get('high', 0)}")
        print(f"    Medium: {summary.get('medium', 0)}")
        print(f"    Low: {summary.get('low', 0)}")
        
        # Show first few vulnerabilities
        vulns = result.get('vulnerabilities', [])
        if vulns:
            print(f"\nTop Vulnerabilities Found:")
            for i, vuln in enumerate(vulns[:5], 1):
                print(f"  {i}. {vuln.get('type', 'Unknown')} - Line {vuln.get('line', 'N/A')} - Severity: {vuln.get('severity', 'N/A')}")
        
        # Save JSON report
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        json_path = reports_dir / f"{output_name}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)
        print(f"\n✓ JSON report saved: {json_path}")
        
        # Generate HTML report
        html_path = reports_dir / f"{output_name}.html"
        generate_html_report([result], output_path=str(html_path))
        print(f"✓ HTML report saved: {html_path}")
        
        return result
        
    except Exception as e:
        print(f"✗ Error scanning {file_path}: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Run tests on example files"""
    print("="*60)
    print("AUTOMATED SECURITY CODE REVIEW - FUNCTIONAL TESTS")
    print("="*60)
    
    # Test files
    test_cases = [
        ("examples/vulnerable_code/sql_injection.py", "test_sql_injection"),
        ("examples/vulnerable_code/command_injection.py", "test_command_injection"),
        ("examples/vulnerable_code/xss_example.js", "test_xss"),
        ("examples/vulnerable_code/test.java", "test_java"),
        ("examples/vulnerable_code/test.cpp", "test_cpp"),
    ]
    
    results = []
    successes = 0
    failures = 0
    
    for file_path, output_name in test_cases:
        if Path(file_path).exists():
            result = test_file(file_path, output_name)
            if result:
                results.append(result)
                successes += 1
            else:
                failures += 1
        else:
            print(f"\n✗ File not found: {file_path}")
            failures += 1
    
    # Final summary
    print(f"\n{'='*60}")
    print("TESTING SUMMARY")
    print(f"{'='*60}")
    print(f"Total tests: {len(test_cases)}")
    print(f"Successes: {successes}")
    print(f"Failures: {failures}")
    
    total_vulns = sum(r.get('summary', {}).get('total_vulnerabilities', 0) for r in results)
    print(f"\nTotal vulnerabilities found across all files: {total_vulns}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
