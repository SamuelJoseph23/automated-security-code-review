# Usage Guide

This guide provides detailed instructions for using the Automated Security Code Review tool.

## Table of Contents

- [Command Line Interface](#command-line-interface)
- [Web Dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Report Interpretation](#report-interpretation)
- [Advanced Usage](#advanced-usage)

---

## Command Line Interface

### Basic Usage

**Scan a single file:**
```bash
python main.py scan path/to/file.py
```

**Scan with default options:**
- Creates `scan_results.json` in the current directory
- Generates HTML report automatically
- Uses minimum severity: "low" (shows all findings)
- Enables ML classifier if trained

### Command Options

```bash
python main.py scan TARGET [OPTIONS]
```

**Arguments:**
- `TARGET`: Path to file or directory to scan (required)

**Options:**
- `--output, -o TEXT`: Output file path (default: `scan_results.json`)
- `--severity, -s [low|medium|high|critical]`: Minimum severity to report (default: `low`)
- `--html / --no-html`: Generate HTML report (default: enabled)

### Examples

#### Example 1: Scan with Custom Output
```bash
python main.py scan src/app.py --output reports/app_scan.json
```

**Output:**
- `reports/app_scan.json` - JSON report
- `reports/app_scan.html` - HTML report

#### Example 2: Filter High Severity Issues
```bash
python main.py scan myproject/ --severity high
```

Shows only High and Critical severity vulnerabilities.

#### Example 3: JSON Only (No HTML)
```bash
python main.py scan code.py --no-html --output results.json
```

Generates only JSON output, skips HTML report generation.

#### Example 4: Scan Directory
```bash
python main.py scan src/ --output project_scan.json
```

**Behavior:**
- Recursively scans all supported files in `src/`
- Skips: `venv/`, `node_modules/`, `.git/`, `__pycache__/`, `build/`, `dist/`
- Default extensions: `.py`, `.js`, `.java`

---

## Web Dashboard

### Launching the Dashboard

```bash
streamlit run dashboard.py
```

The browser will automatically open to http://localhost:8501

### Dashboard Features

#### 1. **File Upload**
- Supports: `.py`, `.js`, `.java`, `.c`, `.cpp`
- Max file size: Default Streamlit limit (200MB)
- Drag-and-drop or browse

#### 2. **Configuration Sidebar**
- **Use ML Classifier**: Toggle ML-based predictions on/off
- **Filter Severity**: Select which severity levels to display
  - Critical
  - High
  - Medium
  - Low

#### 3. **Metrics Overview**
Four key metrics displayed at the top:
- **Total Issues**: Total vulnerabilities found
- **Critical**: Count of critical severity issues
- **High**: Count of high severity issues
- **Medium**: Count of medium severity issues

#### 4. **Visualizations**

**Pie Chart - Issues by Severity:**
- Color-coded by severity
- Interactive (hover for details)
- Shows distribution percentages

**Bar Chart - Issues by Type:**
- Shows counts per vulnerability type
- Helps identify most common issues

#### 5. **Detailed Findings Table**

Columns:
- **Type**: Vulnerability type (e.g., SQL Injection)
- **Severity**: Critical/High/Medium/Low
- **Line**: Line number in source file
- **Description**: What was detected
- **Fix Recommendation**: How to remediate

**Features:**
- Sortable columns
- Filterable by severity
- Full-width display

#### 6. **Code Inspector**
- Syntax-highlighted source code
- Shows entire uploaded file
- Language-specific highlighting

### Dashboard Workflow

1. **Upload file** via drag-and-drop or file picker
2. **Wait for scan** (progress spinner shows during analysis)
3. **Review metrics** at the top
4. **Analyze charts** for vulnerability distribution
5. **Inspect findings** in the detailed table
6. **Review code** with line numbers for context

### Troubleshooting Dashboard

**Issue**: "Analysis Failed" error
- **Cause**: Unsupported file extension
- **Solution**: Ensure file has `.py`, `.js`, `.java`, `.c`, or `.cpp` extension

**Issue**: No vulnerabilities displayed
- **Cause**: All issues filtered out by severity filter
- **Solution**: Adjust severity filter in sidebar to include more levels

**Issue**: Temp file not cleaned up
- **Cause**: Browser closed during scan
- **Solution**: Manually delete `temp_scan_file*` from project root

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the template
cp .env.example .env
```

**Available Variables:**

```bash
# Logging
LOG_LEVEL=INFO          # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE=logs/scan.log  # Path to log file

# ML Configuration
ML_MODEL_PATH=models/vulnerability_classifier.pkl
USE_ML=true             # Enable/disable ML classifier

# Custom Configuration Paths
SEVERITY_CONFIG=configs/severity_rules.yaml
PATTERN_CONFIG=configs/vulnerability_patterns.yaml

# Analysis Options
SKIP_DIRECTORIES=venv,node_modules,.git,__pycache__
SUPPORTED_EXTENSIONS=.py,.js,.java,.c,.cpp
```

### Custom Vulnerability Patterns

Edit `configs/vulnerability_patterns.yaml`:

```yaml
custom_sql_injection:
  pattern: "execute\\(.*\\+.*\\)"
  severity: Critical
  description: "SQL injection via string concatenation"
  cwe: "CWE-89"
  languages:
    - python
    - java
```

### Custom Severity Rules

Edit `configs/severity_rules.yaml`:

```yaml
SQL Injection:
  severity: Critical
  cwe: CWE-89
  description: "SQL injection vulnerability"

Hardcoded Password:
  severity: High
  cwe: CWE-798
  description: "Hardcoded credentials detected"
```

---

## Report Interpretation

### JSON Report Structure

```json
{
  "file": "path/to/file.py",
  "language": "python",
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "Critical",
      "line": 42,
      "description": "SQL injection detected via string formatting",
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
      "exploit_scenario": "Attacker can inject: 1 OR 1=1",
      "fix_recommendation": "Use parameterized queries",
      "cwe": "CWE-89",
      "confidence": 0.85,
      "detection_method": "Pattern Matching",
      "ml_prediction": "SQL Injection",
      "ml_confidence": 0.92
    }
  ],
  "summary": {
    "total_vulnerabilities": 5,
    "critical": 2,
    "high": 1,
    "medium": 2
  }
}
```

### Understanding Fields

- **type**: Category of vulnerability
- **severity**: Risk level (Critical > High > Medium > Low)
- **line**: Line number in source file
- **description**: What was detected
- **code_snippet**: The vulnerable code
- **exploit_scenario**: How an attacker could exploit this
- **fix_recommendation**: How to remediate the issue
- **cwe**: Common Weakness Enumeration reference
- **confidence**: Detection confidence (0.0 to 1.0)
- **detection_method**: Which analyzer found it (Pattern Matching, AST Analysis, Bandit)
- **ml_prediction**: ML model's classification (optional)
- **ml_confidence**: ML model's confidence (optional)

### Severity Levels

| Level    | Description | Action Required |
|----------|-------------|----------------|
| **Critical** | Exploitable vulnerability with severe impact | Fix immediately |
| **High** | Serious security issue requiring urgent attention | Fix in next release |
| **Medium** | Security weakness that should be addressed | Schedule for fix |
| **Low** | Minor issue or code smell | Consider fixing |

### Common Vulnerability Types

**SQL Injection (CWE-89)**
- Using string concatenation in SQL queries
- Failure to use parameterized queries

**XSS - Cross-Site Scripting (CWE-79)**
- Rendering user input without escaping
- Using dangerous functions like `eval()` on user data

**Command Injection (CWE-78)**
- Using `os.system()` with user input
- `subprocess` with `shell=True` and untrusted data

**Path Traversal (CWE-22)**
- Building file paths from user input
- Not validating file access permissions

**Hardcoded Secrets (CWE-798)**
- API keys, passwords, tokens in source code
- Should use environment variables or secret management

---

## Advanced Usage

### Batch Scanning

**Scan multiple projects:**
```bash
#!/bin/bash
for project in projects/*; do
    python main.py scan "$project" --output "reports/$(basename $project).json"
done
```

### CI/CD Integration

**GitHub Actions Example:**
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -e .
      
      - name: Run security scan
        run: |
          python main.py scan src/ --severity high --output security_report.json
      
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security_report.json
      
      - name: Fail on critical issues
        run: |
          critical=$(jq '[.[] | .summary.critical] | add' security_report.json)
          if [ "$critical" -gt 0 ]; then
            echo "Found $critical critical vulnerabilities!"
            exit 1
          fi
```

### Programmatic Usage

```python
from src.analyzers.security_analyzer import SecurityCodeAnalyzer

# Initialize analyzer
analyzer = SecurityCodeAnalyzer(use_ml=True)

# Analyze single file
results = analyzer.analyze_file("path/to/code.py")

# Analyze directory
results = analyzer.analyze_directory("src/", extensions=['.py', '.js'])

# Access results
for file_result in results:
    print(f"File: {file_result['file']}")
    print(f"Total issues: {file_result['summary']['total_vulnerabilities']}")
    
    for vuln in file_result['vulnerabilities']:
        if vuln['severity'] == 'Critical':
            print(f"  Line {vuln['line']}: {vuln['type']}")
```

### Custom Reporter

```python
from src.analyzers.security_analyzer import SecurityCodeAnalyzer
import json

class CustomReporter:
    def __init__(self, results):
        self.results = results
    
    def generate_csv(self, output_path):
        import csv
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['File', 'Line', 'Type', 'Severity', 'Description'])
            
            for file_result in self.results:
                for vuln in file_result['vulnerabilities']:
                    writer.writerow([
                        file_result['file'],
                        vuln['line'],
                        vuln['type'],
                        vuln['severity'],
                        vuln['description']
                    ])

# Usage
analyzer = SecurityCodeAnalyzer()
results = analyzer.analyze_directory("src/")
reporter = CustomReporter(results)
reporter.generate_csv("vulnerabilities.csv")
```

---

## Best Practices

1. **Regular Scans**: Run security scans before every commit or as part of CI/CD
2. **Fix Critical First**: Prioritize critical and high severity issues
3. **Verify Findings**: Not all detections are true positives - review each finding
4. **Use ML Confidence**: Higher ML confidence scores indicate more likely true positives
5. **Keep Patterns Updated**: Regularly update vulnerability patterns
6. **Train ML Model**: Retrain with your codebase-specific examples for better accuracy
7. **Combine with Manual Review**: Automated scanning complements but doesn't replace manual security review

---

## Troubleshooting

### Common Issues

**Issue**: "Bandit not found"
```bash
pip install bandit
```

**Issue**: "Tree-sitter language not installed"
```bash
pip install tree-sitter-python tree-sitter-javascript
```

**Issue**: "ML model fails to load"
- Delete existing model: `rm models/vulnerability_classifier.pkl`
- Restart scan - new model will be trained

**Issue**: "Encoding errors when reading file"
- Files are read with UTF-8 encoding
- Use `errors='replace'` option or convert file encoding

---

## Getting Help

- **Documentation**: Check [docs/](../docs/) directory
- **Issues**: Report bugs on [GitHub Issues](https://github.com/SamuelJoseph23/automated-security-code-review/issues)
- **Contributing**: See [CONTRIBUTING.md](contributing.md)
