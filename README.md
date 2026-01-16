# 🛡️ Automated Security Code Review

An intelligent security code analysis tool that combines **pattern-based detection**, **AST analysis**, **machine learning**, and **static analysis** (Bandit) to identify vulnerabilities in your source code.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Features

- **Multi-Language Support**: Analyze Python, JavaScript, Java, C/C++, PHP, and more
- **Multiple Detection Methods**:
  - 🔍 Pattern-based vulnerability detection using regex patterns
  - 🌳 Abstract Syntax Tree (AST) analysis for Python code
  - 🤖 Machine Learning classifier for vulnerability prediction
  - 🛡️ Bandit integration for Python security scanning
- **Rich CLI Interface**: Beautiful terminal output with progress indicators
- **Interactive Dashboard**: Streamlit-based web interface for visual analysis
- **Comprehensive Reports**: JSON and HTML report generation
- **Severity Classification**: Critical, High, Medium, and Low severity ratings
- **CWE Mappings**: Common Weakness Enumeration references for identified issues

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/SamuelJoseph23/automated-security-code-review.git
cd automated-security-code-review

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Install Bandit (Optional but Recommended)

```bash
pip install bandit
```

## 🚀 Quick Start

### Command Line Interface

**Scan a single file:**
```bash
python main.py scan path/to/your/code.py
```

**Scan with custom output:**
```bash
python main.py scan path/to/code.py --output results.json
```

**Scan entire directory:**
```bash
python main.py scan path/to/project/ --output project_scan.json
```

**Filter by severity:**
```bash
python main.py scan code.py --severity high
```

**Skip HTML report generation:**
```bash
python main.py scan code.py --no-html
```

### Web Dashboard

Launch the interactive web interface:

```bash
streamlit run dashboard.py
```

Then:
1. Open your browser to the URL shown (typically http://localhost:8501)
2. Upload a source code file (.py, .js, .java, .c, .cpp)
3. View vulnerability distribution charts
4. Inspect detailed findings in the data table
5. Review highlighted code with line numbers

## 📖 Usage Examples

### Example 1: Scan Python File

```bash
python main.py scan examples/vulnerable_code/sql_injection.py
```

This will detect:
- SQL injection vulnerabilities
- Hardcoded credentials
- Command injection risks
- Dangerous function calls (eval, exec)

### Example 2: Batch Scanning

```bash
# Scan all Python files in a directory
python main.py scan src/ --severity medium

# The tool automatically skips:
# - venv, node_modules, .git directories
# - __pycache__, build, dist folders
```

### Example 3: Custom Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configurations
# Then run scans with custom settings
python main.py scan myproject/
```

## 🏗️ Architecture

The tool uses a multi-layered approach to security analysis:

```
┌─────────────────────────────────────────┐
│         Security Code Analyzer          │
└─────────────────────────────────────────┘
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
┌──────────┐ ┌─────────┐ ┌──────────┐
│ Pattern  │ │   AST   │ │  Bandit  │
│ Detector │ │Analyzer │ │ Scanner  │
└──────────┘ └─────────┘ └──────────┘
        │         │         │
        └─────────┼─────────┘
                  ▼
        ┌──────────────────┐
        │  ML Classifier   │
        │  (Optional)      │
        └──────────────────┘
                  │
                  ▼
        ┌──────────────────┐
        │  Report          │
        │  Generator       │
        └──────────────────┘
```

For detailed architecture documentation, see [docs/architecture.md](docs/architecture.md).

## 🎯 Supported Vulnerability Types

- **SQL Injection** (CWE-89)
- **Cross-Site Scripting (XSS)** (CWE-79)
- **Command Injection** (CWE-78)
- **Path Traversal** (CWE-22)
- **Hardcoded Secrets** (CWE-798)
- **Insecure Deserialization** (CWE-502)
- **XML External Entity (XXE)** (CWE-611)
- **Server-Side Request Forgery (SSRF)** (CWE-918)
- **Dangerous Function Usage** (eval, exec, os.system)
- **Weak Cryptography** (MD5, SHA1)
- And many more...

## 📊 Report Formats

### JSON Report
```json
{
  "file": "example.py",
  "language": "python",
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "Critical",
      "line": 42,
      "description": "SQL injection detected",
      "code_snippet": "cursor.execute(query)",
      "cwe": "CWE-89",
      "confidence": 0.85
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

### HTML Report
Interactive HTML reports with:
- Syntax-highlighted code snippets
- Clickable line numbers
- Severity badges
- Fix recommendations
- CWE references

## ⚙️ Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```bash
# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/security_scan.log

# ML Model
ML_MODEL_PATH=models/vulnerability_classifier.pkl

# Custom Rules
SEVERITY_CONFIG=configs/severity_rules.yaml
```

### Custom Patterns

Edit `configs/vulnerability_patterns.yaml` to add custom detection patterns:

```yaml
custom_pattern:
  pattern: "dangerous_function\\(.*\\)"
  severity: High
  description: "Dangerous function detected"
  cwe: "CWE-XXX"
```

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_analyzers/test_security_analyzer.py
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](docs/contributing.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Bandit](https://github.com/PyCQA/bandit) - Python security linter
- [tree-sitter](https://tree-sitter.github.io/) - Multi-language parsing
- [Streamlit](https://streamlit.io/) - Dashboard framework
- OWASP and CWE for vulnerability classifications

## 📧 Contact

Samuel Joseph - [@SamuelJoseph23](https://github.com/SamuelJoseph23)

Project Link: [https://github.com/SamuelJoseph23/automated-security-code-review](https://github.com/SamuelJoseph23/automated-security-code-review)

## 🗺️ Roadmap

- [ ] Add support for more languages (Ruby, Go, Rust)
- [ ] API endpoint for CI/CD integration
- [ ] GitHub Actions integration
- [ ] VS Code extension
- [ ] Real-time code scanning
- [ ] Automated fix suggestions
- [ ] Integration with SIEM tools

---

**⚠️ Disclaimer**: This tool is designed to assist in identifying potential security vulnerabilities. It should not be the only security measure employed. Always conduct thorough manual security reviews and testing.
