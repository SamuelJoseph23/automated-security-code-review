# Architecture Documentation

## Overview

The Automated Security Code Review tool employs a **multi-layered detection architecture** that combines different analysis techniques to identify security vulnerabilities in source code. This approach maximizes detection coverage while minimizing false positives.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interface Layer                      │
├──────────────────────────┬──────────────────────────────────┤
│     CLI (Typer/Rich)     │   Web Dashboard (Streamlit)      │
└──────────────────────────┴──────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 SecurityCodeAnalyzer                         │
│              (Main Orchestration Layer)                      │
└─────────────────────────────────────────────────────────────┘
                             ▼
┌──────────────┬──────────────┬──────────────┬────────────────┐
│   Pattern    │     AST      │   Bandit     │      ML        │
│   Detector   │   Analyzer   │   Scanner    │  Classifier    │
└──────────────┴──────────────┴──────────────┴────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Reporter Layer                            │
│              (JSON, HTML, Console)                           │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. SecurityCodeAnalyzer
**Location**: `src/analyzers/security_analyzer.py`

**Purpose**: Main orchestration component that coordinates all detection methods.

**Responsibilities**:
- File and directory scanning
- Language detection
- Coordinating multiple analyzers
- Result aggregation
- Summary generation

**Key Methods**:
- `analyze_file(file_path)`: Analyzes a single file
- `analyze_directory(directory, extensions)`: Scans all files in a directory
- `_run_bandit(file_path)`: Executes Bandit scan for Python files
- `_detect_language(path)`: Determines programming language from file extension

**Workflow**:
1. Read source file
2. Detect programming language
3. Run pattern-based detection
4. Run AST analysis (Python only)
5. Run Bandit scan (Python only)
6. Optionally run ML classification
7. Aggregate results and generate summary

---

### 2. Pattern-Based Detector
**Location**: `src/detectors/pattern_detector.py`

**Purpose**: Detect vulnerabilities using regex pattern matching.

**Detection Patterns**:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Hardcoded Secrets (API keys, passwords)
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- Insecure Deserialization
- Weak Cryptography

**Language Support**:
- Python
- JavaScript/TypeScript
- Java
- C/C++
- PHP
- Go
- Ruby

**Confidence Scoring**:
Patterns are scored based on:
- Specificity of the match
- Context of surrounding code
- Presence of dangerous function calls
- Hardcoded values

**Data Structure**:
```python
@dataclass
class Vulnerability:
    type: str                    # Vulnerability type
    severity: str                # Critical/High/Medium/Low
    line: int                    # Line number
    code_snippet: str            # Vulnerable code
    description: str             # Issue description
    exploit_scenario: str        # How it could be exploited
    fix_recommendation: str      # How to fix it
    cwe: str                     # CWE identifier
    confidence: float            # 0.0 to 1.0
```

---

### 3. AST Security Analyzer
**Location**: `src/detectors/ast_analyzer.py`

**Purpose**: Perform deep code analysis using Abstract Syntax Trees (Python only).

**Detection Capabilities**:
- Dangerous imports (os, subprocess, pickle, etc.)
- Hardcoded credentials in variable assignments
- Command injection via subprocess with shell=True
- Dangerous function calls (eval, exec, compile)
- SQL query construction patterns

**Advantages**:
- **Context-aware**: Understands code structure
- **Fewer false positives**: Can differentiate between safe and unsafe patterns
- **Detailed analysis**: Tracks data flow and variable usage

**Example Detection**:
```python
# Pattern detector might miss this:
cmd = user_input
os.system(cmd)  # AST detects this as command injection

# AST can trace:
password = "secret123"  # Hardcoded credential detected
api_key = os.getenv("KEY")  # Safe pattern, not flagged
```

---

### 4. ML Vulnerability Classifier
**Location**: `src/detectors/ml_classifier.py`

**Purpose**: Machine learning-based classification of code snippets for vulnerability prediction.

**Model**: 
- Algorithm: Random Forest Classifier
- Features: TF-IDF vectorization of code snippets
- Labels: Vulnerability types

**Training Data**:
- Synthetic training data generated from known vulnerable patterns
- Real-world examples from CVE databases

**Prediction Output**:
- Vulnerability type prediction
- Confidence score (0.0 to 1.0)

**Integration**:
- Runs after other detectors
- Provides ML-based confidence scoring for detected issues
- Can identify variants of known vulnerability patterns

---

### 5. Bandit Integration
**Location**: Integrated in `SecurityCodeAnalyzer._run_bandit()`

**Purpose**: Leverage the Bandit static analysis tool for Python security issues.

**Coverage**:
- Standard Python security anti-patterns
- CWE-mapped issues
- Official security best practices

**Process**:
1. Execute Bandit as subprocess
2. Parse JSON output
3. Convert to internal vulnerability format
4. Merge with other detection results

---

## Detection Flow

### Single File Analysis

```
┌─────────────────┐
│  Input: file    │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Detect Lang    │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Read Code      │
└────────┬────────┘
         ▼
    ┌────┴────┐
    ▼         ▼
┌─────┐   ┌─────┐
│ Pat │   │ AST │
│ tern│   │ Ana │
└──┬──┘   └──┬──┘
   │         │
   └────┬────┘
        ▼
   ┌─────────┐
   │ Bandit  │
   └────┬────┘
        ▼
   ┌─────────┐
   │   ML    │
   └────┬────┘
        ▼
   ┌─────────┐
   │ Merge   │
   │Results  │
   └────┬────┘
        ▼
   ┌─────────┐
   │Summary  │
   └─────────┘
```

### Directory Scanning

```
┌──────────────────┐
│  Input: dir      │
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Discover Files  │
│  (recursive)     │
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Filter Skip     │
│  Directories     │
└────────┬─────────┘
         ▼
┌──────────────────┐
│  For Each File:  │
│  - Analyze File  │
│  - Collect       │
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Aggregate       │
│  All Results     │
└──────────────────┘
```

**Skipped Directories**:
- `venv`, `env`, `ENV`
- `node_modules`
- `.git`
- `__pycache__`
- `build`, `dist`
- `.pytest_cache`

---

## Reporting Architecture

### Report Generators

**JSON Reporter** (`src/reporters/json_reporter.py`):
- Structured data format
- Machine-readable
- Used for CI/CD integration
- Includes all vulnerability details

**HTML Reporter** (`src/reporters/html_reporter.py`):
- Human-readable format
- Syntax highlighting
- Interactive elements
- Severity badges
- Fix recommendations

**Console Reporter** (`src/reporters/console_reporter.py`):
- Rich terminal output
- Color-coded severity levels
- Progress indicators
- Summary statistics

---

## Data Flow

### Input Processing
```
Source File → Language Detection → Code Reading → Encoding Handling
```

### Analysis Pipeline
```
Raw Code → Pattern Matching → AST Parsing → Bandit Scan → ML Prediction
```

### Output Generation
```
Vulnerabilities → Deduplication → Severity Ranking → Report Formatting
```

---

## Configuration

### Pattern Configuration
**File**: `configs/vulnerability_patterns.yaml`

Defines regex patterns for vulnerability detection across languages.

### Severity Rules
**File**: `configs/severity_rules.yaml`

Maps vulnerability types to severity levels and CWE identifiers.

---

## Extensibility

### Adding New Languages

1. Update `_detect_language()` method in `SecurityCodeAnalyzer`
2. Add patterns to `vulnerability_patterns.yaml`
3. Optionally add AST parser for the language

### Adding New Vulnerability Types

1. Define pattern in `PatternBasedDetector._load_vulnerability_patterns()`
2. Add to training data for ML classifier
3. Update severity rules configuration

### Adding New Detection Methods

1. Create detector in `src/detectors/`
2. Integrate in `SecurityCodeAnalyzer.analyze_file()`
3. Add result transformation logic

---

## Performance Considerations

- **Parallel Processing**: Directory scans can be parallelized (future enhancement)
- **Caching**: ML model is loaded once and reused
- **Incremental Analysis**: Only changed files need re-scanning (future enhancement)
- **Skip Patterns**: Efficiently skip irrelevant directories

---

## Security & Privacy

- **No External Calls**: All analysis runs locally
- **No Code Transmission**: Source code never leaves the machine
- **Configurable**: All settings can be controlled via environment variables

---

## Future Architecture Enhancements

- **Plugin System**: Allow third-party detectors
- **Distributed Scanning**: Support for large codebases
- **Real-time Analysis**: VS Code / IDE integration
- **API Gateway**: RESTful API for remote scanning
- **Database Backend**: Store historical scan results
- **Automated Remediation**: Suggest code fixes via LLM
