# Contributing to Automated Security Code Review

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Adding New Features](#adding-new-features)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and constructive
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards other community members

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of security concepts
- Familiarity with Python programming

### Finding Issues to Work On

1. Check the [Issues page](https://github.com/SamuelJoseph23/automated-security-code-review/issues)
2. Look for issues labeled `good first issue` or `help wanted`
3. Comment on an issue to express interest before starting work
4. Wait for maintainer approval to avoid duplicate efforts

---

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/automated-security-code-review.git
cd automated-security-code-review

# Add upstream remote
git remote add upstream https://github.com/SamuelJoseph23/automated-security-code-review.git
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
# Install project dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install
```

### 4. Verify Setup

```bash
# Run tests to ensure everything works
pytest

# Try running the CLI
python main.py scan examples/vulnerable_code/sql_injection.py

# Try the dashboard
streamlit run dashboard.py
```

---

## Making Changes

### Branch Naming Convention

Create a descriptive branch name:

```bash
# Feature branches
git checkout -b feature/add-rust-support
git checkout -b feature/improve-ml-accuracy

# Bug fix branches
git checkout -b fix/dashboard-crash
git checkout -b fix/unicode-error

# Documentation branches
git checkout -b docs/update-readme
git checkout -b docs/add-api-examples
```

### Commit Message Guidelines

Use clear, descriptive commit messages:

```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```bash
feat: add support for Rust language detection

fix: resolve unicode encoding error in dashboard
- Handle files with non-UTF-8 encoding
- Add error message for encoding issues
- Closes #123

docs: update installation instructions
```

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_analyzers/test_security_analyzer.py

# Run specific test
pytest tests/test_analyzers/test_security_analyzer.py::test_analyze_file
```

### Writing Tests

Create tests for new functionality:

```python
# tests/test_detectors/test_new_feature.py
import pytest
from src.detectors.pattern_detector import PatternBasedDetector

def test_new_vulnerability_detection():
    """Test detection of new vulnerability type"""
    detector = PatternBasedDetector()
    code = "vulnerable_code_here()"
    
    vulns = detector.detect_vulnerabilities(code, "python")
    
    assert len(vulns) > 0
    assert vulns[0].type == "Expected Type"
    assert vulns[0].severity == "Critical"
```

### Test Coverage Requirements

- New features must include tests
- Aim for >80% code coverage
- Test both success and failure cases
- Include edge cases

---

## Submitting Changes

### Pull Request Process

1. **Update Your Branch**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request**
   - Go to GitHub and create a PR from your fork
   - Fill out the PR template completely
   - Reference any related issues

4. **Address Review Comments**
   - Respond to all reviewer comments
   - Make requested changes
   - Push updates to the same branch

### Pull Request Template

```markdown
## Description
Brief description of what this PR does

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Related Issues
Closes #123

## Testing
- [ ] All tests pass
- [ ] Added new tests for this feature
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings introduced
```

---

## Coding Standards

### Python Style Guide

Follow [PEP 8](https://pep8.org/) with these specifics:

- **Line Length**: Max 100 characters
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Double quotes for strings
- **Imports**: Organized in standard order

```python
# Standard library
import os
import sys
from typing import Dict, List

# Third-party
import numpy as np
from rich.console import Console

# Local imports
from src.analyzers.security_analyzer import SecurityCodeAnalyzer
```

### Type Hints

Use type hints for function signatures:

```python
def analyze_file(self, file_path: str) -> Dict[str, Any]:
    """
    Analyze a single file for vulnerabilities.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def complex_function(param1: str, param2: int) -> bool:
    """
    Brief description of function.
    
    Longer description if needed, explaining the function's
    behavior and any important details.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When param2 is negative
        
    Example:
        >>> complex_function("test", 42)
        True
    """
    pass
```

### Code Formatting

Use the following tools:

```bash
# Format code
black src/

# Check style
flake8 src/

# Type checking
mypy src/

# Sort imports
isort src/
```

---

## Adding New Features

### Adding a New Language

1. **Update Language Detection**
   ```python
   # src/analyzers/security_analyzer.py
   def _detect_language(self, path: Path) -> str:
       extension_map = {
           # ... existing languages
           '.rs': 'rust',  # Add new language
       }
       return extension_map.get(path.suffix, None)
   ```

2. **Add Vulnerability Patterns**
   ```python
   # src/detectors/pattern_detector.py
   'rust': {
       'sql_injection': {
           'pattern': r'execute\s*\(',
           'severity': 'Critical',
           # ...
       }
   }
   ```

3. **Update Tests**
   ```python
   # tests/test_analyzers/test_security_analyzer.py
   def test_rust_detection():
       analyzer = SecurityCodeAnalyzer()
       result = analyzer.analyze_file("test.rs")
       assert result['language'] == 'rust'
   ```

4. **Update Documentation**
   - Add to README language list
   - Update architecture documentation

### Adding a New Vulnerability Type

1. **Define Pattern**
   ```python
   # In PatternBasedDetector._load_vulnerability_patterns()
   'new_vulnerability': {
       'pattern': r'dangerous_pattern',
       'severity': 'High',
       'description': 'Description of the vulnerability',
   }
   ```

2. **Add Test Cases**
   ```python
   def test_new_vulnerability_detection():
       detector = PatternBasedDetector()
       code = "sample_vulnerable_code()"
       vulns = detector.detect_vulnerabilities(code, "python")
       # Assert detection
   ```

3. **Update ML Training Data**
   ```python
   # src/detectors/ml_classifier.py
   # Add examples to synthetic_data
   ```

### Adding a New Detector

1. **Create Detector Class**
   ```python
   # src/detectors/new_detector.py
   class NewDetector:
       def detect(self, code: str, language: str) -> List[Vulnerability]:
           """Detect vulnerabilities using new method"""
           pass
   ```

2. **Integrate in Analyzer**
   ```python
   # src/analyzers/security_analyzer.py
   def __init__(self):
       self.new_detector = NewDetector()
       
   def analyze_file(self, file_path: str):
       # ... existing code
       new_vulns = self.new_detector.detect(code, language)
       results['vulnerabilities'].extend(new_vulns)
   ```

---

## Documentation

### Updating Documentation

When adding features, update:

- `README.md`: High-level overview and examples
- `docs/architecture.md`: Technical architecture details
- `docs/usage.md`: User-facing instructions
- Code comments and docstrings

### Documentation Standards

- Use clear, concise language
- Include code examples
- Add screenshots for UI changes
- Keep documentation in sync with code

---

## Review Process

### What Reviewers Look For

- **Correctness**: Does the code work as intended?
- **Tests**: Are there adequate tests?
- **Style**: Does it follow coding standards?
- **Documentation**: Is it well-documented?
- **Security**: Does it introduce security issues?
- **Performance**: Are there performance concerns?

### Getting Your PR Merged

- Respond promptly to review comments
- Be open to suggestions
- Make requested changes
- Keep PR scope focused
- Ensure CI/CD checks pass

---

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions
- **Discussions**: General questions and ideas

### Recognition

Contributors are recognized in:
- Git commit history
- Release notes
- Contributors section (if added)

---

## Questions?

If you have questions:

1. Check existing documentation
2. Search closed issues
3. Open a new issue with the `question` label
4. Be specific and provide context

---

Thank you for contributing to Automated Security Code Review! 🛡️
