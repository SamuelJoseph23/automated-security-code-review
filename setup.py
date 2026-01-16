"""
Automated Security Code Review Tool
A multi-method security vulnerability scanner for source code
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read requirements
requirements = []
with open("requirements.txt", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        # Skip comments and empty lines
        if line and not line.startswith("#"):
            requirements.append(line)

setup(
    name="automated-security-code-review",
    version="1.0.0",
    author="Samuel Joseph",
    author_email="your.email@example.com",  # Update with your email
    description="Multi-method security vulnerability scanner using ML, AST analysis, and pattern detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SamuelJoseph23/automated-security-code-review",
    project_urls={
        "Bug Tracker": "https://github.com/SamuelJoseph23/automated-security-code-review/issues",
        "Documentation": "https://github.com/SamuelJoseph23/automated-security-code-review/tree/main/docs",
        "Source Code": "https://github.com/SamuelJoseph23/automated-security-code-review",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "docs"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.1",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-scan=src.cli:main",
            "security-dashboard=dashboard:main",
        ],
    },
    include_package_data=True,
    package_data={
        "src": [
            "configs/*.yaml",
            "configs/*.json",
        ],
    },
    keywords=[
        "security",
        "vulnerability",
        "scanner",
        "static-analysis",
        "code-review",
        "ml",
        "ast",
        "pattern-matching",
        "bandit",
    ],
    zip_safe=False,
)
