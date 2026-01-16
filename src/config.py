"""
Configuration module for security code analyzer.
Centralizes all configuration values and settings.
"""

import os
from typing import List, Set
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Main configuration class for the security analyzer."""
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS: List[str] = [
        '.py',    # Python
        '.js',    # JavaScript
        '.jsx',   # React JavaScript
        '.ts',    # TypeScript
        '.tsx',   # React TypeScript
        '.java',  # Java
        '.c',     # C
        '.cpp',   # C++
        '.cc',    # C++
        '.cxx',   # C++
        '.php',   # PHP
        '.go',    # Go
        '.rb',    # Ruby
    ]
    
    # Directories to skip during scanning
    SKIP_DIRECTORIES: Set[str] = {
        'venv',
        'env',
        'ENV',
        'virtualenv',
        'node_modules',
        '.git',
        '.svn',
        '.hg',
        '__pycache__',
        '.pytest_cache',
        'build',
        'dist',
        'target',  # Maven/Gradle
        'out',
        '.cache',
        '.mypy_cache',
        '.tox',
        'htmlcov',
        'coverage',
    }
    
    # Language detection mapping
    EXTENSION_TO_LANGUAGE = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',  # TypeScript treated as JavaScript for pattern detection
        '.tsx': 'javascript',
        '.java': 'java',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.php': 'php',
        '.go': 'go',
        '.rb': 'ruby',
    }
    
    # ML Model configuration
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "models/vulnerability_classifier.pkl")
    USE_ML: bool = os.getenv("USE_ML", "true").lower() == "true"
    
    # Severity levels (in order of importance)
    SEVERITY_LEVELS: List[str] = [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]
    
    # Configuration file paths
    SEVERITY_CONFIG: str = os.getenv("SEVERITY_CONFIG", "configs/severity_rules.yaml")
    PATTERN_CONFIG: str = os.getenv("PATTERN_CONFIG", "configs/vulnerability_patterns.yaml")
    
    # Logging configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "")
    
    # Analysis options
    DEFAULT_MIN_SEVERITY: str = os.getenv("DEFAULT_MIN_SEVERITY", "low")
    GENERATE_HTML_DEFAULT: bool = os.getenv("GENERATE_HTML_DEFAULT", "true").lower() == "true"
    
    # Bandit configuration
    BANDIT_TIMEOUT: int = int(os.getenv("BANDIT_TIMEOUT", "30"))
    
    # Report output
    DEFAULT_REPORT_OUTPUT: str = "scan_results.json"
    REPORT_DIRECTORY: str = os.getenv("REPORT_DIRECTORY", "reports")
    
    @classmethod
    def get_supported_extensions(cls) -> List[str]:
        """Get list of supported file extensions."""
        custom_extensions = os.getenv("SUPPORTED_EXTENSIONS", "")
        if custom_extensions:
            return [ext.strip() for ext in custom_extensions.split(",")]
        return cls.SUPPORTED_EXTENSIONS
    
    @classmethod
    def get_skip_directories(cls) -> Set[str]:
        """Get set of directories to skip."""
        custom_skip = os.getenv("SKIP_DIRECTORIES", "")
        if custom_skip:
            return {dir.strip() for dir in custom_skip.split(",")}
        return cls.SKIP_DIRECTORIES
    
    @classmethod
    def detect_language(cls, file_extension: str) -> str:
        """
        Detect programming language from file extension.
        
        Args:
            file_extension: File extension (e.g., '.py')
            
        Returns:
            Language name or None if not supported
        """
        return cls.EXTENSION_TO_LANGUAGE.get(file_extension)


# Create a singleton instance
config = Config()
