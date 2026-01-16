from typing import Dict, List
from pathlib import Path
from ..detectors.pattern_detector import PatternBasedDetector, Vulnerability
from ..detectors.ast_analyzer import ASTSecurityAnalyzer
from ..detectors.ml_classifier import MLVulnerabilityClassifier
from ..config import config
from ..utils.logger import get_logger
import subprocess
import json

class SecurityCodeAnalyzer:
    """Integrated security analyzer using multiple detection methods"""
    
    def __init__(self, use_ml: bool = True, min_severity: str = "low"):
        self.logger = get_logger(__name__)
        self.logger.info("Initializing Security Code Analyzer...")
        
        # Store configuration
        self.min_severity = min_severity
        
        # Initialize detectors
        self.pattern_detector = PatternBasedDetector()
        self.ast_analyzer = ASTSecurityAnalyzer()
        
        # ML classifier (optional)
        self.ml_classifier = None
        if use_ml:
            self.ml_classifier = MLVulnerabilityClassifier()
            try:
                self.ml_classifier.load_model()
                self.logger.info("ML model loaded successfully")
            except Exception as e:
                self.logger.warning(f"Training new ML model: {str(e)}")
                training_data = self.ml_classifier.get_synthetic_training_data()
                self.ml_classifier.train(training_data)
                self.ml_classifier.save_model()
        
        self.logger.info("Analyzer initialized successfully")
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a single file comprehensively"""
        self.logger.info(f"Analyzing: {file_path}")
        
        path = Path(file_path)
        language = self._detect_language(path)
        
        if not language:
            error_msg = f"Unsupported file type: {path.suffix}"
            self.logger.error(error_msg)
            return {"error": error_msg}
        
        # Read code
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            error_msg = f"Could not read file: {str(e)}"
            self.logger.error(error_msg)
            return {"error": error_msg}
        
        # Run multiple detection methods
        results = {
            'file': str(file_path),
            'language': language,
            'vulnerabilities': []
        }
        
        # 1. Pattern-based detection
        self.logger.debug("Running pattern-based detection...")
        pattern_vulns = self.pattern_detector.detect_vulnerabilities(code, language)
        results['vulnerabilities'].extend([
            self._vulnerability_to_dict(v) for v in pattern_vulns
        ])
        
        # 2. AST analysis (Python only)
        if language == 'python':
            self.logger.debug("Running AST analysis...")
            ast_issues = self.ast_analyzer.analyze(code)
            results['vulnerabilities'].extend([
                {
                    'type': issue.type,
                    'severity': issue.severity,
                    'line': issue.line_number,
                    'description': issue.description,
                    'code_snippet': issue.context,
                    'detection_method': 'AST Analysis'
                }
                for issue in ast_issues
            ])
        
        # 3. Bandit (Python only)
        if language == 'python':
            self.logger.debug("Running Bandit scan...")
            bandit_results = self._run_bandit(file_path)
            results['vulnerabilities'].extend(bandit_results)
        
        # 4. ML classification (if trained)
        if self.ml_classifier and self.ml_classifier.is_trained:
            self.logger.debug("Running ML classification...")
            for vuln in results['vulnerabilities']:
                snippet = vuln.get('code_snippet', '')
                if snippet:
                    pred_type, confidence = self.ml_classifier.predict(snippet)
                    vuln['ml_prediction'] = pred_type
                    vuln['ml_confidence'] = float(confidence)
        
        # Summary
        total_vulns = len(results['vulnerabilities'])
        critical = sum(1 for v in results['vulnerabilities'] if v.get('severity') == 'Critical')
        high = sum(1 for v in results['vulnerabilities'] if v.get('severity') == 'High')
        
        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'critical': critical,
            'high': high,
            'medium': total_vulns - critical - high
        }
        
        self.logger.info(f"Found {total_vulns} potential vulnerabilities")
        
        return results
    
    def analyze_directory(
        self, 
        directory: str, 
        extensions: List[str] = None
    ) -> List[Dict]:
        """Analyze all files in a directory"""
        if extensions is None:
            extensions = config.get_supported_extensions()[:3]  # Default to first 3
        
        results = []
        path = Path(directory)
        
        files_to_scan = []
        for ext in extensions:
            files_to_scan.extend(path.rglob(f'*{ext}'))
        
        files_to_scan = [
            f for f in files_to_scan 
            if not self._should_skip(f)
        ]
        
        self.logger.info(f"Found {len(files_to_scan)} files to scan")
        
        for i, file_path in enumerate(files_to_scan, 1):
            self.logger.info(f"Scanning file {i}/{len(files_to_scan)}: {file_path.name}")
            result = self.analyze_file(str(file_path))
            results.append(result)
        
        return results
    
    def scan_file(self, file_path: str) -> Dict:
        """Alias for analyze_file for CLI compatibility"""
        return self.analyze_file(file_path)
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """Alias for analyze_directory for CLI compatibility"""
        return self.analyze_directory(directory, extensions)
    
    def _run_bandit(self, file_path: str) -> List[Dict]:
        """Run Bandit static analysis tool"""
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', file_path],
                capture_output=True,
                text=True,
                timeout=config.BANDIT_TIMEOUT
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                return [
                    {
                        'type': issue['test_id'],
                        'severity': issue['issue_severity'],
                        'line': issue['line_number'],
                        'description': issue['issue_text'],
                        'code_snippet': issue['code'],
                        'detection_method': 'Bandit'
                    }
                    for issue in data.get('results', [])
                ]
        except FileNotFoundError:
            self.logger.warning("Bandit not found - install with: pip install bandit")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Bandit scan timed out after {config.BANDIT_TIMEOUT}s")
        except Exception as e:
            self.logger.warning(f"Bandit scan failed: {str(e)}")
        
        return []
    
    def _detect_language(self, path: Path) -> str:
        """Detect programming language from file extension"""
        return config.detect_language(path.suffix)
    
    def _vulnerability_to_dict(self, vuln: Vulnerability) -> Dict:
        """Convert Vulnerability dataclass to dict"""
        return {
            'type': vuln.type,
            'severity': vuln.severity,
            'line': vuln.line,
            'description': vuln.description,
            'code_snippet': vuln.code_snippet,
            'exploit_scenario': vuln.exploit_scenario,
            'fix_recommendation': vuln.fix_recommendation,
            'cwe': vuln.cwe,
            'confidence': vuln.confidence,
            'detection_method': 'Pattern Matching'
        }
    
    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        skip_dirs = config.get_skip_directories()
        return any(part in skip_dirs for part in file_path.parts)
