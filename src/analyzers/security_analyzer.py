from typing import Dict, List
from pathlib import Path
from ..detectors.pattern_detector import PatternBasedDetector, Vulnerability
from ..detectors.ast_analyzer import ASTSecurityAnalyzer
from ..detectors.ml_classifier import MLVulnerabilityClassifier
import subprocess
import json

class SecurityCodeAnalyzer:
    """Integrated security analyzer using multiple detection methods"""
    
    def __init__(self, use_ml: bool = True):
        print("🔧 Initializing Security Code Analyzer...")
        
        # Initialize detectors
        self.pattern_detector = PatternBasedDetector()
        self.ast_analyzer = ASTSecurityAnalyzer()
        
        # ML classifier (optional)
        self.ml_classifier = None
        if use_ml:
            self.ml_classifier = MLVulnerabilityClassifier()
            try:
                self.ml_classifier.load_model()
            except:
                print("⚠️  Training new ML model...")
                training_data = self.ml_classifier.get_synthetic_training_data()
                self.ml_classifier.train(training_data)
                self.ml_classifier.save_model()
        
        print("✅ Analyzer initialized successfully")
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a single file comprehensively"""
        print(f"\n📝 Analyzing: {file_path}")
        
        path = Path(file_path)
        language = self._detect_language(path)
        
        if not language:
            return {"error": f"Unsupported file type: {path.suffix}"}
        
        # Read code
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            return {"error": f"Could not read file: {str(e)}"}
        
        # Run multiple detection methods
        results = {
            'file': str(file_path),
            'language': language,
            'vulnerabilities': []
        }
        
        # 1. Pattern-based detection
        print("   🔍 Running pattern-based detection...")
        pattern_vulns = self.pattern_detector.detect_vulnerabilities(code, language)
        results['vulnerabilities'].extend([
            self._vulnerability_to_dict(v) for v in pattern_vulns
        ])
        
        # 2. AST analysis (Python only)
        if language == 'python':
            print("   🌳 Running AST analysis...")
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
            print("   🛡️  Running Bandit scan...")
            bandit_results = self._run_bandit(file_path)
            results['vulnerabilities'].extend(bandit_results)
        
        # 4. ML classification (if trained)
        if self.ml_classifier and self.ml_classifier.is_trained:
            print("   🤖 Running ML classification...")
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
        
        print(f"   ✓ Found {total_vulns} potential vulnerabilities")
        
        return results
    
    def analyze_directory(
        self, 
        directory: str, 
        extensions: List[str] = None
    ) -> List[Dict]:
        """Analyze all files in a directory"""
        if extensions is None:
            extensions = ['.py', '.js', '.java']
        
        results = []
        path = Path(directory)
        
        files_to_scan = []
        for ext in extensions:
            files_to_scan.extend(path.rglob(f'*{ext}'))
        
        files_to_scan = [
            f for f in files_to_scan 
            if not self._should_skip(f)
        ]
        
        print(f"\n🔍 Found {len(files_to_scan)} files to scan\n")
        
        for i, file_path in enumerate(files_to_scan, 1):
            print(f"[{i}/{len(files_to_scan)}]", end=' ')
            result = self.analyze_file(str(file_path))
            results.append(result)
        
        return results
    
    def _run_bandit(self, file_path: str) -> List[Dict]:
        """Run Bandit static analysis tool"""
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', file_path],
                capture_output=True,
                text=True,
                timeout=30
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
        except Exception as e:
            print(f"   ⚠️  Bandit failed: {str(e)}")
        
        return []
    
    def _detect_language(self, path: Path) -> str:
        """Detect programming language from file extension"""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.php': 'php',
        }
        return extension_map.get(path.suffix, None)
    
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
        skip_dirs = {
            'venv', 'node_modules', '.git', '__pycache__',
            'build', 'dist', '.pytest_cache', 'env', 'venv'
        }
        return any(part in skip_dirs for part in file_path.parts)
