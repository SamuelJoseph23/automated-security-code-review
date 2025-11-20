import re
from typing import Dict, List, Tuple
from dataclasses import dataclass

@dataclass
class Vulnerability:
    type: str
    severity: str
    line: int
    code_snippet: str
    description: str
    exploit_scenario: str
    fix_recommendation: str
    cwe: str
    confidence: float

class PatternBasedDetector:
    """Classical pattern-based vulnerability detection"""
    
    def __init__(self):
        self.patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict:
        """Load vulnerability detection patterns"""
        return {
            # SQL Injection Patterns
            'sql_injection': {
                'patterns': [
                    r'execute\s*\(\s*["\'].*?%s.*?["\'].*?\%',  # String formatting
                    r'execute\s*\(\s*f["\'].*?\{.*?\}.*?["\']',  # f-strings in SQL
                    r'execute\s*\(\s*["\'].*?\+.*?["\']',  # String concatenation
                    r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\+',
                    r'\.format\s*\(.*?\).*?execute',
                    r'SELECT.*?FROM.*?\+.*?WHERE',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-89',
                'description': 'SQL Injection vulnerability detected',
                'exploit': 'Attacker can inject malicious SQL: \' OR \'1\'=\'1',
                'fix': 'Use parameterized queries with placeholders'
            },
            
            # Cross-Site Scripting (XSS)
            'xss': {
                'patterns': [
                    r'\.innerHTML\s*=.*?(?!escape|sanitize)',
                    r'document\.write\s*\(',
                    r'eval\s*\(',
                    r'dangerouslySetInnerHTML',
                    r'render_template_string\s*\(.*?\+',
                ],
                'severity': 'High',
                'cwe': 'CWE-79',
                'description': 'Cross-Site Scripting (XSS) vulnerability',
                'exploit': 'Attacker can inject: <script>alert(document.cookie)</script>',
                'fix': 'Escape user input and use safe rendering methods'
            },
            
            # Command Injection
            'command_injection': {
                'patterns': [
                    r'os\.system\s*\([^)]*(?:input|request|argv)',
                    r'subprocess\.(?:call|run|Popen)\s*\(.*?shell\s*=\s*True',
                    r'exec\s*\(',
                    r'eval\s*\(',
                    r'__import__\s*\(',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-78',
                'description': 'Command Injection vulnerability detected',
                'exploit': 'Attacker can execute: ; rm -rf /',
                'fix': 'Avoid shell=True, use subprocess with lists, validate input'
            },
            
            # Hardcoded Secrets
            'hardcoded_secrets': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']{6,}["\']',
                    r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
                    r'secret[_-]?key\s*=\s*["\'][^"\']+["\']',
                    r'token\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']',
                    r'aws[_-]?access[_-]?key\s*=',
                    r'private[_-]?key\s*=\s*["\']',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded credentials detected',
                'exploit': 'Credentials exposed in source code/repository',
                'fix': 'Use environment variables or secure key management'
            },
            
            # Path Traversal
            'path_traversal': {
                'patterns': [
                    r'open\s*\([^)]*(?:input|request|argv)',
                    r'file\s*=\s*.*?(?:request|input)',
                    r'\.\./',
                    r'os\.path\.join\s*\([^)]*(?:request|input)',
                ],
                'severity': 'High',
                'cwe': 'CWE-22',
                'description': 'Path Traversal vulnerability',
                'exploit': 'Attacker can access: ../../etc/passwd',
                'fix': 'Validate paths, use whitelist, sanitize input'
            },
            
            # Insecure Deserialization
            'insecure_deserialization': {
                'patterns': [
                    r'pickle\.loads?\s*\(',
                    r'yaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader)',
                    r'marshal\.loads?\s*\(',
                    r'jsonpickle\.decode',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-502',
                'description': 'Insecure Deserialization detected',
                'exploit': 'Remote Code Execution through crafted payloads',
                'fix': 'Use safe loaders: yaml.SafeLoader, avoid pickle'
            },
            
            # Weak Cryptography
            'weak_crypto': {
                'patterns': [
                    r'hashlib\.md5\s*\(',
                    r'hashlib\.sha1\s*\(',
                    r'DES\.new\(',
                    r'ARC4\.new\(',
                    r'Random\.new\(\)',
                    r'random\.random\(\).*?(?:password|key|token)',
                ],
                'severity': 'High',
                'cwe': 'CWE-327',
                'description': 'Weak cryptographic algorithm',
                'exploit': 'Vulnerable to collision attacks and brute force',
                'fix': 'Use SHA-256, SHA-3, or bcrypt for hashing'
            },
            
            # SSRF (Server-Side Request Forgery)
            'ssrf': {
                'patterns': [
                    r'requests\.(?:get|post)\s*\([^)]*(?:request|input)',
                    r'urllib\.request\.urlopen\s*\([^)]*(?:request|input)',
                    r'httplib\..*?\([^)]*(?:request|input)',
                ],
                'severity': 'High',
                'cwe': 'CWE-918',
                'description': 'Server-Side Request Forgery (SSRF)',
                'exploit': 'Access internal services: http://localhost:8080/admin',
                'fix': 'Validate URLs, use whitelist, disable redirects'
            },
        }
    
    def detect_vulnerabilities(
        self, 
        code: str, 
        language: str = "python"
    ) -> List[Vulnerability]:
        """Detect vulnerabilities using pattern matching"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for vuln_type, config in self.patterns.items():
            for pattern in config['patterns']:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        # Calculate confidence based on pattern specificity
                        confidence = self._calculate_confidence(
                            line, pattern, vuln_type
                        )
                        
                        if confidence > 0.3:  # Threshold
                            vuln = Vulnerability(
                                type=vuln_type.replace('_', ' ').title(),
                                severity=config['severity'],
                                line=line_num,
                                code_snippet=line.strip(),
                                description=config['description'],
                                exploit_scenario=config['exploit'],
                                fix_recommendation=config['fix'],
                                cwe=config['cwe'],
                                confidence=confidence
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_confidence(
        self, 
        line: str, 
        pattern: str, 
        vuln_type: str
    ) -> float:
        """Calculate confidence score for detection"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence for specific indicators
        risk_keywords = {
            'sql_injection': ['execute', 'query', 'SELECT', 'INSERT', 'UPDATE'],
            'command_injection': ['system', 'shell', 'exec', 'eval'],
            'hardcoded_secrets': ['password', 'api_key', 'secret', 'token'],
            'xss': ['innerHTML', 'write', 'eval'],
        }
        
        keywords = risk_keywords.get(vuln_type, [])
        for keyword in keywords:
            if keyword.lower() in line.lower():
                confidence += 0.1
        
        # Decrease confidence if input validation present
        safe_indicators = ['validate', 'sanitize', 'escape', 'whitelist']
        for indicator in safe_indicators:
            if indicator in line.lower():
                confidence -= 0.3
        
        return min(max(confidence, 0.0), 1.0)
