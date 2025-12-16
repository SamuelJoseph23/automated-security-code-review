import re
from typing import Dict, List
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
                    # Python
                    r'execute\s*\(\s*["\'].*?%s.*?["\'].*?\%',  # String formatting
                    r'execute\s*\(\s*f["\'].*?\{.*?\}.*?["\']',  # f-strings in SQL
                    r'execute\s*\(\s*["\'].*?\+.*?["\']',  # String concatenation
                    r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\+',
                    r'\.format\s*\(.*?\).*?execute',
                    r'SELECT.*?FROM.*?\+.*?WHERE',
                    
                    # Java / General
                    r'executeQuery\s*\(\s*["\'].*?\s*\+\s*',  # "SELECT..." + var
                    r'executeUpdate\s*\(\s*["\'].*?\s*\+\s*',
                    r'execute\s*\(\s*["\'].*?\s*\+\s*',
                    r'createNativeQuery\s*\(\s*["\'].*?\s*\+\s*',
                    r'prepareStatement\s*\(\s*["\'].*?\s*\+\s*',
                    r'jdbcTemplate\.query.*?\+.*?',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-89',
                'description': 'SQL Injection vulnerability detected (Unsafe String Concatenation)',
                'exploit': 'Attacker can inject malicious SQL via string concatenation.',
                'fix': 'Use parameterized queries (PreparedStatement in Java, ? placeholders in Python).'
            },
            
            # Cross-Site Scripting (XSS)
            'xss': {
                'patterns': [
                    r'\.innerHTML\s*=.*?(?!escape|sanitize)',
                    r'document\.write\s*\(',
                    r'eval\s*\(',
                    r'dangerouslySetInnerHTML',
                    r'render_template_string\s*\(.*?\+',
                    
                    # Java / General
                    r'return\s+["\']<.*?["\']\s*\+\s*',  # Java: return "<div>" + input
                    r'response\.getWriter\(\)\.write\(.*?\)',
                    r'out\.println\(.*?\)',
                ],
                'severity': 'High',
                'cwe': 'CWE-79',
                'description': 'Cross-Site Scripting (XSS) vulnerability',
                'exploit': 'Attacker can inject malicious scripts into web pages.',
                'fix': 'Escape user input and use safe rendering methods.'
            },
            
            # Command Injection
            'command_injection': {
                'patterns': [
                    # Python
                    r'os\.system\s*\([^)]*(?:input|request|argv)',
                    r'subprocess\.(?:call|run|Popen)\s*\(.*?shell\s*=\s*True',
                    r'exec\s*\(',
                    r'__import__\s*\(',
                    
                    # Java
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'ProcessBuilder\s*\(',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-78',
                'description': 'Command Injection vulnerability detected',
                'exploit': 'Attacker can execute arbitrary system commands.',
                'fix': 'Avoid executing shell commands or validate input strictly.'
            },
            
            # Hardcoded Secrets
            'hardcoded_secrets': {
                'patterns': [
                    # Universal
                    r'(?i)(password|passwd|pwd|secret|token|api_key|auth_key)\s*=\s*["\'][^"\']{5,}["\']',
                    r'aws[_-]?access[_-]?key\s*=',
                    r'private[_-]?key\s*=\s*["\']',
                    r'bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*',
                    
                    # Java
                    r'(?i)private\s+static\s+final\s+String\s+.*?(PASS|KEY|SECRET).*?=\s*["\'].*?["\']',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded credentials detected',
                'exploit': 'Credentials exposed in source code.',
                'fix': 'Use environment variables or a secrets manager.'
            },
            
            # Path Traversal
            'path_traversal': {
                'patterns': [
                    r'open\s*\([^)]*(?:input|request|argv)',
                    r'file\s*=\s*.*?(?:request|input)',
                    r'\.\./',
                    r'os\.path\.join\s*\([^)]*(?:request|input)',
                    
                    # Java
                    r'new\s+File\s*\(.*?\s*\+\s*',
                    r'Paths\.get\s*\(.*?\s*\+\s*',
                ],
                'severity': 'High',
                'cwe': 'CWE-22',
                'description': 'Path Traversal vulnerability',
                'exploit': 'Attacker can access unauthorized files via directory traversal.',
                'fix': 'Validate paths, use whitelist, sanitize input.'
            },
            
            # Insecure Deserialization
            'insecure_deserialization': {
                'patterns': [
                    r'pickle\.loads?\s*\(',
                    r'yaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader)',
                    r'marshal\.loads?\s*\(',
                    r'jsonpickle\.decode',
                    
                    # Java
                    r'readObject\s*\(',
                    r'XMLDecoder\s*\(',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-502',
                'description': 'Insecure Deserialization detected',
                'exploit': 'Remote Code Execution through crafted payloads.',
                'fix': 'Use safe loaders, validate input types, avoid deserializing untrusted data.'
            },
            
            # Weak Cryptography
            'weak_crypto': {
                'patterns': [
                    r'hashlib\.md5\s*\(',
                    r'hashlib\.sha1\s*\(',
                    r'DES\.new\(',
                    r'ARC4\.new\(',
                    r'random\.random\(\).*?(?:password|key|token)',
                    
                    # Java
                    r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                    r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']',
                    r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
                ],
                'severity': 'High',
                'cwe': 'CWE-327',
                'description': 'Weak cryptographic algorithm detected',
                'exploit': 'Vulnerable to collision attacks and brute force.',
                'fix': 'Use SHA-256 or stronger algorithms.'
            },
            
            # SSRF (Server-Side Request Forgery)
            'ssrf': {
                'patterns': [
                    r'requests\.(?:get|post)\s*\([^)]*(?:request|input)',
                    r'urllib\.request\.urlopen\s*\([^)]*(?:request|input)',
                    
                    # Java
                    r'new\s+URL\s*\(.*?\s*\+\s*',
                    r'HttpURLConnection',
                ],
                'severity': 'High',
                'cwe': 'CWE-918',
                'description': 'Server-Side Request Forgery (SSRF)',
                'exploit': 'Attacker can access internal services via forged requests.',
                'fix': 'Validate URLs, use whitelist, disable redirects.'
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
                    # Use IGNORECASE for better matching
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        # Calculate confidence based on pattern specificity
                        confidence = self._calculate_confidence(
                            line, pattern, vuln_type
                        )
                        
                        # Threshold
                        if confidence > 0.3:
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
            'command_injection': ['system', 'shell', 'exec', 'eval', 'Runtime', 'Process'],
            'hardcoded_secrets': ['password', 'api_key', 'secret', 'token', 'key'],
            'xss': ['innerHTML', 'write', 'eval', 'print', 'response'],
            'weak_crypto': ['MD5', 'SHA1', 'DES'],
        }
        
        keywords = risk_keywords.get(vuln_type, [])
        for keyword in keywords:
            if keyword.lower() in line.lower():
                confidence += 0.2  # Boost confidence if keyword found
        
        # Decrease confidence if input validation or safe pattern present
        safe_indicators = ['validate', 'sanitize', 'escape', 'whitelist', 'Prepare', '?' ]
        
        # Specific check: if it's SQLi but uses ?, it's likely safe (parameterized)
        if vuln_type == 'sql_injection' and '?' in line:
            confidence -= 0.4
            
        for indicator in safe_indicators:
            if indicator.lower() in line.lower():
                confidence -= 0.3
        
        return min(max(confidence, 0.0), 1.0)
