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
    """
    Advanced pattern-based vulnerability detection engine.
    Supports: Python, Java, JavaScript/TypeScript, C/C++, PHP, Go, Ruby.
    """
    
    def __init__(self):
        self.patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict:
        """Load comprehensive vulnerability detection patterns"""
        return {
            # -----------------------------------------------------------
            # 1. SQL Injection (SQLi)
            # -----------------------------------------------------------
            'sql_injection': {
                'patterns': [
                    # Python
                    r'execute\s*\(\s*["\'].*?%s.*?["\'].*?\%',
                    r'execute\s*\(\s*f["\'].*?\{.*?\}.*?["\']',
                    r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\+',
                    
                    # Java
                    r'executeQuery\s*\(\s*["\'].*?\s*\+\s*',
                    r'executeUpdate\s*\(\s*["\'].*?\s*\+\s*',
                    r'createNativeQuery\s*\(\s*["\'].*?\s*\+\s*',
                    r'prepareStatement\s*\(\s*["\'].*?\s*\+\s*',
                    
                    # JS/Node
                    r'\.query\s*\(\s*["\'].*?\s*\+\s*',
                    r'\.query\s*\(\s*`.*?$\{.*?\}',
                    
                    # PHP
                    r'mysqli_query\s*\(\s*.*?\s*\.\s*',
                    r'\$db->query\s*\(\s*["\'].*?\s*\.\s*',
                    
                    # C/C++
                    r'sprintf\s*\(.*?select.*?%s',
                    r'sqlite3_exec\s*\(.*?%s',
                    
                    # Go
                    r'db\.Query\s*\(\s*fmt\.Sprintf',
                    r'db\.Exec\s*\(\s*fmt\.Sprintf',
                    
                    # Ruby
                    r'where\s*\(\s*["\'].*?#\{.*?\}',
                    r'find_by_sql\s*\(\s*["\'].*?#\{.*?\}',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-89',
                'description': 'SQL Injection vulnerability detected (Unsafe Query Construction)',
                'exploit': 'Attacker can inject malicious SQL via string concatenation or formatting.',
                'fix': 'Use parameterized queries, PreparedStatements, or ORM binding methods.'
            },
            
            # -----------------------------------------------------------
            # 2. Cross-Site Scripting (XSS)
            # -----------------------------------------------------------
            'xss': {
                'patterns': [
                    # General / JS
                    r'\.innerHTML\s*=.*?(?!escape|sanitize)',
                    r'document\.write\s*\(',
                    r'dangerouslySetInnerHTML',
                    r'\.html\s*\(\s*.*?\)',
                    r'v-html\s*=',
                    r'\[innerHTML\]\s*=',
                    
                    # Java
                    r'return\s+["\']<.*?["\']\s*\+\s*',
                    r'out\.println\(.*?\)',
                    
                    # PHP
                    r'echo\s+\$_GET\[',
                    r'echo\s+\$_POST\[',
                    r'echo\s+\$_REQUEST\[',
                    
                    # Go
                    r'w\.Write\(\[\]byte\(r\.URL\.Query\(\)\.Get',
                    
                    # Ruby (Rails)
                    r'raw\s+',
                    r'html_safe',
                ],
                'severity': 'High',
                'cwe': 'CWE-79',
                'description': 'Cross-Site Scripting (XSS) vulnerability',
                'exploit': 'Attacker can inject malicious scripts into web pages.',
                'fix': 'Escape user input, use safe rendering methods, or Content Security Policy (CSP).'
            },
            
            # -----------------------------------------------------------
            # 3. Command Injection (RCE)
            # -----------------------------------------------------------
            'command_injection': {
                'patterns': [
                    # Python
                    r'os\.system\s*\([^)]*(?:input|request|argv)',
                    r'subprocess\.(?:call|run|Popen)\s*\(.*?shell\s*=\s*True',
                    r'exec\s*\(',
                    
                    # Java
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'ProcessBuilder\s*\(',
                    
                    # JS/Node
                    r'child_process\.exec\s*\(',
                    r'child_process\.spawn\s*\(.*?shell\s*:\s*true',
                    r'eval\s*\(',
                    
                    # PHP
                    r'shell_exec\s*\(',
                    r'system\s*\(',
                    r'passthru\s*\(',
                    r'exec\s*\(',
                    
                    # C/C++
                    r'system\s*\(\s*.*?\)',
                    r'popen\s*\(\s*.*?\)',
                    
                    # Go
                    r'exec\.Command\s*\(\s*["\'](sh|bash|cmd)["\']',
                    
                    # Ruby
                    r'system\s*\(',
                    r'`.*?#\{.*?\}',  # Backtick execution
                    r'%x\[.*?\]',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-78',
                'description': 'Command Injection vulnerability detected',
                'exploit': 'Attacker can execute arbitrary system commands.',
                'fix': 'Avoid executing shell commands or validate input strictly (whitelist).'
            },
            
            # -----------------------------------------------------------
            # 4. Hardcoded Secrets
            # -----------------------------------------------------------
            'hardcoded_secrets': {
                'patterns': [
                    # Universal
                    r'(?i)(password|passwd|pwd|secret|token|api_key|auth_key|access_key)\s*=\s*["\'][^"\']{8,}["\']',
                    r'aws[_-]?access[_-]?key\s*=',
                    r'bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*',
                    r'BEGIN\s+PRIVATE\s+KEY',
                    
                    # Java
                    r'(?i)private\s+static\s+final\s+String\s+.*?(PASS|KEY|SECRET).*?=\s*["\'].*?["\']',
                    
                    # C/C++
                    r'#define\s+.*?(PASS|KEY|SECRET)\s+["\'].*?["\']',
                    
                    # Go
                    r'const\s+.*?(Pass|Key|Secret)\s*=\s*["\'].*?["\']',
                    
                    # PHP
                    r'define\s*\(\s*["\'].*?(PASS|KEY|SECRET).*?["\']\s*,\s*["\'].*?["\']',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-798',
                'description': 'Hardcoded credentials detected',
                'exploit': 'Credentials exposed in source code.',
                'fix': 'Use environment variables or a secrets manager.'
            },
            
            # -----------------------------------------------------------
            # 5. Buffer Overflow / Memory Safety (C/C++)
            # -----------------------------------------------------------
            'buffer_overflow': {
                'patterns': [
                    r'strcpy\s*\(',
                    r'strcat\s*\(',
                    r'gets\s*\(',
                    r'sprintf\s*\(',
                    r'scanf\s*\(\s*["\']%s["\']',
                    r'memcpy\s*\([^,]+,[^,]+,\s*strlen\(',  # classic memcpy overflow pattern
                ],
                'severity': 'Critical',
                'cwe': 'CWE-120',
                'description': 'Potential Buffer Overflow detected',
                'exploit': 'Attacker can crash the program or execute arbitrary code by overwriting memory.',
                'fix': 'Use safe alternatives: strncpy, strncat, fgets, snprintf.'
            },
            
            # -----------------------------------------------------------
            # 6. Path Traversal
            # -----------------------------------------------------------
            'path_traversal': {
                'patterns': [
                    # Python
                    r'open\s*\([^)]*(?:input|request|argv)',
                    r'os\.path\.join\s*\([^)]*(?:request|input)',
                    r'\.\./',
                    
                    # Java
                    r'new\s+File\s*\(.*?\s*\+\s*',
                    r'Paths\.get\s*\(.*?\s*\+\s*',
                    
                    # JS
                    r'fs\.readFile\s*\(\s*.*?\+',
                    r'res\.sendFile\s*\(\s*.*?\+',
                    
                    # PHP
                    r'include\s*\(\s*\$_(GET|POST)',
                    r'require\s*\(\s*\$_(GET|POST)',
                    r'file_get_contents\s*\(\s*\$_(GET|POST)',
                    
                    # C/C++
                    r'fopen\s*\(\s*.*?\s*,\s*',
                ],
                'severity': 'High',
                'cwe': 'CWE-22',
                'description': 'Path Traversal vulnerability',
                'exploit': 'Attacker can access unauthorized files via directory traversal.',
                'fix': 'Validate paths, use whitelist, sanitize input (remove ../).'
            },
            
            # -----------------------------------------------------------
            # 7. Insecure Deserialization
            # -----------------------------------------------------------
            'insecure_deserialization': {
                'patterns': [
                    # Python
                    r'pickle\.loads?\s*\(',
                    r'yaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader)',
                    
                    # Java
                    r'readObject\s*\(',
                    r'XMLDecoder\s*\(',
                    
                    # JS
                    r'serialize\.unserialize\s*\(',
                    r'eval\s*\(\s*JSON\.parse',
                    
                    # PHP
                    r'unserialize\s*\(',
                ],
                'severity': 'Critical',
                'cwe': 'CWE-502',
                'description': 'Insecure Deserialization detected',
                'exploit': 'Remote Code Execution through crafted payloads.',
                'fix': 'Use safe loaders, validate input types, avoid deserializing untrusted data.'
            },
            
            # -----------------------------------------------------------
            # 8. Weak Cryptography
            # -----------------------------------------------------------
            'weak_crypto': {
                'patterns': [
                    # General
                    r'(?i)md5',
                    r'(?i)sha1',
                    r'DES',
                    r'RC4',
                    
                    # Python
                    r'hashlib\.md5\s*\(',
                    r'random\.random\(\)',  # Not crypto safe
                    
                    # Java
                    r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                    r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
                    
                    # JS
                    r'crypto\.createHash\s*\(\s*["\']md5["\']',
                    r'Math\.random\(\)',    # Not crypto safe
                    
                    # C/C++
                    r'MD5_Init',
                    r'EVP_des_ecb',
                    r'rand\(\)',            # Not crypto safe
                    
                    # PHP
                    r'md5\s*\(',
                    r'sha1\s*\(',
                ],
                'severity': 'High',
                'cwe': 'CWE-327',
                'description': 'Weak cryptographic algorithm detected',
                'exploit': 'Vulnerable to collision attacks and brute force.',
                'fix': 'Use SHA-256, AES-GCM, or stronger algorithms. Use CSPRNG for secrets.'
            },
            
            # -----------------------------------------------------------
            # 9. SSRF (Server-Side Request Forgery)
            # -----------------------------------------------------------
            'ssrf': {
                'patterns': [
                    # Python
                    r'requests\.get\s*\(\s*request\.',
                    r'urllib\.request\.urlopen\s*\(\s*request\.',
                    
                    # Java
                    r'new\s+URL\s*\(.*?\s*\+\s*',
                    r'HttpURLConnection',
                    
                    # PHP
                    r'curl_init\s*\(\s*\$_(GET|POST)',
                    r'file_get_contents\s*\(\s*http',
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
            'sql_injection': ['execute', 'query', 'SELECT', 'INSERT', 'UPDATE', 'sprintf', 'format', 'Fetch', 'Delete'],
            'command_injection': ['system', 'shell', 'exec', 'eval', 'Runtime', 'Process', 'popen', 'spawn', 'bash', 'cmd'],
            'hardcoded_secrets': ['password', 'api_key', 'secret', 'token', 'key', 'auth', 'cred', 'private'],
            'xss': ['innerHTML', 'write', 'eval', 'print', 'response', 'render', 'send', 'echo', 'raw'],
            'buffer_overflow': ['strcpy', 'gets', 'strcat', 'scanf', 'buffer', 'char', 'memcpy'],
            'weak_crypto': ['MD5', 'SHA1', 'DES', 'crypto', 'rand', 'random'],
            'path_traversal': ['file', 'path', 'open', 'read', 'include', 'require', '../'],
            'insecure_deserialization': ['pickle', 'yaml', 'serialize', 'decode', 'readObject'],
        }
        
        keywords = risk_keywords.get(vuln_type, [])
        for keyword in keywords:
            if keyword.lower() in line.lower():
                confidence += 0.2  # Boost confidence if keyword found
        
        # Decrease confidence if input validation or safe pattern present
        safe_indicators = [
            'validate', 'sanitize', 'escape', 'whitelist', 'Prepare', '?',  # SQL/General
            'strncpy', 'strncat', 'snprintf', 'fgets',                      # C Safe Functions
            'DOMPurify', 'encodeURIComponent', 'htmlspecialchars',          # JS/PHP Safe Functions
            'secure_filename', 'safe_join'                                  # Python Safe Functions
        ]
        
        # Specific check: if it's SQLi but uses ?, it's likely safe (parameterized)
        if vuln_type == 'sql_injection' and '?' in line:
            confidence -= 0.4
            
        for indicator in safe_indicators:
            if indicator.lower() in line.lower():
                confidence -= 0.3
        
        return min(max(confidence, 0.0), 1.0)
