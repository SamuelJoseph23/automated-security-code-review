import ast
from typing import List, Dict, Set
from dataclasses import dataclass

@dataclass
class SecurityIssue:
    type: str
    severity: str
    line_number: int
    description: str
    context: str

class ASTSecurityAnalyzer(ast.NodeVisitor):
    """AST-based vulnerability detection for Python"""
    
    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.imported_modules: Set[str] = set()
        self.dangerous_functions: Set[str] = set()
    
    def analyze(self, code: str) -> List[SecurityIssue]:
        """Analyze Python code using AST"""
        try:
            tree = ast.parse(code)
            self.visit(tree)
            return self.issues
        except SyntaxError as e:
            return [SecurityIssue(
                type="Syntax Error",
                severity="Low",
                line_number=e.lineno or 0,
                description=f"Syntax error: {str(e)}",
                context=""
            )]
    
    def visit_Import(self, node: ast.Import):
        """Track imported modules"""
        for alias in node.names:
            self.imported_modules.add(alias.name)
            
            # Check for dangerous imports
            if alias.name in ['pickle', 'marshal', 'subprocess', 'os']:
                self.issues.append(SecurityIssue(
                    type="Potentially Dangerous Import",
                    severity="Medium",
                    line_number=node.lineno,
                    description=f"Import of '{alias.name}' - requires careful usage",
                    context=ast.unparse(node)
                ))
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Analyze function calls for security issues"""
        func_name = self._get_func_name(node.func)
        
        # Check eval/exec
        if func_name in ['eval', 'exec', '__import__']:
            self.issues.append(SecurityIssue(
                type="Dangerous Function Call",
                severity="Critical",
                line_number=node.lineno,
                description=f"Use of {func_name}() - arbitrary code execution",
                context=ast.unparse(node)
            ))
        
        # Check subprocess with shell=True
        if func_name in ['subprocess.call', 'subprocess.run', 'subprocess.Popen']:
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        self.issues.append(SecurityIssue(
                            type="Command Injection Risk",
                            severity="Critical",
                            line_number=node.lineno,
                            description="subprocess with shell=True is dangerous",
                            context=ast.unparse(node)
                        ))
        
        # Check pickle.loads
        if func_name in ['pickle.loads', 'pickle.load']:
            self.issues.append(SecurityIssue(
                type="Insecure Deserialization",
                severity="Critical",
                line_number=node.lineno,
                description="pickle.loads() can execute arbitrary code",
                context=ast.unparse(node)
            ))
        
        # Check SQL execution
        if func_name in ['execute', 'executemany']:
            # Check if SQL query uses string formatting
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self.issues.append(SecurityIssue(
                    type="SQL Injection",
                    severity="Critical",
                    line_number=node.lineno,
                    description="SQL query uses string formatting - use parameterized queries",
                    context=ast.unparse(node)
                ))
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Check for hardcoded secrets in assignments"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # Check for password/key/secret assignments
                if any(keyword in var_name for keyword in ['password', 'secret', 'key', 'token']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 5:  # Non-trivial string
                            self.issues.append(SecurityIssue(
                                type="Hardcoded Credentials",
                                severity="Critical",
                                line_number=node.lineno,
                                description=f"Hardcoded {var_name} detected",
                                context=ast.unparse(node)
                            ))
        
        self.generic_visit(node)
    
    def _get_func_name(self, node) -> str:
        """Extract function name from call node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_func_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        return ""
