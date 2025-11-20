import sqlite3
import os
import subprocess

# VULNERABLE: SQL Injection
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABLE: Hardcoded credentials
def login(username, password):
    admin_password = "admin123"
    api_key = "sk-1234567890abcdef"
    
    if password == admin_password:
        return True
    return False

# VULNERABLE: Command Injection
def run_command(user_input):
    os.system(f"echo {user_input}")
    subprocess.call("ping " + user_input, shell=True)

# VULNERABLE: eval usage
def calculate(expression):
    result = eval(expression)
    return result

# VULNERABLE: Path Traversal
def read_file(filename):
    with open("/var/files/" + filename, 'r') as f:
        return f.read()
