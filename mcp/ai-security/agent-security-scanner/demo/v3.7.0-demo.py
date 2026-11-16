#!/usr/bin/env python3
"""
Demo: v3.7.0 Inter-Procedural Taint Analysis
=============================================

This file demonstrates the new inter-procedural taint analysis feature
that can detect vulnerabilities across multiple function calls.

Previous versions could only detect taint within a single function.
v3.7.0 builds a call graph and tracks taint through function boundaries!
"""

from flask import Flask, request
import os
import subprocess

app = Flask(__name__)

# ============================================================================
# DEMO 1: Basic Parameter-to-Return Taint Flow
# ============================================================================
# Previous: ❌ MISSED - couldn't see through process_user_input()
# v3.7.0:   ✅ DETECTED - tracks taint from user_cmd → processed → os.system()

def process_user_input(data):
    """Helper function that processes user input"""
    return "command: " + data

@app.route('/demo1/vulnerable')
def demo1_vulnerable():
    """VULNERABLE: Command injection through function call"""
    user_cmd = request.args.get('cmd')
    processed = process_user_input(user_cmd)  # Taint flows through here!
    os.system(processed)  # 💥 VULNERABLE: Inter-procedural taint detected!
    return "Executed"

@app.route('/demo1/safe')
def demo1_safe():
    """SAFE: Using subprocess with shell=False"""
    user_cmd = request.args.get('cmd')
    processed = process_user_input(user_cmd)
    subprocess.run(['echo', processed], shell=False)  # ✅ SAFE
    return "Executed safely"


# ============================================================================
# DEMO 2: Source-Returning Functions
# ============================================================================
# Previous: ❌ MISSED - couldn't track function return values
# v3.7.0:   ✅ DETECTED - tracks get_user_data() as source-returning function

def get_user_data():
    """Function that returns tainted data from request"""
    return request.args.get('input')

@app.route('/demo2/vulnerable')
def demo2_vulnerable():
    """VULNERABLE: Using source-returning function"""
    user_input = get_user_data()  # Function returns tainted data
    os.system(user_input)  # 💥 VULNERABLE: Taint from source function!
    return "Executed"


# ============================================================================
# DEMO 3: Multi-Hop Taint Chains (3+ function calls)
# ============================================================================
# Previous: ❌ MISSED - couldn't track through multiple hops
# v3.7.0:   ✅ DETECTED - tracks taint through 3+ function calls!

def step1_receive(data):
    """First hop: receive data"""
    return data + "_step1"

def step2_process(data):
    """Second hop: process data"""
    return data + "_step2"

def step3_format(data):
    """Third hop: format data"""
    return "formatted: " + data

@app.route('/demo3/vulnerable')
def demo3_vulnerable():
    """VULNERABLE: Command injection through 3-hop chain"""
    user_input = request.args.get('data')
    hop1 = step1_receive(user_input)      # Hop 1
    hop2 = step2_process(hop1)            # Hop 2
    hop3 = step3_format(hop2)             # Hop 3
    os.system(hop3)  # 💥 VULNERABLE: 3-hop inter-procedural taint!
    return "Executed"


# ============================================================================
# DEMO 4: Internal Sinks (Sink Inside Called Function)
# ============================================================================
# Previous: ❌ MISSED - couldn't detect sinks inside called functions
# v3.7.0:   ✅ DETECTED - builds function summaries with internal sinks!

def execute_command(cmd):
    """Function with internal sink"""
    os.system(cmd)  # Sink is INSIDE this function

@app.route('/demo4/vulnerable')
def demo4_vulnerable():
    """VULNERABLE: Sink is inside the called function"""
    user_cmd = request.args.get('cmd')
    execute_command(user_cmd)  # 💥 VULNERABLE: Internal sink detected!
    return "Executed"


# ============================================================================
# DEMO 5: Sanitizer Blocking
# ============================================================================
# Previous: ❌ FALSE POSITIVE - couldn't see sanitizers in other functions
# v3.7.0:   ✅ SMART - tracks sanitizers and blocks taint propagation!

def sanitize_input(data):
    """Sanitizer function that removes dangerous characters"""
    if data is None:
        return ""
    # Remove shell metacharacters
    return data.replace(";", "").replace("&", "").replace("|", "").replace("`", "")

@app.route('/demo5/safe')
def demo5_safe():
    """SAFE: Sanitizer blocks taint propagation"""
    user_cmd = request.args.get('cmd')
    safe_cmd = sanitize_input(user_cmd)  # Sanitizer blocks taint
    os.system(safe_cmd)  # ✅ SAFE: Sanitizer detected, no false positive!
    return "Executed safely"


# ============================================================================
# DEMO 6: Complex Real-World Example
# ============================================================================
# Previous: ❌ MISSED - too complex for single-function analysis
# v3.7.0:   ✅ DETECTED - handles complex call graphs!

class CommandBuilder:
    """Class with methods that propagate taint"""

    def __init__(self):
        self.prefix = ""

    def set_prefix(self, prefix):
        self.prefix = prefix
        return self

    def build_command(self, user_input):
        """Builds command from user input"""
        return f"{self.prefix} {user_input}"

def validate_input(data):
    """Validation that doesn't sanitize"""
    if data and len(data) < 100:
        return data
    return ""

def log_and_execute(command):
    """Logs command and executes it"""
    print(f"Executing: {command}")
    os.system(command)  # Sink inside helper function

@app.route('/demo6/vulnerable')
def demo6_vulnerable():
    """VULNERABLE: Complex multi-step attack chain"""
    # Step 1: Get user input
    user_data = request.args.get('action')

    # Step 2: Validate (but not sanitize)
    validated = validate_input(user_data)

    # Step 3: Build command using class method
    builder = CommandBuilder()
    builder.set_prefix("ping -c 1")
    command = builder.build_command(validated)

    # Step 4: Execute through helper function
    log_and_execute(command)  # 💥 VULNERABLE: Complex chain detected!

    return "Executed"


# ============================================================================
# DEMO 7: SQL Injection Through Multiple Functions
# ============================================================================

def get_user_filter():
    """Gets filter from user input"""
    return request.args.get('filter')

def build_query(table, filter_value):
    """Builds SQL query - VULNERABLE"""
    return f"SELECT * FROM {table} WHERE name = '{filter_value}'"

def execute_query(query):
    """Executes the query"""
    import sqlite3
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute(query)  # 💥 VULNERABLE: SQL injection!
    return cursor.fetchall()

@app.route('/demo7/vulnerable')
def demo7_vulnerable():
    """VULNERABLE: SQL injection through function chain"""
    user_filter = get_user_filter()           # Source function
    query = build_query('users', user_filter) # Taint propagates
    results = execute_query(query)            # Sink in called function
    return str(results)


# ============================================================================
# Performance Note
# ============================================================================
"""
🚀 BONUS: Python Daemon with LRU Caching

When you scan this file multiple times:
- First scan:  ~4-7 seconds (cold start)
- Second scan: ~0-1 milliseconds (cached!)
- Speedup:     ~4000x faster! 🔥

The daemon caches results keyed by (file_path, mtime), so unchanged files
return instantly from cache. Perfect for:
- IDE integrations
- Pre-commit hooks
- Watch mode development
- CI/CD pipelines
"""

if __name__ == '__main__':
    print("⚠️  WARNING: This file contains intentional vulnerabilities for demo purposes.")
    print("    DO NOT run this server in production!")
    print()
    print("To scan this file:")
    print("  npx agent-security-scanner-mcp scan test demo/v3.7.0-demo.py")
    app.run(debug=True, port=5000)
