# Best Practices Guide

## 📖 Introduction

This guide provides best practices for using CTF-MCP effectively and safely. Following these guidelines will help you maximize the tool's capabilities while maintaining security and ethical standards.

## 🎯 General Principles

### 1. Start with Reconnaissance
Always begin with information gathering before attempting exploitation:

```
✓ Use tech_detect to identify technologies
✓ Use port_scan to discover open services
✓ Use subdomain_bruteforce for domain enumeration
✓ Use fingerprint_engine for detailed fingerprinting
```

### 2. Understand Before Acting
```
✓ Read tool descriptions before use
✓ Check risk levels (LOW → MEDIUM → HIGH → CRITICAL)
✓ Understand what each tool does
✓ Know the potential impact
```

### 3. Progress Gradually
```
✓ Start with passive reconnaissance
✓ Move to active scanning
✓ Then vulnerability detection
✓ Finally, exploitation (with authorization)
```

## 🔍 Reconnaissance Phase

### Information Gathering Workflow

```python
# Step 1: Technology Detection
tech_detect(url="https://target.com")

# Step 2: Port Scanning
port_scan(target="target.com", ports="1-1000")

# Step 3: Subdomain Enumeration
subdomain_bruteforce(domain="target.com")

# Step 4: Directory Discovery
dir_bruteforce(url="https://target.com")

# Step 5: Fingerprinting
fingerprint_engine(url="https://target.com")
```

### Best Practices for Recon

**DO:**
- ✅ Use multiple tools to cross-verify findings
- ✅ Document all discovered information
- ✅ Start with broad scans, then narrow down
- ✅ Respect rate limits and timeouts

**DON'T:**
- ❌ Skip reconnaissance and jump to exploitation
- ❌ Use aggressive scanning on production systems
- ❌ Ignore robots.txt and security.txt
- ❌ Overwhelm targets with requests

## 🔐 Vulnerability Detection

### Systematic Approach

```python
# 1. Start with automated scanning
vuln_check(url="https://target.com")

# 2. Test specific vulnerabilities based on findings
sqli_detect(url="https://target.com/page?id=1")
xss_detect(url="https://target.com/search?q=test")
ssrf_detect(url="https://target.com/fetch?url=example.com")

# 3. Verify findings manually
verify_vuln(url="...", param="...", vuln_type="sqli")
```

### Testing Guidelines

**Input Validation Testing:**
```
✓ Test all input parameters
✓ Try different payload types
✓ Check for filter bypasses
✓ Verify with multiple methods
```

**Authentication Testing:**
```
✓ Test weak passwords with fingerprint_weak_password
✓ Check for authentication bypass
✓ Test session management
✓ Verify JWT security with jwt_full_scan
```

**API Security Testing:**
```
✓ Test REST endpoints with api_security_test
✓ Check GraphQL with graphql_full_scan
✓ Test WebSocket with websocket_full_scan
✓ Verify CORS with cors_deep_check
```

### Using AI Assistant

The AI assistant can help analyze challenges and suggest approaches:

```python
# Analyze a CTF challenge
challenge_info = {
    "description": "Find the flag in this encrypted message",
    "files": ["encrypted.txt"],
    "category": "crypto"
}

# AI will suggest:
# - Challenge category
# - Recommended tools
# - Step-by-step approach
# - Next actions
```

### Workflow System

Use pre-built workflows for common scenarios:

```python
# Web challenge workflow
workflow = CTFWorkflowTemplates.web_recon_workflow()
workflow.execute(initial_context={"target": "https://ctf.example.com"})

# Crypto challenge workflow
workflow = CTFWorkflowTemplates.crypto_analysis_workflow()
workflow.execute(initial_context={"ciphertext": "..."})

# Pwn challenge workflow
workflow = CTFWorkflowTemplates.pwn_exploit_workflow()
workflow.execute(initial_context={"binary_path": "./challenge"})
```

### Category-Specific Tips

**Web Challenges:**
```
1. Check source code and comments
2. Test all input fields
3. Look for hidden endpoints
4. Check for common vulnerabilities (SQLi, XSS, SSRF)
5. Analyze JavaScript files
```

**Crypto Challenges:**
```
1. Identify encoding/encryption method
2. Try common ciphers (Caesar, Vigenere, Base64)
3. Analyze patterns and frequencies
4. Check for weak keys or implementation flaws
5. Use crypto_identify for automatic detection
```

**Pwn Challenges:**
```
1. Run checksec to identify protections
2. Analyze binary with reverse tools
3. Find vulnerability (buffer overflow, format string)
4. Calculate offsets
5. Craft exploit payload
```

## 🛠️ Tool Selection Guide

### By Risk Level

**🟢 LOW Risk - Safe for Initial Testing:**
```
- tech_detect
- port_scan
- dns_lookup
- whois_query
- fingerprint_engine
- crypto_identify
```

**🟡 MEDIUM Risk - Requires Authorization:**
```
- dir_bruteforce
- subdomain_bruteforce
- vuln_check
- sqli_detect
- xss_detect
```

**🟠 HIGH Risk - Explicit Authorization Required:**
```
- weak_password_detect
- exploit_sqli_extract
- file_upload_detect
- auth_bypass_detect
```

**🔴 CRITICAL Risk - Written Authorization Required:**
```
- pickle_payload
- yaml_deserialize
- nodejs_deserialize
- ssti_payloads
- cmd_injection
- lateral_*_exec
```

### By Use Case

**Information Gathering:**
```
full_recon → Comprehensive reconnaissance
tech_detect → Technology identification
fingerprint_engine → Detailed fingerprinting
js_analyze → JavaScript analysis
```

**Vulnerability Scanning:**
```
auto_pentest → Automated full scan
vulnerability_pipeline → Complete workflow
vuln_check → General vulnerability check
nuclei_scan → Template-based scanning
```

**Specific Vulnerability Testing:**
```
sqli_detect → SQL injection
xss_detect → Cross-site scripting
ssrf_detect → Server-side request forgery
xxe_detect → XML external entity
```

**Exploitation:**
```
exploit_sqli_extract → SQL data extraction
lateral_smb_exec → SMB lateral movement
lateral_ssh_exec → SSH lateral movement
```

## 📊 Result Interpretation

### Understanding Output

**Vulnerability Detection Results:**
```json
{
  "vulnerable": true,
  "vulnerability_type": "SQL Injection",
  "severity": "HIGH",
  "proof": "' OR '1'='1 returned different response",
  "recommendation": "Use parameterized queries"
}
```

**What to look for:**
- ✅ Clear indication of vulnerability presence
- ✅ Severity level
- ✅ Proof of concept
- ✅ Remediation advice

### False Positives

**How to verify findings:**
```
1. Run the test multiple times
2. Use verify_vuln for statistical validation
3. Try manual exploitation
4. Cross-check with other tools
5. Analyze the actual response
```

## 🔄 Automation Best Practices

### Using Smart Pentest

```python
# AI-powered automated testing
smart_pentest(
    target="https://target.com",
    auto_learn=True,  # Learn from results
    use_cache=True    # Use cached results
)
```

**Benefits:**
- AI-driven decision making
- Automatic tool selection
- Performance optimization
- Learning from results

### Task Management

```python
# Submit long-running tasks
task_id = task_submit(
    tool_name="auto_pentest",
    target="https://target.com"
)

# Check status
task_status(task_id=task_id)

# List all tasks
task_list(limit=20)
```

## 🔒 Security Considerations

### Protecting Your Testing Environment

**Network Isolation:**
```
✓ Use VPN or isolated network
✓ Implement firewall rules
✓ Monitor outbound connections
✓ Use proxy for anonymity (when authorized)
```

**Data Protection:**
```
✓ Encrypt sensitive findings
✓ Use secure storage for reports
✓ Sanitize logs before sharing
✓ Follow data retention policies
```

### Avoiding Detection

**Legitimate Testing Techniques:**
```
✓ Use realistic user agents
✓ Respect rate limits
✓ Randomize request timing
✓ Use stealth_request for sensitive operations
```

**Note:** These techniques are for authorized testing only. Do not use for malicious purposes.

## 📝 Documentation and Reporting

### During Testing

**Keep detailed notes:**
```
✓ Timestamp all activities
✓ Document tools used
✓ Record findings immediately
✓ Note any anomalies
✓ Save all evidence
```

### Report Generation

```python
# Generate comprehensive report
generate_report(
    target="https://target.com",
    format="markdown",  # or "json", "html", "pdf"
    include_cve=True
)
```

**Report should include:**
- Executive summary
- Methodology
- Findings with severity
- Proof of concept
- Remediation recommendations
- Timeline of activities

## 🎓 Learning Resources

### Recommended Practice

**CTF Platforms:**
- HackTheBox
- TryHackMe
- PicoCTF
- OverTheWire

**Practice Labs:**
- DVWA (Damn Vulnerable Web Application)
- WebGoat
- Juice Shop
- VulnHub

### Skill Development

**Beginner Path:**
```
1. Learn basic web technologies
2. Understand common vulnerabilities
3. Practice with LOW risk tools
4. Participate in CTF competitions
5. Study vulnerability reports
```

**Intermediate Path:**
```
1. Master vulnerability detection
2. Learn exploitation techniques
3. Study real-world case studies
4. Practice responsible disclosure
5. Contribute to security community
```

**Advanced Path:**
```
1. Develop custom exploits
2. Research zero-day vulnerabilities
3. Create security tools
4. Mentor others
5. Present at conferences
```

## ⚠️ Common Mistakes to Avoid

### Technical Mistakes

```
❌ Not reading tool documentation
❌ Using wrong tool for the task
❌ Ignoring error messages
❌ Not verifying findings
❌ Skipping reconnaissance
❌ Using default wordlists only
❌ Not understanding the target
```

### Ethical Mistakes

```
❌ Testing without authorization
❌ Exceeding agreed scope
❌ Not reporting findings responsibly
❌ Sharing vulnerabilities publicly before fix
❌ Using findings for personal gain
❌ Ignoring legal boundaries
```

### Operational Mistakes

```
❌ Not documenting activities
❌ Poor time management
❌ Not backing up data
❌ Inadequate logging
❌ Not having rollback plan
❌ Testing on production without approval
```

## 🚀 Advanced Techniques

### Chaining Vulnerabilities

```python
# Example: SSRF → Internal Port Scan → RCE
1. ssrf_detect(url="...")
2. Use SSRF to scan internal network
3. Find internal service
4. Exploit internal service for RCE
```

### Custom Workflows

```python
# Create custom workflow
workflow = Workflow(
    name="custom_test",
    description="Custom testing workflow"
)

# Add nodes
workflow.add_node(WorkflowNode(
    id="step1",
    tool="tech_detect",
    params={"url": "{target}"},
    next_nodes=["step2"]
))

# Execute
workflow.execute(initial_context={"target": "..."})
```

### Performance Optimization

```python
# Use caching
cache_stats()  # Check cache statistics
cache_cleanup()  # Clean expired cache

# Monitor performance
perf_summary()  # Get performance summary
perf_bottlenecks()  # Identify bottlenecks
```

## 📞 Getting Help

### When You're Stuck

```
1. Check tool documentation
2. Review error messages carefully
3. Search for similar issues
4. Ask in CTF community
5. Review this guide
6. Check SECURITY.md
```

### Community Resources

- GitHub Issues for bug reports
- Discord/Slack for discussions
- CTF writeups for learning
- Security blogs for techniques

---

## 📋 Quick Reference

### Essential Commands

```bash
# Information Gathering
tech_detect(url="...")
port_scan(target="...")
subdomain_bruteforce(domain="...")

# Vulnerability Detection
vuln_check(url="...")
sqli_detect(url="...")
xss_detect(url="...")

# Automated Testing
auto_pentest(target="...")
smart_pentest(target="...")
vulnerability_pipeline(target="...")

# Exploitation (Authorization Required)
exploit_sqli_extract(url="...", param="...")
lateral_smb_exec(target="...", username="...", password="...")
```

### Risk Level Quick Check

```
🟢 Information gathering → Safe
🟡 Vulnerability detection → Requires authorization
🟠 Exploitation → Explicit authorization
🔴 RCE/Deserialization → Written authorization
```

---

**Remember: Always prioritize safety, legality, and ethics in your security testing activities.**

Last updated: 2026-01-12
