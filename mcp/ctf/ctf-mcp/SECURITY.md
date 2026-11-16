# Security Policy

## 🔒 Security Statement

CTF-MCP is a security tool collection designed for **authorized security testing only**. This project provides powerful tools that can be dangerous if misused.

## ⚠️ Critical Warning

**ONLY USE FOR:**
- ✅ Authorized penetration testing with written permission
- ✅ CTF (Capture The Flag) competitions
- ✅ Security research in controlled environments
- ✅ Educational purposes in lab environments
- ✅ Testing your own systems

**NEVER USE FOR:**
- ❌ Unauthorized access to systems
- ❌ Malicious attacks
- ❌ Data theft or destruction
- ❌ Denial of Service (DoS) attacks
- ❌ Any illegal activities

## 🎯 Risk Levels

CTF-MCP uses a four-level risk classification system:

### 🟢 LOW Risk
- Information gathering tools
- Encoding/decoding utilities
- Basic analysis tools
- No direct security impact

### 🟡 MEDIUM Risk
- Vulnerability detection tools
- Network scanning tools
- May trigger security alerts
- Requires authorization

### 🟠 HIGH Risk
- Exploitation tools
- Credential testing tools
- Can cause system changes
- Requires explicit authorization

### 🔴 CRITICAL Risk
- Remote Code Execution (RCE) payloads
- Deserialization exploits
- Command injection payloads
- Can cause severe damage
- **Requires written authorization**

## 📊 Security Audit Statistics

CTF-MCP has undergone a comprehensive security audit. All dangerous operations are protected with `@dangerous_operation` decorators that display warnings before execution.

### Overall Statistics
- **Total Security Decorators**: 33
- **Modules Audited**: 6
- **Risk Distribution**:
  - 🔴 CRITICAL: 14 tools
  - 🟠 HIGH: 13 tools
  - 🟡 MEDIUM: 6 tools
  - 🟢 LOW: All other tools (no decorator needed)

### Module Breakdown

| Module | Total Decorators | CRITICAL | HIGH | MEDIUM |
|--------|-----------------|----------|------|--------|
| **pwn.py** | 9 | 7 | 2 | 0 |
| **web.py** | 17 | 5 | 10 | 2 |
| **crypto.py** | 6 | 0 | 1 | 5 |
| **reverse.py** | 1 | 0 | 0 | 1 |
| **misc.py** | 0 | 0 | 0 | 0 |
| **forensics.py** | 0 | 0 | 0 | 0 |
| **Total** | **33** | **14** | **13** | **6** |

## 🚨 Critical Risk Tools

The following tools are classified as **CRITICAL** risk and will display security warnings before use:

### Binary Exploitation (pwn.py) - 7 tools
- `shellcode_gen` - Generate executable shellcode for various architectures
- `rop_chain_builder` - Build ROP chains for code execution
- `ret2libc` - ret2libc exploitation technique
- `ret2csu` - ret2csu universal gadget exploitation
- `heap_tcache` - Tcache poisoning heap exploitation
- `heap_fastbin` - Fastbin dup heap exploitation
- `heap_house_of_force` - House of Force heap exploitation
- `heap_house_of_spirit` - House of Spirit heap exploitation

### Web Exploitation (web.py) - 7 tools
- `ssti_payloads` - Server-Side Template Injection (SSTI) payloads for RCE
- `pickle_payload` - Python pickle deserialization RCE payloads
- `php_unserialize_exploit` - PHP unserialize exploits with gadget chains
- `java_deserialize` - Java deserialization payloads (ysoserial)
- `nodejs_deserialize` - Node.js deserialization RCE payloads
- `yaml_deserialize` - YAML deserialization RCE payloads
- `cmd_injection` - OS command injection payloads
- `cmd_blind` - Blind command injection techniques (time-based, OOB)

## 🟠 High Risk Tools

The following tools are classified as **HIGH** risk:

### Binary Exploitation (pwn.py) - 2 tools
- `shellcode_encode` - Encode shellcode to avoid detection and bypass filters

### Web Exploitation (web.py) - 10 tools
- `sql_payloads` - SQL injection payloads for data extraction/modification
- `lfi_payloads` - Local File Inclusion payloads for file read and RCE
- `rfi_payloads` - Remote File Inclusion payloads for RCE
- `ssrf_payloads` - Server-Side Request Forgery payloads for internal access
- `xxe_payloads` - XXE injection payloads for file read and SSRF
- `xxe_oob` - Out-of-band XXE data exfiltration techniques
- `xxe_blind` - Blind XXE exploitation techniques
- `http_smuggling` - HTTP request smuggling for security bypass

### Cryptography (crypto.py) - 1 tool
- `hash_crack` - Password hash cracking with wordlists

## 🟡 Medium Risk Tools

The following tools are classified as **MEDIUM** risk:

### Web Exploitation (web.py) - 2 tools
- `xss_payloads` - Cross-Site Scripting payloads for client-side attacks

### Cryptography (crypto.py) - 5 tools
- `xor_single_byte_bruteforce` - Brute force single-byte XOR encryption
- `des_encrypt` - DES encryption (weak algorithm)
- `des_decrypt` - DES decryption
- `rc4` - RC4 stream cipher (deprecated algorithm)
- `xor_repeating_key` - XOR with repeating key encryption

### Reverse Engineering (reverse.py) - 1 tool
- `asm` - Generate executable machine code from assembly instructions

## 🛡️ Security Best Practices

### 1. Authorization
```
✓ Always obtain written authorization before testing
✓ Document the scope of testing
✓ Keep authorization documents accessible
✓ Respect the agreed-upon scope and timeline
```

### 2. Environment Isolation
```
✓ Use isolated lab environments for testing
✓ Never test on production systems without approval
✓ Use virtual machines or containers
✓ Implement network segmentation
```

### 3. Data Protection
```
✓ Handle discovered vulnerabilities responsibly
✓ Protect sensitive data found during testing
✓ Follow responsible disclosure practices
✓ Encrypt test reports and findings
```

### 4. Tool Usage
```
✓ Read tool descriptions before use
✓ Understand the risk level of each tool
✓ Start with LOW risk tools for reconnaissance
✓ Only use CRITICAL tools when necessary
✓ Monitor and log all testing activities
```

### 5. Legal Compliance
```
✓ Comply with local laws and regulations
✓ Respect computer fraud and abuse laws
✓ Follow industry standards (OWASP, PTES, etc.)
✓ Maintain professional ethics
```

## 📋 Pre-Testing Checklist

Before using CTF-MCP tools, verify:

- [ ] I have written authorization to test the target system
- [ ] I understand the scope and limitations of testing
- [ ] I am using an isolated test environment OR have production approval
- [ ] I have reviewed the risk levels of tools I plan to use
- [ ] I have a plan for responsible disclosure of findings
- [ ] I understand the legal implications in my jurisdiction
- [ ] I have proper logging and monitoring in place
- [ ] I have a rollback plan if something goes wrong

## 🔐 Security Features

CTF-MCP includes built-in security features:

### 1. Risk Warnings
All CRITICAL risk tools display warnings before execution:
```
🔴 CRITICAL RISK - Use with extreme caution
This payload can be dangerous. Only use for:
- Authorized penetration testing
- CTF competitions
- Security research
- Educational purposes
```

### 2. Input Validation
- Path traversal protection
- Command injection prevention
- SQL injection prevention in tool parameters
- File size and type validation

### 3. Timeout Protection
- Automatic timeout for long-running operations
- Prevents resource exhaustion
- Configurable timeout limits

### 4. Audit Logging
- Tool usage logging (when enabled)
- Timestamp and user tracking
- Command history

## 🐛 Reporting Security Issues

### Found a vulnerability in CTF-MCP?

If you discover a security vulnerability in CTF-MCP itself:

1. **DO NOT** open a public GitHub issue
2. Email the maintainers privately (see README for contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you on:
- Confirming the vulnerability
- Developing a fix
- Coordinating disclosure
- Crediting your discovery (if desired)

### Responsible Disclosure Timeline
- Day 0: Report received
- Day 1-2: Initial response and confirmation
- Day 3-14: Fix development and testing
- Day 15-30: Coordinated disclosure
- Day 30+: Public disclosure (if not resolved)

## ⚖️ Legal Disclaimer

**IMPORTANT LEGAL NOTICE:**

The developers and contributors of CTF-MCP:
- Provide this tool "AS IS" without warranty
- Are NOT responsible for misuse of these tools
- Do NOT condone illegal activities
- Assume NO liability for damages caused by tool misuse

**Users are solely responsible for:**
- Obtaining proper authorization
- Complying with applicable laws
- Any consequences of tool usage
- Damages caused by unauthorized testing

**By using CTF-MCP, you agree to:**
- Use tools only for authorized purposes
- Accept full responsibility for your actions
- Comply with all applicable laws and regulations
- Indemnify the developers from any claims

---

## 📚 Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Responsible Disclosure Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)

## 📞 Contact

For security-related questions or concerns:
- GitHub Issues (for general questions): [CTF-MCP Issues](https://github.com/yourusername/CTF-MCP/issues)
- Security vulnerabilities: [Contact maintainers privately]

---

**Remember: With great power comes great responsibility. Use CTF-MCP ethically and legally.**

Last updated: 2026-01-12
