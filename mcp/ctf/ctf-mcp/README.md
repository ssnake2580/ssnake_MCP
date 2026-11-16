# CTF-MCP

---

A Model Context Protocol (MCP) server providing comprehensive tools for CTF (Capture The Flag) challenges.

## ⚠️ Security Warning

**IMPORTANT: This tool is designed for authorized security testing only.**

- ✅ **Authorized Use**: CTF competitions, penetration testing with written permission, security research, educational purposes
- ❌ **Prohibited Use**: Unauthorized access, malicious attacks, illegal activities

**Before using this tool:**
1. Ensure you have proper authorization
2. Read [SECURITY.md](SECURITY.md) for detailed security guidelines
3. Review [BEST_PRACTICES.md](BEST_PRACTICES.md) for usage recommendations
4. Understand the risk levels of tools you plan to use

**Risk Levels:**
- 🟢 LOW: Information gathering (safe)
- 🟡 MEDIUM: Vulnerability detection (requires authorization)
- 🟠 HIGH: Exploitation tools (explicit authorization required)
- 🔴 CRITICAL: RCE/Deserialization payloads (written authorization required)

**Security Audit Results:**
- 🔒 **Total Security Decorators**: 33 dangerous operations protected
- 🔴 **CRITICAL**: 14 tools (RCE, deserialization)
- 🟠 **HIGH**: 13 tools (exploitation, injection)
- 🟡 **MEDIUM**: 6 tools (weak crypto, code generation)
- See [SECURITY.md](SECURITY.md) for complete tool lists and descriptions

**By using CTF-MCP, you agree to use it responsibly and legally.**

### Features

#### Crypto (53 tools)
- Base encoding (Base64, Base32, Base58, Base85)
- Classical ciphers (Caesar, Vigenere, Atbash, Affine, Rail Fence, Playfair, Hill)
- XOR operations and analysis
- Modern crypto (AES, DES, RC4)
- Hash functions and cracking
- RSA attacks (Wiener, Hastad, Common Modulus, Franklin-Reiter)
- Frequency analysis

#### Web (46 tools)
- SQL Injection (Union, Error, Blind, Time-based)
- XSS payloads and filter bypass
- SSTI (Server-Side Template Injection)
- SSRF, XXE, Command Injection
- JWT attacks (None algorithm, Key confusion)
- Deserialization (PHP, Python Pickle, Java, Node.js)
- HTTP Smuggling, GraphQL, WebSocket
- OAuth, CORS, Cache Poisoning

#### Pwn (27 tools)
- Shellcode generation (x64/x86)
- Cyclic pattern creation and offset finding
- ROP gadgets and chain building
- Format string exploits
- Heap exploitation (Tcache, Fastbin, House of Force/Spirit)
- Stack pivot techniques
- SROP (Sigreturn-oriented programming)
- Libc database and one_gadget

#### Reverse
- Disassembly helpers
- String extraction
- Binary analysis

#### Forensics
- File carving
- Memory analysis
- Network forensics

#### Misc
- Encoding/decoding utilities
- Steganography helpers

### Installation

```bash
pip install -e .
```

### Usage

#### As MCP Server
```bash
ctf-mcp
```

#### In Python
```python
from ctf_mcp.tools.crypto import CryptoTools
from ctf_mcp.tools.web import WebTools
from ctf_mcp.tools.pwn import PwnTools

crypto = CryptoTools()
web = WebTools()
pwn = PwnTools()

# Generate SQL injection payloads
print(web.sql_payloads("mysql", "union"))

# Base64 encode
print(crypto.base64_encode("Hello CTF"))

# Create cyclic pattern
print(pwn.pattern_create(100))
```

### MCP Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "ctf-mcp": {
      "command": "ctf-mcp"
    }
  }
}
```

### Requirements

- Python 3.10+
- mcp >= 1.0.0

---

---

## Author

**Coff0xc**

## License

MIT License - see [LICENSE](LICENSE)
