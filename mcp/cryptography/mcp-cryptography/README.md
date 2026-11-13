# mcp-cryptography

> MCP server exposing cryptography library functionality.

[![PyPI](https://img.shields.io/pypi/v/mcp-cryptography.svg)](https://pypi.org/project/mcp-cryptography/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-cryptography.svg)](https://pypi.org/project/mcp-cryptography/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

mcp-name: io.github.daedalus/mcp-cryptography

## Install

```bash
pip install mcp-cryptography
```

## Usage

```python
from mcp_cryptography import mcp

# Run the MCP server
if __name__ == "__main__":
    mcp.run()
```

## Available Tools

The server provides the following cryptographic tools:

### Key Generation
- `generate_symmetric_key` - Generate a Fernet symmetric key
- `generate_rsa_key` - Generate an RSA key pair
- `generate_x25519_key` - Generate an X25519 key pair

### Symmetric Encryption
- `fernet_encrypt` / `fernet_decrypt` - Fernet encryption
- `aes_encrypt` / `aes_decrypt` - AES encryption (CBC/GCM modes)

### Asymmetric Encryption
- `rsa_encrypt` / `rsa_decrypt` - RSA OAEP encryption
- `rsa_sign` / `rsa_verify` - RSA digital signatures

### Hashing
- `hash_sha256` - SHA-256 hash
- `hash_sha512` - SHA-512 hash
- `hash_sha1` - SHA-1 hash

### HMAC
- `hmac_sign` - Generate HMAC
- `hmac_verify` - Verify HMAC

### Key Derivation
- `pbkdf2_derive` - PBKDF2 key derivation
- `scrypt_derive` - Scrypt key derivation

### X.509 Certificates
- `generate_self_signed_cert` - Generate self-signed certificate
- `parse_certificate` - Parse X.509 certificate

### Utilities
- `generate_random_bytes` - Generate random bytes
- `generate_random_base64` - Generate random base64 bytes

## Development

```bash
git clone https://github.com/daedalus/mcp-cryptography.git
cd mcp-cryptography
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mcp_cryptography src/
```
