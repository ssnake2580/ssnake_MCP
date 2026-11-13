# SPEC.md — mcp-cryptography

## Purpose

Create an MCP server that exposes all cryptographic functionality from the `cryptography` Python library. The server provides tools for symmetric encryption, asymmetric encryption, key generation, hashing, HMAC, key derivation, and X.509 certificate handling.

## Scope

- **In scope:**
  - Symmetric encryption (Fernet, AES)
  - Asymmetric encryption (RSA)
  - Key exchange (X25519)
  - Hashing (SHA family)
  - HMAC
  - Key derivation functions (PBKDF2, Scrypt)
  - X.509 certificate generation and parsing
  - Random bytes generation
- **Not out of scope:** This is not a comprehensive security audit tool or a key management system.

## Public API / Interface

### Tools (MCP Tools)

All tools use the `cryptography` library. Each tool is documented with examples.

#### Key Generation

1. `generate_symmetric_key` - Generate a Fernet symmetric key
   - Returns: Base64-encoded 32-byte key

2. `generate_rsa_key` - Generate an RSA key pair
   - Args: `key_size` (default 2048)
   - Returns: Dictionary with public and private keys (PEM format)

3. `generate_x25519_key` - Generate an X25519 key pair
   - Returns: Dictionary with public and private keys (PEM format)

#### Symmetric Encryption

4. `fernet_encrypt` - Encrypt data using Fernet
   - Args: `key` (base64), `data` (string)
   - Returns: Base64-encoded ciphertext

5. `fernet_decrypt` - Decrypt Fernet ciphertext
   - Args: `key` (base64), `ciphertext` (base64)
   - Returns: Decrypted string

6. `aes_encrypt` - Encrypt data using AES
   - Args: `key` (base64), `data` (bytes), `mode` (CBC/GCM, default CBC)
   - Returns: Dictionary with ciphertext and IV

7. `aes_decrypt` - Decrypt AES ciphertext
   - Args: `key` (base64), `ciphertext` (bytes), `iv` (bytes), `mode` (CBC/GCM)

#### Asymmetric Encryption

8. `rsa_encrypt` - RSA encryption (OAEP)
   - Args: `public_key` (PEM), `data` (bytes)
   - Returns: Encrypted data

9. `rsa_decrypt` - RSA decryption
   - Args: `private_key` (PEM), `ciphertext` (bytes)

10. `rsa_sign` - RSA digital signature
    - Args: `private_key` (PEM), `data` (bytes)
    - Returns: Signature

11. `rsa_verify` - Verify RSA signature
    - Args: `public_key` (PEM), `data` (bytes), `signature` (bytes)
    - Returns: Boolean

#### Hashing

12. `hash_sha256` - SHA-256 hash
    - Args: `data` (string or bytes)
    - Returns: Hex-encoded hash

13. `hash_sha512` - SHA-512 hash
    - Args: `data` (string or bytes)
    - Returns: Hex-encoded hash

14. `hash_sha1` - SHA-1 hash (deprecated but available)
    - Args: `data` (string or bytes)
    - Returns: Hex-encoded hash

#### HMAC

15. `hmac_sign` - Generate HMAC
    - Args: `key` (bytes), `data` (string or bytes), `algorithm` (sha256/sha512)
    - Returns: Hex-encoded HMAC

16. `hmac_verify` - Verify HMAC
    - Args: `key` (bytes), `data` (string or bytes), `hmac` (hex), `algorithm`
    - Returns: Boolean

#### Key Derivation

17. `pbkdf2_derive` - PBKDF2 key derivation
    - Args: `password` (string), `salt` (hex, optional), `iterations` (default 480000)
    - Returns: Dictionary with derived key (hex) and salt (hex)

18. `scrypt_derive` - Scrypt key derivation
    - Args: `password` (string), `salt` (hex, optional)
    - Returns: Dictionary with derived key (hex) and salt (hex)

#### X.509 Certificates

19. `generate_self_signed_cert` - Generate self-signed X.509 certificate
    - Args: `common_name`, `organization`, `days_valid` (default 365)
    - Returns: Dictionary with certificate (PEM) and private key (PEM)

20. `parse_certificate` - Parse X.509 certificate
    - Args: `certificate` (PEM)
    - Returns: Dictionary with subject, issuer, validity dates

#### Utilities

21. `generate_random_bytes` - Generate random bytes
    - Args: `length` (default 32)
    - Returns: Hex-encoded bytes

22. `generate_random_base64` - Generate random base64 bytes
    - Args: `length` (default 32)
    - Returns: Base64-encoded string

## Edge Cases

1. Empty data for hashing/encryption
2. Invalid key sizes for RSA
3. Expired certificates
4. Corrupted ciphertext (should raise appropriate errors)
5. Invalid PEM format
6. Salt not provided for KDF (should generate random salt)
7. Data too large for RSA encryption (max ~446 bytes for 4096-bit key)

## Performance & Constraints

- RSA encryption limited by key size (max ~key_size/8 - 66 bytes)
- Default PBKDF2 iterations: 480000 (OWASP recommended)
- AES key must be 16, 24, or 32 bytes for AES-128/192/256
