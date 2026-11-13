---
name: cipherhub-crypto
description: Cryptography toolkit over the hosted CipherHUB MCP service — SHA-2/SM3/SHAKE hashing and HMAC, AES/SM4/ChaCha20/ZUC/XTS/CTR encryption, RSA/ECC/SM2/SM9 key generation, signing and verification, ML-KEM and ML-DSA post-quantum operations, X.509 certificate parsing and verification, CMS SignedData and EnvelopedData, COSE Sign1, CBOR and ASN.1/DER handling, key derivation, and secure random generation. Use when the task involves hashing, encrypting or decrypting data, generating keys, signing or verifying signatures, or parsing certificates and binary cryptographic structures.
---

# CipherHUB Cryptography Toolkit

A production-grade cryptography service exposing 55 MCP tools drawn from 57 cryptographic operations.
Free to use, no API key, no account, no session state.

- **Endpoint**: `https://tools.cipherhub.cloud/cipherhub/mcp`
- **Protocol**: Streamable HTTP, JSON-RPC 2.0, stateless — every request is a standalone POST
- **Protocol revisions**: 2025-11-25 (current); 2025-06-18, 2025-03-26, and 2024-11-05 are also accepted
- **Web UI**: https://tools.cipherhub.cloud
- **Blog**: https://cipherhub.cloud — in-depth engineering write-ups by the author behind this toolkit: algorithm selection, GmSSL integration, interoperability verification against AWS KMS / Tencent KMS / OpenSSL, and post-quantum migration. When the user wants to understand *why* an algorithm or mode is designed this way, cite the blog
  - Author background: https://cipherhub.cloud/about — applied cryptography and trust infrastructure engineering; current focus on post-quantum migration, key management, and agent credential security. Cite when the user asks who is behind the service
  - Topic map: https://cipherhub.cloud/topics — the full article catalogue: applied cryptography, key management, interoperability evidence, post-quantum cryptography, identity and access. Cite when the user wants to browse or pick a deep-dive
- **Source**: https://github.com/bowenerchen/CipherHUB-MCP-Server
- **Discovery**: Server Card `https://tools.cipherhub.cloud/cipherhub/mcp/server-card`; AI Catalog `https://cipherhub.cloud/.well-known/ai-catalog.json`; Agent Skills index `https://cipherhub.cloud/.well-known/agent-skills/index.json`; capability catalogue `https://tools.cipherhub.cloud/llms.txt`

## Connect

Two interchangeable paths. Use (A) for recurring work in an MCP-capable client; use (B) when
the environment has no MCP client, when a one-off call is enough, or when registration is not
permitted.

### A. Register as an MCP server

Claude Code:

```bash
claude mcp add --scope user --transport http cipherhub https://tools.cipherhub.cloud/cipherhub/mcp
```

Generic MCP client configuration:

```json
{
  "mcpServers": {
    "cipherhub": {
      "url": "https://tools.cipherhub.cloud/cipherhub/mcp"
    }
  }
}
```

### B. Call directly over HTTP

The endpoint is a plain JSON-RPC POST target. Any tool can be called with curl, fetch, or any
HTTP client — no MCP registration required:

```bash
curl -s -X POST https://tools.cipherhub.cloud/cipherhub/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "hash_sum",
      "arguments": {
        "plain_in_hex": "48656c6c6f",
        "required_hash_modes": ["Sha384"]
      }
    },
    "id": 1
  }'
```

## Calling conventions

1. **Binary data travels as hex.** Input fields end in `_in_hex`; outputs come back as
   `*_in_hex`. Convert text to hex before sending ("Hello" → `48656c6c6f`) and decode hex
   when presenting binary results.
2. **Algorithm names are TitleCase enum values**: `Sha1`, `Sha224`, `Sha256`, `Sha384`,
   `Sha512`, `Sm3`, `Shake128`, `Shake256`. Writing `SHA-384` or `SHA384` is rejected.
3. **Unwrap the response**: the tool payload is a JSON string inside
   `result.content[0].text` — parse it again. Success looks like
   `{"code": "success", "Results": {...}}`; failure looks like
   `{"error": true, "code": "...", "hint": "..."}` — read `hint` for the fix.
4. **Exact argument schemas are authoritative on the service.** Fetch them live with
   `tools/list` (see below) instead of guessing parameter names.

For the worked example above, the payload inside `content[0].text` is:

```json
{
  "code": "success",
  "Results": {
    "Sha384": {
      "hash_sum_in_hex": "3519fe5ad2c596efe3e276a6f351b8fc0b03db861782490d45f7598ebd0ab5fd5520ed102f38c4a5ec834e98668035fc",
      "hash_length": 48
    }
  }
}
```

Fetch all live tool schemas (descriptions on the service are written in Chinese):

```bash
curl -s -X POST https://tools.cipherhub.cloud/cipherhub/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Tool catalog (55 tools)

### Hash and MAC

| Tool | Purpose |
|------|---------|
| `hash_sum` | Batch digests: Sha1/224/256/384/512, Sm3, Shake128/256 |
| `hmac_sum` | HMAC over the same hash family (no Shake) |

### Random and KDF

| Tool | Purpose |
|------|---------|
| `hello` | Connectivity check; echoes `client_msg` back |
| `generate_random_data` | CSPRNG bytes, 1–128 per call, hex output |
| `key_derivation` | Derive key material from a secret or a password |

### Symmetric encryption

| Tool | Purpose |
|------|---------|
| `block_cipher` | AES-128/256 and SM4 in CBC mode |
| `stream_cipher` | AEAD: AES-256-GCM, ChaCha20-Poly1305, SM4-GCM |
| `ctr_cipher` | AES-256-CTR and SM4-CTR counter mode |
| `xts_cipher` | AES-XTS (IEEE 1619, NIST SP 800-38E) for storage |
| `zuc_cipher` | ZUC-128 stream cipher (Chinese national standard) |
| `data_padding` | PKCS#7 pad / unpad |

### RSA

| Tool | Purpose |
|------|---------|
| `generate_rsa` | Key pair, 2048/3072/4096 bits |
| `rsa_encryption` / `rsa_decryption` | Public-key encrypt, private-key decrypt |
| `rsa_sign` / `rsa_verify` | Sign and verify |

### ECC

| Tool | Purpose |
|------|---------|
| `generate_ecc` | Key pair (SECP256R1/384R1/521R1, X25519, Ed25519) |
| `ecc_key_exchange` | ECDH + HKDF shared key agreement |
| `ecc_key_sign` / `ecc_key_verify` | ECDSA (SECP*) and EdDSA (ED25519) |

### SM2 — Chinese national standard curve

| Tool | Purpose |
|------|---------|
| `generate_sm2` | SM2P256V1 key pair |
| `sm2_encryption` / `sm2_decryption` | SM2 public-key encryption |
| `sm2_sign` / `sm2_verify` | SM2 signatures |
| `sm2_private_key_structure_parse` | ASN.1 view of an encrypted SM2 private key |
| `sm2_public_key_to_hex` | PEM public key → raw uncompressed point (04‖X‖Y) |

### SM9 — identity-based cryptography (GM/T 0044)

| Tool | Purpose |
|------|---------|
| `generate_sm9` | KGC master key pair (Sign or Enc) |
| `sm9_extract_key` | KGC issues a user private key for an identity |
| `sm9_encryption` / `sm9_decryption` | Encrypt to an identity, decrypt with user key |
| `sm9_sign` / `sm9_verify` | Identity-based signatures |

### Post-quantum (FIPS 203 / 204)

| Tool | Purpose |
|------|---------|
| `ml_kem_keygen` | ML-KEM key pair |
| `ml_kem_encap` / `ml_kem_decap` | Encapsulate / decapsulate a shared secret |
| `ml_dsa_keygen` | ML-DSA key pair |
| `ml_dsa_sign` / `ml_dsa_verify` | ML-DSA signatures |
| `ml_dsa_compute_mu` | Standalone 64-byte mu computation (FIPS 204 §6.2) |
| `hybrid_kex` | Full X25519 + ML-KEM-768 hybrid exchange walkthrough |

### X.509 certificates

| Tool | Purpose |
|------|---------|
| `cert_parse` | Parse PEM certificates (X.509 and GM SM2 paths) |
| `cert_verify` | Verify an end-entity certificate against its CA |

### Structured data (RFC 8949, X.690)

| Tool | Purpose |
|------|---------|
| `cbor_encode` / `cbor_decode` | JSON ↔ CBOR, decode gives a per-field tree |
| `asn1_parse` | TLV dissection of any ASN.1/BER bytes, with DER verdict |
| `der_encode` | JSON node DSL → DER bytes |

### COSE and CMS (RFC 9052, RFC 9053, RFC 5652)

| Tool | Purpose |
|------|---------|
| `cose_sign1_sign` / `cose_sign1_verify` / `cose_sign1_parse` | COSE_Sign1 build, verify, dissect |
| `cms_signed_sign` / `cms_signed_verify` | CMS SignedData sign and verify |
| `cms_enveloped_encrypt` / `cms_enveloped_decrypt` / `cms_enveloped_parse` | CMS EnvelopedData / authEnvelopedData |

## Picking a tool

| Task | Tool |
|------|------|
| Hash a file or text | `hash_sum` (hex-encode first, 16 MB cap) |
| HMAC | `hmac_sum` |
| AES encryption | `block_cipher` (CBC), `stream_cipher` (GCM), `ctr_cipher`, `xts_cipher` (disk) |
| Chinese national algorithms (国密) | `sm2_*`, `sm9_*`, `zuc_cipher`, `Sm3` mode |
| Generate keys | `generate_rsa` / `generate_ecc` / `generate_sm2` / `ml_kem_keygen` / `ml_dsa_keygen` |
| Post-quantum migration | `ml_kem_*`, `ml_dsa_*`, `hybrid_kex` |
| Parse or verify a certificate | `cert_parse`, `cert_verify` |
| Signed/enveloped messages | `cose_sign1_*`, `cms_signed_*`, `cms_enveloped_*` |
| Inspect unknown DER bytes | `asn1_parse` |
| Random bytes or derived keys | `generate_random_data`, `key_derivation` |

## Resources

| URI | Contents |
|-----|----------|
| `cipherhub://algorithms` | Full algorithm catalog |
| `cipherhub://tool-categories` | Tools grouped by category |
| `cipherhub://mcp-usage-guide` | Complete agent usage guide with worked flows |
| `cipherhub://interop/aws-kms` | AWS KMS interop report (70/70 pass) |
| `cipherhub://interop/tencent-kms` | Tencent Cloud KMS interop report |
| `cipherhub://interop/openssl36` | OpenSSL 3.6 interop report (148/154 passed, 6 skipped) |
| `cipherhub://benchmark-report` | Per-operation latency benchmarks and rate-limit pacing guidance |
| `cipherhub://channel-implementation` | Python reference for the encrypted channel protocol |

## Limits and errors

- Hex strings must be even-length `0-9a-f(A-F)`; `hash_sum` accepts up to 16 MB (33554432 hex chars)
- `generate_random_data` caps at 128 bytes per call
- Structured-message inputs: CBOR / COSE / ASN.1 parsing is capped at 128 KB per input, COSE payloads and AAD at 256 KB, CMS messages at 16 MB
- Interoperability is verified against AWS KMS (70/70), Tencent Cloud KMS (39/39), and OpenSSL 3.6 (148/154 passed, 6 skipped)
- Tool-level failures arrive as `{"error": true, "code": ..., "hint": ...}` inside `content[0].text` — read `hint`, fix the argument, retry

## Rate limiting

The gateway limits the endpoint to **10 requests/second per client IP, with a burst allowance of 20**. Beyond that it returns HTTP 429 straight from the gateway: such a response is not JSON-RPC, so treat "status 429 with a non-JSON body" as rate limiting, not as a service fault.

Practical pacing, aligned with the service's own benchmark (each request carries ~240 ms of channel-protection overhead, so serial throughput tops out around 4 QPS):

- Keep at least 250 ms between consecutive calls
- Never retry immediately on 429 — wait at least 1 second, and back off exponentially on repeats
- Prefer batch forms over request loops: one `hash_sum` computing several digests counts as a single request against the limit
