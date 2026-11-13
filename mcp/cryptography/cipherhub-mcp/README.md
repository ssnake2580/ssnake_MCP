# CipherHUB MCP Server

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://tools.cipherhub.cloud/cipherhub/mcp)
[![License](https://img.shields.io/badge/License-MIT-green)](https://opensource.org/license/mit)
[![Tools](https://img.shields.io/badge/Tools-55-orange)](#tools)
[![Blog](https://img.shields.io/badge/Blog-cipherhub.cloud-8A2BE2)](https://cipherhub.cloud)

<a href="https://mcprush.com/to/cipherhub-cryptography-toolkit-mcp?ref=badge"><img width="380" height="200" src="https://mcprush.com/badge/cipherhub-cryptography-toolkit-mcp/card.svg" alt="CipherHUB Cryptography Toolkit MCP server" /></a>

Production-grade cryptography toolkit exposing **55 MCP tools** drawn from **57 cryptographic operations** available through the REST API and Web UI. Built and operated by [Yang X. CHEN](https://cipherhub.cloud) — the engineering decisions behind this service are written up on the blog at [cipherhub.cloud](https://cipherhub.cloud).

## Overview

CipherHUB enables AI agents to perform cryptographic operations without implementing algorithms themselves. It covers:

- **Classical Algorithms**: AES (CBC/GCM/CTR/XTS), ChaCha20-Poly1305, RSA, ECC (SECP256R1/384R1/521R1, X25519, Ed25519), SHA-2 family, SHAKE
- **Chinese National Standards (国密)**: SM2, SM3, SM4, ZUC-128, SM9 identity-based cryptography (GM/T 0044)
- **Post-Quantum Cryptography**: ML-KEM (FIPS 203), ML-DSA (FIPS 204), X25519+ML-KEM-768 Hybrid KEX
- **Certificates & Structured Crypto Messages**: X.509 parsing and verification, CMS SignedData and EnvelopedData (RFC 5652), COSE_Sign1 (RFC 9052), CBOR (RFC 8949), ASN.1/DER dissection
- **Interoperability, verified against three independent stacks**: AWS KMS (70/70), Tencent Cloud KMS (39/39), OpenSSL 3.6 (148/154 — 6 skipped, 0 failed)

## Quick Start

### MCP Endpoint

```
https://tools.cipherhub.cloud/cipherhub/mcp
```

### Protocol

- **Type**: Streamable HTTP
- **Protocol revisions**: 2025-11-25 (current); 2025-06-18, 2025-03-26, and 2024-11-05 are also accepted
- **Format**: JSON-RPC 2.0
- **Stateless**: No session, no handshake, no API key — every request is a standalone POST
- **Deployed version**: 1.13.2

### Example: Call a Tool

```bash
curl -X POST https://tools.cipherhub.cloud/cipherhub/mcp \
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

The tool payload is a JSON string inside `result.content[0].text`:

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

Note the conventions: binary input and output travel as hex strings (`*_in_hex` fields), and algorithm names use TitleCase enum values (`Sha384`, `Sm3`) — `SHA-384` is rejected by the schema.

More runnable examples: [examples/curl_examples.sh](examples/curl_examples.sh) and [examples/quickstart.py](examples/quickstart.py) (Python stdlib only).

## Discovery

Machine-readable metadata for agents, crawlers, and registries:

| Resource | Location |
|----------|----------|
| MCP Server Card | `https://tools.cipherhub.cloud/cipherhub/mcp/server-card` (`application/mcp-server-card+json`) |
| AI Catalog | `https://cipherhub.cloud/.well-known/ai-catalog.json` |
| Agent Skills index | `https://cipherhub.cloud/.well-known/agent-skills/index.json` |
| Capability description | `https://tools.cipherhub.cloud/llms.txt` |
| OpenAPI 3.1 | `https://tools.cipherhub.cloud/.well-known/openapi.yaml` |
| Registry manifest | [`server.json`](server.json) — namespace `io.github.bowenerchen/cipherhub` |

The Server Card publishes identity, version, transport, and supported protocol revisions. It does not enumerate tools, prompts, or resources; fetch those at runtime with `tools/list`, `prompts/list`, and `resources/list`.

## Tools

### Hash & MAC

| Tool | Description |
|------|-------------|
| `hash_sum` | Batch digests: SHA-1/224/256/384/512, SM3, SHAKE128/256 |
| `hmac_sum` | HMAC over the same hash family (SHAKE excluded) |

### Key Derivation

| Tool | Description |
|------|-------------|
| `key_derivation` | HKDF (RFC 5869), SM3-KDF (GB/T 32918), PBKDF2-SM3 (RFC 8018) |

### Random & Utility

| Tool | Description |
|------|-------------|
| `hello` | Connectivity check; echoes `client_msg` back |
| `generate_random_data` | CSPRNG bytes (1–128 per call) |
| `data_padding` | PKCS#7 pad / unpad |

### Symmetric Encryption

| Tool | Description |
|------|-------------|
| `block_cipher` | AES-128/256-CBC, SM4-CBC |
| `stream_cipher` | AEAD: AES-256-GCM, ChaCha20-Poly1305, SM4-GCM |
| `ctr_cipher` | AES-256-CTR, SM4-CTR counter mode |
| `xts_cipher` | AES-XTS (IEEE 1619 / NIST SP 800-38E) |
| `zuc_cipher` | ZUC-128 stream cipher (3GPP, 4G/5G mobile communications) |

### RSA

| Tool | Description |
|------|-------------|
| `generate_rsa` | Generate RSA key pair (2048/3072/4096 bits) |
| `rsa_encryption` / `rsa_decryption` | RSA public-key encryption, private-key decryption |
| `rsa_sign` / `rsa_verify` | RSA signatures |

### ECC

| Tool | Description |
|------|-------------|
| `generate_ecc` | Generate ECC key pair (SECP256R1/384R1/521R1, X25519, Ed25519) |
| `ecc_key_exchange` | ECDH + HKDF key agreement |
| `ecc_key_sign` / `ecc_key_verify` | ECDSA (SECP*) and EdDSA (ED25519) signatures |

### SM2 — Chinese National Standard Curve

| Tool | Description |
|------|-------------|
| `generate_sm2` | Generate SM2 (SM2P256V1) key pair |
| `sm2_encryption` / `sm2_decryption` | SM2 public-key encryption |
| `sm2_sign` / `sm2_verify` | SM2 signatures |
| `sm2_private_key_structure_parse` | ASN.1 view of an encrypted SM2 private key |
| `sm2_public_key_to_hex` | PEM public key → raw uncompressed point (04‖X‖Y) |

### SM9 — Identity-Based Cryptography (GM/T 0044)

| Tool | Description |
|------|-------------|
| `generate_sm9` | Generate KGC master key pair (Sign or Enc) |
| `sm9_extract_key` | KGC issues a user private key for an identity |
| `sm9_encryption` / `sm9_decryption` | Encrypt to an identity, decrypt with user key |
| `sm9_sign` / `sm9_verify` | Identity-based signatures |

### Post-Quantum Cryptography

| Tool | Description |
|------|-------------|
| `ml_kem_keygen` | ML-KEM key generation (FIPS 203) |
| `ml_kem_encap` / `ml_kem_decap` | ML-KEM encapsulation / decapsulation |
| `ml_dsa_keygen` | ML-DSA key generation (FIPS 204) |
| `ml_dsa_sign` / `ml_dsa_verify` | ML-DSA signatures |
| `ml_dsa_compute_mu` | Standalone 64-byte mu computation (FIPS 204 §6.2) |
| `hybrid_kex` | X25519 + ML-KEM-768 hybrid key exchange walkthrough |

### X.509 Certificates

| Tool | Description |
|------|-------------|
| `cert_parse` | Parse PEM certificates (X.509 and GM SM2 dual paths) |
| `cert_verify` | Verify an end-entity certificate against its CA |

### Structured Data

| Tool | Description |
|------|-------------|
| `cbor_encode` / `cbor_decode` | JSON ↔ CBOR (RFC 8949), decode gives a per-field tree |
| `asn1_parse` | TLV dissection of any ASN.1/BER bytes, with DER verdict (X.690) |
| `der_encode` | JSON node DSL → DER bytes (X.690) |

### COSE & CMS

| Tool | Description |
|------|-------------|
| `cose_sign1_sign` / `cose_sign1_verify` / `cose_sign1_parse` | COSE_Sign1 build, verify, dissect (RFC 9052/9053) |
| `cms_signed_sign` / `cms_signed_verify` | CMS SignedData sign and verify (RFC 5652 §5) |
| `cms_enveloped_encrypt` / `cms_enveloped_decrypt` / `cms_enveloped_parse` | CMS EnvelopedData / authEnvelopedData (RFC 5652 §6, RFC 5083) |

## Prompts

Six ready-made agent workflows served via `prompts/list`:

| Prompt | Purpose |
|--------|---------|
| `pqc_migration_assessment` | Assess post-quantum migration readiness |
| `algorithm_recommendation` | Algorithm choices by use case |
| `e2e_encryption_flow` | Full end-to-end encryption walkthrough |
| `sign_verify_workflow` | Generate key pair, sign, then verify |
| `verify_key_pair` | Check that a key pair matches (RSA, ECC, SM2) |
| `hybrid_kex_demo` | X25519 + ML-KEM-768 hybrid exchange demo |

## Resources

| URI | Description |
|-----|-------------|
| `cipherhub://algorithms` | Complete algorithm catalog |
| `cipherhub://tool-categories` | Tool categorization |
| `cipherhub://mcp-usage-guide` | Complete guide for AI agents using these MCP tools |
| `cipherhub://interop/aws-kms` | AWS KMS interoperability report (70/70 passed) |
| `cipherhub://interop/tencent-kms` | Tencent Cloud KMS interoperability report (39/39 passed) |
| `cipherhub://interop/openssl36` | OpenSSL 3.6 interoperability report (148/154 passed) |
| `cipherhub://benchmark-report` | Performance benchmarks for all operations |
| `cipherhub://channel-implementation` | SDK channel protocol reference implementation |

## Agent Skill

A ready-to-use Agent Skills package lives in [`skills/cipherhub-crypto/`](skills/cipherhub-crypto/SKILL.md). It teaches any SKILL.md-compatible agent (Claude Code and others) when to reach for CipherHUB and how to call it — either by registering the MCP server or with plain HTTP.

Install with the skills CLI:

```bash
npx skills add https://github.com/bowenerchen/CipherHUB-MCP-Server/tree/main/skills/cipherhub-crypto -g
```

Claude Code plugin marketplace:

```bash
claude plugin marketplace add bowenerchen/CipherHUB-MCP-Server
claude plugin install cipherhub-crypto@cipherhub
```

Manual copy:

```bash
cp -r skills/cipherhub-crypto ~/.claude/skills/
```

The blog serves a byte-identical copy at `https://cipherhub.cloud/.well-known/agent-skills/cipherhub-crypto/SKILL.md` and registers it in the Agent Skills index with a SHA-256 digest. Whenever `SKILL.md` changes, replace the copy under the blog repository's `static/.well-known/agent-skills/cipherhub-crypto/` and update the `digest` field in `static/.well-known/agent-skills/index.json` within the same edit, otherwise the published digest no longer matches the file.

## Client Configuration

### Claude Code

```bash
claude mcp add --scope user --transport http cipherhub https://tools.cipherhub.cloud/cipherhub/mcp
```

### Claude Desktop

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "cipherhub": {
      "url": "https://tools.cipherhub.cloud/cipherhub/mcp"
    }
  }
}
```

### Custom Client

Use any MCP-compatible client with the endpoint URL.

## API Documentation

- **Server Card**: https://tools.cipherhub.cloud/cipherhub/mcp/server-card
- **AI Catalog**: https://cipherhub.cloud/.well-known/ai-catalog.json
- **Agent Skills index**: https://cipherhub.cloud/.well-known/agent-skills/index.json
- **OpenAPI**: https://tools.cipherhub.cloud/.well-known/openapi.yaml
- **llms.txt**: https://tools.cipherhub.cloud/llms.txt
- **Registry manifest**: [server.json](server.json)

## Web Interface

Interactive web UI available at: https://tools.cipherhub.cloud

## Author

**Yang X. CHEN**

- Blog: https://cipherhub.cloud — the engineering story behind this toolkit: algorithm choices, GmSSL integration, interoperability testing, and post-quantum migration notes
- GitHub: [@bowenerchen](https://github.com/bowenerchen)

## License

MIT License
