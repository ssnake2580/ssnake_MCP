import base64

import pytest
from cryptography.fernet import InvalidToken

from mcp_cryptography.mcp import (
    aes_decrypt,
    aes_encrypt,
    fernet_decrypt,
    fernet_encrypt,
    generate_random_base64,
    generate_random_bytes,
    generate_rsa_key,
    generate_self_signed_cert,
    generate_symmetric_key,
    generate_x25519_key,
    hash_sha1,
    hash_sha256,
    hash_sha512,
    hmac_sign,
    hmac_verify,
    parse_certificate,
    pbkdf2_derive,
    rsa_decrypt,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
    scrypt_derive,
)


class TestGenerateSymmetricKey:
    def test_generates_valid_key(self):
        key = generate_symmetric_key()
        assert isinstance(key, str)
        assert len(key) == 44

    def test_keys_are_unique(self):
        key1 = generate_symmetric_key()
        key2 = generate_symmetric_key()
        assert key1 != key2


class TestGenerateRsaKey:
    def test_generates_valid_key_pair(self):
        keys = generate_rsa_key()
        assert "public_key" in keys
        assert "private_key" in keys
        assert "-----BEGIN PUBLIC KEY-----" in keys["public_key"]
        assert "-----BEGIN PRIVATE KEY-----" in keys["private_key"]

    def test_custom_key_size(self):
        keys = generate_rsa_key(key_size=4096)
        assert "private_key" in keys

    def test_invalid_key_size(self):
        with pytest.raises(ValueError, match="key_size must be at least"):
            generate_rsa_key(key_size=1024)


class TestGenerateX25519Key:
    def test_generates_valid_key_pair(self):
        keys = generate_x25519_key()
        assert "public_key" in keys
        assert "private_key" in keys


class TestFernetEncrypt:
    def test_encrypt_decrypt_roundtrip(self):
        key = generate_symmetric_key()
        plaintext = "Hello, World!"
        ciphertext = fernet_encrypt(key, plaintext)
        decrypted = fernet_decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_different_ciphertexts(self):
        key = generate_symmetric_key()
        ciphertext1 = fernet_encrypt(key, "Hello")
        ciphertext2 = fernet_encrypt(key, "Hello")
        assert ciphertext1 != ciphertext2


class TestFernetDecrypt:
    def test_invalid_token_raises(self):
        key = generate_symmetric_key()
        with pytest.raises(InvalidToken):
            fernet_decrypt(key, "invalid")


class TestAesEncrypt:
    def test_encrypt_cbc_mode(self):
        key = "aabbccddeeff00112233445566778899"  # 16 bytes hex = 32 chars
        result = aes_encrypt(key, "Hello, World!", mode="CBC")
        assert "ciphertext" in result
        assert "iv" in result

    def test_invalid_key_size(self):
        key = "aabbcc"  # too short
        with pytest.raises(ValueError, match="Key must be"):
            aes_encrypt(key, "data")

    def test_invalid_mode(self):
        key = "aabbccddeeff00112233445566778899"
        with pytest.raises(ValueError, match="Mode must be"):
            aes_encrypt(key, "data", mode="INVALID")


class TestAesDecrypt:
    def test_encrypt_decrypt_roundtrip_cbc(self):
        key = "aabbccddeeff00112233445566778899"
        result = aes_encrypt(key, "Hello, World!", mode="CBC")
        decrypted = aes_decrypt(key, result["ciphertext"], result["iv"], mode="CBC")
        assert decrypted == "Hello, World!"


class TestRsaEncrypt:
    def test_encrypt_decrypt_roundtrip(self):
        keys = generate_rsa_key()
        plaintext = "Hello, World!"
        ciphertext = rsa_encrypt(keys["public_key"], plaintext)
        decrypted = rsa_decrypt(keys["private_key"], ciphertext)
        assert decrypted == plaintext


class TestRsaSign:
    def test_sign_verify_roundtrip(self):
        keys = generate_rsa_key()
        data = "Message to sign"
        signature = rsa_sign(keys["private_key"], data)
        assert rsa_verify(keys["public_key"], data, signature) is True

    def test_invalid_signature_returns_false(self):
        keys = generate_rsa_key()
        data = "Message to sign"
        signature = rsa_sign(keys["private_key"], data)
        assert rsa_verify(keys["public_key"], "wrong data", signature) is False


class TestHashing:
    def test_sha256(self):
        result = hash_sha256("Hello, World!")
        assert (
            result == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        )

    def test_sha512(self):
        result = hash_sha512("Hello")
        assert isinstance(result, str)

    def test_sha1(self):
        result = hash_sha1("Hello")
        assert isinstance(result, str)


class TestHmac:
    def test_sign_verify_roundtrip(self):
        key = "aabbccdd"
        data = "message"
        hmac_value = hmac_sign(key, data)
        assert hmac_verify(key, data, hmac_value) is True

    def test_invalid_hmac_returns_false(self):
        key = "aabbccdd"
        data = "message"
        hmac_value = hmac_sign(key, data)
        assert hmac_verify(key, "wrong data", hmac_value) is False


class TestKeyDerivation:
    def test_pbkdf2_derive(self):
        result = pbkdf2_derive("password")
        assert "derived_key" in result
        assert "salt" in result
        assert len(result["derived_key"]) == 64

    def test_pbkdf2_with_salt(self):
        result = pbkdf2_derive("password", salt="aabbccdd")
        assert result["salt"] == "aabbccdd"

    def test_scrypt_derive(self):
        result = scrypt_derive("password")
        assert "derived_key" in result
        assert "salt" in result


class TestCertificates:
    def test_generate_self_signed_cert(self):
        result = generate_self_signed_cert("localhost")
        assert "certificate" in result
        assert "private_key" in result
        assert "-----BEGIN CERTIFICATE-----" in result["certificate"]

    def test_parse_certificate(self):
        cert_result = generate_self_signed_cert("example.com")
        parsed = parse_certificate(cert_result["certificate"])
        assert "subject" in parsed
        assert "issuer" in parsed
        assert parsed["subject"]["common_name"] == "example.com"


class TestRandom:
    def test_generate_random_bytes(self):
        result = generate_random_bytes(16)
        assert len(result) == 32  # hex encoded

    def test_generate_random_base64(self):
        result = generate_random_base64(16)
        decoded = base64.b64decode(result)
        assert len(decoded) == 16
