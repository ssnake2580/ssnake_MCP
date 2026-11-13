import base64
import os
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

import fastmcp
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding as asymmetric_padding,
)
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.padding import PKCS7 as pkcs7_padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )

mcp = fastmcp.FastMCP("mcp-cryptography")


@mcp.tool()
def generate_symmetric_key() -> str:
    """Generate a Fernet symmetric key.

    Returns:
        Base64-encoded 32-byte key suitable for Fernet encryption.

    Example:
        >>> key = generate_symmetric_key()
        >>> len(key)  # 44 characters base64 encoded
        44
    """
    key = Fernet.generate_key()
    return key.decode()


@mcp.tool()
def generate_rsa_key(key_size: int = 2048) -> dict[str, str]:
    """Generate an RSA key pair.

    Args:
        key_size: Key size in bits (default 2048). Must be at least 2048.

    Returns:
        Dictionary with 'public_key' and 'private_key' in PEM format.

    Raises:
        ValueError: If key_size is less than 2048.
    """
    if key_size < 2048:
        raise ValueError("key_size must be at least 2048 bits")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "public_key": public_pem.decode(),
        "private_key": private_pem.decode(),
    }


@mcp.tool()
def generate_x25519_key() -> dict[str, str]:
    """Generate an X25519 key pair for key exchange.

    Returns:
        Dictionary with 'public_key' and 'private_key' in PEM format.

    Example:
        >>> keys = generate_x25519_key()
        >>> len(keys['public_key']) > 0
        True
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "public_key": public_pem.decode(),
        "private_key": private_pem.decode(),
    }


@mcp.tool()
def fernet_encrypt(key: str, data: str) -> str:
    """Encrypt data using Fernet symmetric encryption.

    Args:
        key: Base64-encoded Fernet key.
        data: Plain text string to encrypt.

    Returns:
        Base64-encoded ciphertext.

    Example:
        >>> key = generate_symmetric_key()
        >>> ciphertext = fernet_encrypt(key, "Hello, World!")
        >>> len(ciphertext) > 0
        True
    """
    f = Fernet(key.encode())
    ciphertext = f.encrypt(data.encode())
    return ciphertext.decode()


@mcp.tool()
def fernet_decrypt(key: str, ciphertext: str) -> str:
    """Decrypt Fernet ciphertext.

    Args:
        key: Base64-encoded Fernet key.
        ciphertext: Base64-encoded ciphertext.

    Returns:
        Decrypted plain text string.

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails.
    """
    f = Fernet(key.encode())
    plaintext = f.decrypt(ciphertext.encode())
    return plaintext.decode()


@mcp.tool()
def aes_encrypt(key: str, data: str, mode: str = "CBC") -> dict[str, str]:
    """Encrypt data using AES.

    Args:
        key: Hex-encoded AES key (16, 24, or 32 bytes).
        data: String to encrypt.
        mode: Encryption mode - 'CBC' or 'GCM' (default CBC).

    Returns:
        Dictionary with 'ciphertext' (hex) and 'iv' (hex).

    Raises:
        ValueError: If key size is invalid.
    """
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        raise ValueError("Invalid hex key")
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes")

    data_bytes = data.encode()
    iv = os.urandom(16)

    if mode == "CBC":
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        padder = pkcs7_padding(128).padder()
        data_bytes = padder.update(data_bytes) + padder.finalize()
    elif mode == "GCM":
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(iv),  # type: ignore[arg-type]
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
    else:
        raise ValueError("Mode must be 'CBC' or 'GCM'")

    ciphertext = encryptor.update(data_bytes) + encryptor.finalize()

    return {
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
    }


@mcp.tool()
def aes_decrypt(key: str, ciphertext: str, iv: str, mode: str = "CBC") -> str:
    """Decrypt AES ciphertext.

    Args:
        key: Hex-encoded AES key.
        ciphertext: Hex-encoded ciphertext.
        iv: Hex-encoded initialization vector.
        mode: Encryption mode - 'CBC' or 'GCM' (default CBC).

    Returns:
        Decrypted string.

    Raises:
        ValueError: If key size is invalid.
    """
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        raise ValueError("Invalid hex key")
    ciphertext_bytes = bytes.fromhex(ciphertext)
    iv_bytes = bytes.fromhex(iv)

    if mode == "CBC":
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv_bytes),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        unpadder = pkcs7_padding(128).unpadder()
        data_bytes = unpadder.update(padded_data) + unpadder.finalize()
    elif mode == "GCM":
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(iv_bytes),  # type: ignore[arg-type]
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        data_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    else:
        raise ValueError("Mode must be 'CBC' or 'GCM'")

    return data_bytes.decode()


@mcp.tool()
def rsa_encrypt(public_key_pem: str, data: str) -> str:
    """Encrypt data using RSA with OAEP asymmetric_padding.

    Args:
        public_key_pem: RSA public key in PEM format.
        data: String to encrypt (max ~446 bytes for 4096-bit key).

    Returns:
        Base64-encoded ciphertext.

    Raises:
        ValueError: If data is too large for the key size.
    """
    public_key = cast("RSAPublicKey", load_pem_public_key(public_key_pem.encode()))
    data_bytes = data.encode()

    ciphertext = public_key.encrypt(
        data_bytes,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(ciphertext).decode()


@mcp.tool()
def rsa_decrypt(private_key_pem: str, ciphertext: str) -> str:
    """Decrypt RSA ciphertext using private key.

    Args:
        private_key_pem: RSA private key in PEM format.
        ciphertext: Base64-encoded ciphertext.

    Returns:
        Decrypted string.
    """
    private_key = cast(
        "RSAPrivateKey", load_pem_private_key(private_key_pem.encode(), password=None)
    )
    ciphertext_bytes = base64.b64decode(ciphertext)

    plaintext = private_key.decrypt(
        ciphertext_bytes,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return plaintext.decode()


@mcp.tool()
def rsa_sign(private_key_pem: str, data: str) -> str:
    """Create RSA digital signature.

    Args:
        private_key_pem: RSA private key in PEM format.
        data: String to sign.

    Returns:
        Base64-encoded signature.
    """
    private_key = cast(
        "RSAPrivateKey", load_pem_private_key(private_key_pem.encode(), password=None)
    )
    data_bytes = data.encode()

    signature = private_key.sign(
        data_bytes,
        asymmetric_padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode()


@mcp.tool()
def rsa_verify(public_key_pem: str, data: str, signature: str) -> bool:
    """Verify RSA digital signature.

    Args:
        public_key_pem: RSA public key in PEM format.
        data: Original signed data.
        signature: Base64-encoded signature.

    Returns:
        True if signature is valid.
    """
    public_key = cast("RSAPublicKey", load_pem_public_key(public_key_pem.encode()))
    data_bytes = data.encode()
    signature_bytes = base64.b64decode(signature)

    try:
        public_key.verify(
            signature_bytes,
            data_bytes,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


@mcp.tool()
def hash_sha256(data: str) -> str:
    """Compute SHA-256 hash.

    Args:
        data: String or base64-encoded bytes to hash.

    Returns:
        Hex-encoded hash.

    Example:
        >>> hash_sha256("Hello, World!")
        'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f'
    """
    if isinstance(data, str):
        data_bytes = data.encode()
    else:
        data_bytes = base64.b64decode(data)

    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(data_bytes)
    return h.finalize().hex()


@mcp.tool()
def hash_sha512(data: str) -> str:
    """Compute SHA-512 hash.

    Args:
        data: String to hash.

    Returns:
        Hex-encoded hash.
    """
    if isinstance(data, str):
        data_bytes = data.encode()
    else:
        data_bytes = base64.b64decode(data)

    h = hashes.Hash(hashes.SHA512(), backend=default_backend())
    h.update(data_bytes)
    return h.finalize().hex()


@mcp.tool()
def hash_sha1(data: str) -> str:
    """Compute SHA-1 hash.

    Note: SHA-1 is considered cryptographically broken. Use only for legacy compatibility.

    Args:
        data: String to hash.

    Returns:
        Hex-encoded hash.
    """
    if isinstance(data, str):
        data_bytes = data.encode()
    else:
        data_bytes = base64.b64decode(data)

    h = hashes.Hash(hashes.SHA1(), backend=default_backend())
    h.update(data_bytes)
    return h.finalize().hex()


@mcp.tool()
def hmac_sign(key: str, data: str, algorithm: str = "sha256") -> str:
    """Generate HMAC.

    Args:
        key: Hex-encoded key.
        data: String to sign.
        algorithm: Hash algorithm - 'sha256' or 'sha512' (default sha256).

    Returns:
        Hex-encoded HMAC.

    Example:
        >>> hmac_sign("aabbcc", "message")
        'c053c4f7...'
    """
    key_bytes = bytes.fromhex(key)
    if isinstance(data, str):
        data_bytes = data.encode()
    else:
        data_bytes = base64.b64decode(data)

    if algorithm == "sha256":
        h = HMAC(key_bytes, hashes.SHA256(), backend=default_backend())
    elif algorithm == "sha512":
        h = HMAC(key_bytes, hashes.SHA512(), backend=default_backend())
    else:
        raise ValueError("Algorithm must be 'sha256' or 'sha512'")

    h.update(data_bytes)
    return h.finalize().hex()


@mcp.tool()
def hmac_verify(key: str, data: str, hmac: str, algorithm: str = "sha256") -> bool:
    """Verify HMAC.

    Args:
        key: Hex-encoded key.
        data: String that was signed.
        hmac: Hex-encoded HMAC to verify.
        algorithm: Hash algorithm - 'sha256' or 'sha512'.

    Returns:
        True if HMAC is valid.
    """
    key_bytes = bytes.fromhex(key)
    if isinstance(data, str):
        data_bytes = data.encode()
    else:
        data_bytes = base64.b64decode(data)

    expected_hmac = bytes.fromhex(hmac)

    if algorithm == "sha256":
        h = HMAC(key_bytes, hashes.SHA256(), backend=default_backend())
    elif algorithm == "sha512":
        h = HMAC(key_bytes, hashes.SHA512(), backend=default_backend())
    else:
        raise ValueError("Algorithm must be 'sha256' or 'sha512'")

    h.update(data_bytes)
    computed = h.finalize()

    try:
        import hmac as hmac_module

        return hmac_module.compare_digest(computed, expected_hmac)
    except Exception:
        return False


@mcp.tool()
def pbkdf2_derive(
    password: str, salt: str | None = None, iterations: int = 480000
) -> dict[str, str]:
    """Derive key using PBKDF2.

    Args:
        password: Password to derive from.
        salt: Hex-encoded salt (optional, will generate if not provided).
        iterations: Number of iterations (default 480000, OWASP recommended).

    Returns:
        Dictionary with 'derived_key' (hex) and 'salt' (hex).
    """
    if salt is None:
        salt_bytes = os.urandom(16)
    else:
        salt_bytes = bytes.fromhex(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=iterations,
        backend=default_backend(),
    )
    derived_key = kdf.derive(password.encode())

    return {
        "derived_key": derived_key.hex(),
        "salt": salt_bytes.hex(),
    }


@mcp.tool()
def scrypt_derive(password: str, salt: str | None = None) -> dict[str, str]:
    """Derive key using Scrypt.

    Args:
        password: Password to derive from.
        salt: Hex-encoded salt (optional, will generate if not provided).

    Returns:
        Dictionary with 'derived_key' (hex) and 'salt' (hex).
    """
    if salt is None:
        salt_bytes = os.urandom(16)
    else:
        salt_bytes = bytes.fromhex(salt)

    kdf = Scrypt(
        salt=salt_bytes,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    derived_key = kdf.derive(password.encode())

    return {
        "derived_key": derived_key.hex(),
        "salt": salt_bytes.hex(),
    }


@mcp.tool()
def generate_self_signed_cert(
    common_name: str,
    organization: str | None = None,
    days_valid: int = 365,
) -> dict[str, str]:
    """Generate a self-signed X.509 certificate.

    Args:
        common_name: Common name for the certificate subject.
        organization: Organization name (optional).
        days_valid: Number of days the certificate is valid (default 365).

    Returns:
        Dictionary with 'certificate' (PEM) and 'private_key' (PEM).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
        ]
    )
    if organization:
        subject = x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, organization),
            ]
        )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    return {
        "certificate": cert_pem.decode(),
        "private_key": key_pem.decode(),
    }


@mcp.tool()
def parse_certificate(certificate_pem: str) -> dict[str, Any]:
    """Parse X.509 certificate.

    Args:
        certificate_pem: Certificate in PEM format.

    Returns:
        Dictionary with 'subject', 'issuer', 'not_valid_before', 'not_valid_after'.
    """
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())

    def name_to_dict(name: x509.Name) -> dict[str, Any]:
        result = {}
        for attr in name:
            key = attr.oid._name
            if key == "commonName":
                key = "common_name"
            result[key] = attr.value
        return result

    return {
        "subject": name_to_dict(cert.subject),
        "issuer": name_to_dict(cert.issuer),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
    }


@mcp.tool()
def generate_random_bytes(length: int = 32) -> str:
    """Generate random bytes.

    Args:
        length: Number of bytes to generate (default 32).

    Returns:
        Hex-encoded random bytes.

    Example:
        >>> generate_random_bytes(16)
        'a1b2c3d4e5f6...'
    """
    return os.urandom(length).hex()


@mcp.tool()
def generate_random_base64(length: int = 32) -> str:
    """Generate random bytes encoded as base64.

    Args:
        length: Number of bytes to generate (default 32).

    Returns:
        Base64-encoded random string.
    """
    return base64.b64encode(os.urandom(length)).decode()
