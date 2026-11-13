"""Hash calculation tools."""

import hashlib
import os
from typing import Optional

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.exceptions import HashCalculationError, validate_local_file_path


def _calculate_hash(file_path: str, hash_algo: str) -> str:
    """Calculate a specific hash for a file."""
    try:
        hasher = hashlib.new(hash_algo)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        raise HashCalculationError(file_path, hash_algo, str(e))


def _calculate_ssdeep(file_path: str) -> Optional[str]:
    """Calculate ssdeep fuzzy hash if available."""
    try:
        import ssdeep

        return ssdeep.hash_from_file(file_path)
    except ImportError:
        return None
    except Exception:
        return None


async def calculate_hashes(file_path: str) -> dict:
    """
    Calculate multiple hash values for a file.

    Calculates: MD5, SHA1, SHA256, SHA512, and SSDEEP (if available)

    Results are cached to avoid re-calculating hashes for the same file.

    Args:
        file_path: Path to the file

    Returns:
        JSON object containing all hash values:
        {
            "status": "success",
            "file_path": "/path/to/file",
            "file_size": 12345,
            "hashes": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "ssdeep": "3::"
            },
            "cached": false
        }
    """
    if err := validate_local_file_path(file_path):
        return err

    # Check cache first
    cache_key = f"hash:{file_path}"
    cached = await cache.get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    try:
        hashes = {
            "md5": _calculate_hash(file_path, "md5"),
            "sha1": _calculate_hash(file_path, "sha1"),
            "sha256": _calculate_hash(file_path, "sha256"),
            "sha512": _calculate_hash(file_path, "sha512"),
        }

        # Try to calculate ssdeep
        ssdeep_hash = _calculate_ssdeep(file_path)
        if ssdeep_hash:
            hashes["ssdeep"] = ssdeep_hash

        result = {
            "status": "success",
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "hashes": hashes,
            "cached": False,
        }

        # Save to cache
        await cache.set(cache_key, result)

        return result

    except HashCalculationError as e:
        return e.to_dict()
    except Exception as e:
        return {
            "status": "error",
            "error_type": "hash_calculation_failed",
            "message": str(e),
        }
