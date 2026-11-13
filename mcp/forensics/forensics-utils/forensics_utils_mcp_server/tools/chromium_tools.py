"""Chromium deep-artifact parsing tools."""

import base64
import copy
import ctypes
import dataclasses
import json
import platform
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - exercised via dependency checks
    AESGCM = None
    InvalidTag = Exception

from forensics_utils_mcp_server.cache import cache

try:
    from ccl_chromium_reader import ChromiumProfileFolder
except ImportError:  # pragma: no cover - exercised via tests with monkeypatching
    ChromiumProfileFolder = None

try:
    from ccl_chromium_reader import ccl_chromium_snss2
except ImportError:  # pragma: no cover - exercised via dependency checks
    ccl_chromium_snss2 = None


_ARTIFACT_LAYOUT = {
    "local_storage": {
        "presence_path": Path("Local Storage", "leveldb"),
        "stage_paths": (Path("Local Storage"),),
    },
    "session_storage": {
        "presence_path": Path("Session Storage"),
        "stage_paths": (Path("Session Storage"),),
    },
    "indexeddb": {
        "presence_path": Path("IndexedDB"),
        "stage_paths": (Path("IndexedDB"),),
    },
    "cache": {
        "presence_path": Path("Cache", "Cache_Data"),
        "stage_paths": (Path("Cache"),),
    },
    "history": {
        "presence_path": Path("History"),
        "stage_paths": (
            Path("History"),
            Path("History-journal"),
            Path("History-wal"),
            Path("History-shm"),
        ),
    },
    "downloads": {
        "presence_path": Path("History"),
        "stage_paths": (
            Path("History"),
            Path("History-journal"),
            Path("History-wal"),
            Path("History-shm"),
            Path("shared_proto_db"),
        ),
    },
    "bookmarks": {
        "presence_path": Path("Bookmarks"),
        "stage_paths": (Path("Bookmarks"),),
    },
    "logins": {
        "presence_path": Path("Login Data"),
        "stage_paths": (
            Path("Login Data"),
            Path("Login Data-journal"),
            Path("Login Data-wal"),
            Path("Login Data-shm"),
        ),
    },
    "sessions": {
        "presence_paths": (
            Path("Sessions"),
            Path("Current Session"),
            Path("Last Session"),
            Path("Current Tabs"),
            Path("Last Tabs"),
        ),
        "stage_paths": (
            Path("Sessions"),
            Path("Current Session"),
            Path("Last Session"),
            Path("Current Tabs"),
            Path("Last Tabs"),
        ),
    },
    "favicons": {
        "presence_path": Path("Favicons"),
        "stage_paths": (
            Path("Favicons"),
            Path("Favicons-journal"),
            Path("Favicons-wal"),
            Path("Favicons-shm"),
        ),
    },
    "web_data": {
        "presence_path": Path("Web Data"),
        "stage_paths": (
            Path("Web Data"),
            Path("Web Data-journal"),
            Path("Web Data-wal"),
            Path("Web Data-shm"),
        ),
    },
    "extensions": {
        "presence_path": Path("Extensions"),
        "stage_paths": (Path("Extensions"), Path("Preferences"), Path("Secure Preferences")),
    },
    "preferences": {
        "presence_paths": (Path("Preferences"), Path("Secure Preferences")),
        "stage_paths": (Path("Preferences"), Path("Secure Preferences")),
    },
    "cookies": {
        "presence_paths": (Path("Network", "Cookies"), Path("Cookies")),
        "stage_paths": (
            Path("Network", "Cookies"),
            Path("Network", "Cookies-journal"),
            Path("Network", "Cookies-wal"),
            Path("Network", "Cookies-shm"),
            Path("Cookies"),
            Path("Cookies-journal"),
            Path("Cookies-wal"),
            Path("Cookies-shm"),
        ),
    },
}

_INDEXEDDB_BINARY_PREVIEW_BYTES = 2048
_CACHE_BODY_PREVIEW_BYTES = 16384
_MAX_ERROR_SAMPLES = 10
_CHROMIUM_AES_NONCE_SIZE = 12
_PREFERENCE_KEY_PATHS = (
    "autofill.enabled",
    "browser.show_home_button",
    "credentials_enable_service",
    "download.default_directory",
    "download.prompt_for_download",
    "homepage",
    "homepage_is_newtabpage",
    "profile.name",
    "session.restore_on_startup",
    "session.startup_urls",
    "signin.allowed",
)


def _dependency_error() -> dict:
    return {
        "status": "error",
        "error_type": "dependency_not_found",
        "message": "Python package 'ccl_chromium_reader' is not installed",
        "details": {
            "package": "ccl_chromium_reader",
            "install_command": "pip install \"ccl_chromium_reader @ git+https://github.com/cclgroupltd/ccl_chromium_reader.git\"",
        },
    }


def _cryptography_dependency_error() -> dict:
    return {
        "status": "error",
        "error_type": "dependency_not_found",
        "message": "Python package 'cryptography' is required for Chromium login decryption",
        "details": {
            "package": "cryptography",
            "install_command": "pip install cryptography>=41.0.0",
        },
    }


def _input_error(message: str, error_type: str = "invalid_input", **details: Any) -> dict:
    result = {
        "status": "error",
        "error_type": error_type,
        "message": message,
    }
    if details:
        result["details"] = details
    return result


def _validate_profile_path(profile_path: str) -> tuple[Optional[Path], Optional[dict]]:
    path = Path(profile_path)
    if not path.exists():
        return None, {
            "status": "error",
            "error_type": "file_not_found",
            "message": f"Profile path not found: {profile_path}",
        }
    if not path.is_dir():
        return None, _input_error(
            f"Profile path is not a directory: {profile_path}",
            error_type="invalid_profile_path",
        )
    return path, None


def _normalize_filter(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _exact_match(expected: Optional[str], actual: Optional[str]) -> bool:
    if expected is None:
        return True
    return actual == expected


def _validate_positive_int(name: str, value: int) -> Optional[dict]:
    if value < 1:
        return _input_error(f"{name} must be greater than 0", parameter=name, value=value)
    return None


def _artifact_presence_paths(profile_path: Path, artifact_name: str) -> tuple[Path, ...]:
    artifact = _ARTIFACT_LAYOUT[artifact_name]
    if "presence_paths" in artifact:
        return tuple(profile_path / path for path in artifact["presence_paths"])
    return (profile_path / artifact["presence_path"],)


def _artifact_presence(profile_path: Path, artifact_name: str) -> Path:
    candidates = _artifact_presence_paths(profile_path, artifact_name)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _build_cache_key(prefix: str, *parts: Any) -> str:
    return ":".join([prefix, *[str(part) for part in parts]])


async def _get_cached_result(cache_key: str) -> Optional[dict]:
    cached_result = await cache.get(cache_key)
    if cached_result is None:
        return None
    result = copy.deepcopy(cached_result)
    result["cached"] = True
    return result


def _serialize_bytes(data: bytes, max_bytes: int) -> dict:
    preview = data[:max_bytes]
    return {
        "encoding": "base64",
        "size_bytes": len(data),
        "preview_base64": base64.b64encode(preview).decode("ascii"),
        "truncated": len(preview) < len(data),
    }


def _jsonify(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, bytes):
        return _serialize_bytes(value, _INDEXEDDB_BINARY_PREVIEW_BYTES)
    if isinstance(value, Path):
        return str(value)
    if depth >= 4:
        return {"type": value.__class__.__name__, "repr": repr(value)}
    if dataclasses.is_dataclass(value):
        return {
            "type": value.__class__.__name__,
            "fields": {
                field.name: _jsonify(getattr(value, field.name), depth + 1)
                for field in dataclasses.fields(value)
            },
        }
    if isinstance(value, dict):
        return {str(key): _jsonify(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(item, depth + 1) for item in value]
    return {"type": value.__class__.__name__, "repr": repr(value)}


def _base_result(profile_path: Path, artifact_type: str, artifact_path: Path) -> dict:
    return {
        "status": "success",
        "browser_family": "chromium",
        "profile_path": str(profile_path),
        "artifact_type": artifact_type,
        "artifact_path": str(artifact_path),
        "cached": False,
    }


def _empty_artifact_result(profile_path: Path, artifact_type: str, artifact_path: Path) -> dict:
    result = _base_result(profile_path, artifact_type, artifact_path)
    result.update(
        {
            "record_count": 0,
            "records": [],
            "truncated": False,
            "message": f"Artifact not present in profile: {artifact_path}",
        }
    )
    return result


def _collect_records(records: Iterable[Any], limit: int, transformer) -> tuple[list[dict], bool]:
    result = []
    truncated = False
    for record in records:
        if len(result) >= limit:
            truncated = True
            break
        result.append(transformer(record))
    return result, truncated


def _sqlite_row_value(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    keys = row.keys()
    if key in keys:
        return row[key]
    return default


def _cookie_encrypted_value_metadata(row: sqlite3.Row) -> dict:
    encrypted_value = _sqlite_row_value(row, "encrypted_value", b"") or b""
    return {
        "encrypted_value_present": bool(encrypted_value),
        "encrypted_value_size_bytes": len(encrypted_value),
    }


def _cookie_db_rows(db_path: Path) -> Iterator[sqlite3.Row]:
    connection = sqlite3.connect(db_path.absolute().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        for row in connection.execute("SELECT * FROM cookies"):
            yield row
    finally:
        connection.close()


def _login_db_rows(db_path: Path) -> Iterator[sqlite3.Row]:
    connection = sqlite3.connect(db_path.absolute().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        for row in connection.execute("SELECT rowid AS _rowid, * FROM logins"):
            yield row
    finally:
        connection.close()


def _login_password_blob(row: sqlite3.Row) -> bytes:
    return _sqlite_row_value(row, "password_value", b"") or b""


def _login_encryption_scheme(blob: bytes) -> str:
    if not blob:
        return "empty"
    if blob.startswith(b"v10"):
        return "v10"
    if blob.startswith(b"v11"):
        return "v11"
    if blob.startswith(b"v20"):
        return "v20"
    return "dpapi"


def _login_metadata_from_row(row: sqlite3.Row) -> dict:
    password_blob = _login_password_blob(row)
    return {
        "record_id": _sqlite_row_value(row, "_rowid"),
        "origin_url": _sqlite_row_value(row, "origin_url"),
        "action_url": _sqlite_row_value(row, "action_url"),
        "signon_realm": _sqlite_row_value(row, "signon_realm"),
        "username_element": _sqlite_row_value(row, "username_element"),
        "username_value": _sqlite_row_value(row, "username_value"),
        "password_element": _sqlite_row_value(row, "password_element"),
        "date_created_iso": _chromium_timestamp_to_iso(_sqlite_row_value(row, "date_created")),
        "date_last_used_iso": _chromium_timestamp_to_iso(_sqlite_row_value(row, "date_last_used")),
        "date_password_modified_iso": _chromium_timestamp_to_iso(
            _sqlite_row_value(row, "date_password_modified")
        ),
        "date_synced_iso": _chromium_timestamp_to_iso(_sqlite_row_value(row, "date_synced")),
        "blacklisted_by_user": bool(_sqlite_row_value(row, "blacklisted_by_user", 0)),
        "scheme": _sqlite_row_value(row, "scheme"),
        "times_used": _sqlite_row_value(row, "times_used"),
        "display_name": _sqlite_row_value(row, "display_name"),
        "icon_url": _sqlite_row_value(row, "icon_url"),
        "federation_url": _sqlite_row_value(row, "federation_url"),
        "skip_zero_click": bool(_sqlite_row_value(row, "skip_zero_click", 0)),
        "generation_upload_status": _sqlite_row_value(row, "generation_upload_status"),
        "possible_username_pairs": _sqlite_row_value(row, "possible_username_pairs"),
        "submit_element": _sqlite_row_value(row, "submit_element"),
        "password_blob_present": bool(password_blob),
        "password_blob_size_bytes": len(password_blob),
        "password_encryption": _login_encryption_scheme(password_blob),
        "record_location": f"SQLite Rowid: {_sqlite_row_value(row, '_rowid')}",
    }


def _local_state_path_for_profile(profile_path: Path) -> Path:
    return profile_path.parent / "Local State"


def _resolve_local_state_path(
    profile_path: Path, local_state_path: Optional[str]
) -> tuple[Optional[Path], Optional[dict]]:
    candidate = Path(local_state_path) if local_state_path is not None else _local_state_path_for_profile(profile_path)
    if not candidate.exists():
        return None, None
    if not candidate.is_file():
        return None, _input_error(
            f"Local State path is not a file: {candidate}",
            error_type="invalid_local_state_path",
        )
    return candidate, None


def _platform_is_windows() -> bool:
    return platform.system() == "Windows"


def _windows_dpapi_decrypt(ciphertext: bytes) -> bytes:
    if not _platform_is_windows():
        raise OSError("DPAPI decryption is only available on Windows")

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    def _to_blob(data: bytes):
        buffer = ctypes.create_string_buffer(data, len(data))
        blob = DataBlob(
            len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        )
        return blob, buffer

    in_blob, in_buffer = _to_blob(ciphertext)
    out_blob = DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    del in_buffer

    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _chromium_master_key_from_local_state(local_state_path: Path) -> bytes:
    local_state = json.loads(local_state_path.read_text(encoding="utf-8"))
    encrypted_key_b64 = ((local_state.get("os_crypt") or {}).get("encrypted_key"))
    if not encrypted_key_b64:
        raise KeyError("os_crypt.encrypted_key not found in Local State")

    encrypted_key = base64.b64decode(encrypted_key_b64)
    if encrypted_key.startswith(b"DPAPI"):
        encrypted_key = encrypted_key[5:]
    return _windows_dpapi_decrypt(encrypted_key)


def _provided_master_key(master_key_b64: Optional[str]) -> tuple[Optional[bytes], Optional[dict]]:
    if master_key_b64 is None:
        return None, None
    try:
        master_key = base64.b64decode(master_key_b64)
    except Exception as exc:
        return None, _input_error(
            f"Invalid master_key_b64: {exc}",
            error_type="invalid_master_key",
        )
    if len(master_key) not in {16, 24, 32}:
        return None, _input_error(
            "master_key_b64 must decode to a 16, 24, or 32 byte AES key",
            error_type="invalid_master_key",
            key_length=len(master_key),
        )
    return master_key, None


def _decrypt_chromium_login_blob(password_blob: bytes, master_key: Optional[bytes]) -> str:
    scheme = _login_encryption_scheme(password_blob)
    if scheme == "empty":
        return ""
    if scheme in {"v10", "v11"}:
        if AESGCM is None:
            raise RuntimeError("cryptography dependency is unavailable")
        if master_key is None:
            raise ValueError("master_key_required")
        nonce = password_blob[3 : 3 + _CHROMIUM_AES_NONCE_SIZE]
        ciphertext = password_blob[3 + _CHROMIUM_AES_NONCE_SIZE :]
        plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    if scheme == "v20":
        raise NotImplementedError("Chromium app-bound encryption (v20) is not supported")
    plaintext = _windows_dpapi_decrypt(password_blob)
    return plaintext.decode("utf-8")


@contextmanager
def _sqlite_connection(db_path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(db_path.absolute().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def _sqlite_table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _get_json_path_value(data: Any, key_path: str) -> Any:
    current = data
    for part in key_path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise KeyError(key_path)
            current = current[part]
            continue
        if isinstance(current, list):
            index = int(part)
            current = current[index]
            continue
        raise KeyError(key_path)
    return current


def _iter_present_json_preferences(profile_path: Path) -> Iterator[tuple[str, Path, Any]]:
    for candidate in _artifact_presence_paths(profile_path, "preferences"):
        if candidate.exists():
            yield candidate.name, candidate, _load_json_file(candidate)


def _iter_session_files(profile_path: Path) -> Iterator[Path]:
    sessions_dir = profile_path / "Sessions"
    if sessions_dir.is_dir():
        for candidate in sorted(sessions_dir.iterdir()):
            if candidate.is_file() and (
                candidate.name.startswith("Session_") or candidate.name.startswith("Tabs_")
            ):
                yield candidate

    for candidate_name in ("Current Session", "Last Session", "Current Tabs", "Last Tabs"):
        candidate = profile_path / candidate_name
        if candidate.is_file():
            yield candidate


def _session_file_type(file_path: Path):
    if ccl_chromium_snss2 is None:
        raise RuntimeError("ccl_chromium_reader dependency is unavailable")
    if file_path.name.startswith("Session_") or file_path.name in {
        "Current Session",
        "Last Session",
    }:
        return ccl_chromium_snss2.SnssFileType.Session
    if file_path.name.startswith("Tabs_") or file_path.name in {"Current Tabs", "Last Tabs"}:
        return ccl_chromium_snss2.SnssFileType.Tab
    raise ValueError(f"Unsupported Chromium session file name: {file_path.name}")


def _resolve_extension_message(manifest_dir: Path, manifest: dict[str, Any], key: str) -> Any:
    value = manifest.get(key)
    if not isinstance(value, str) or not (value.startswith("__MSG_") and value.endswith("__")):
        return value

    message_key = value[6:-2]
    default_locale = manifest.get("default_locale")
    for locale in [default_locale, "en"]:
        if not locale:
            continue
        messages_path = manifest_dir / "_locales" / locale / "messages.json"
        if not messages_path.exists():
            continue
        messages = _load_json_file(messages_path)
        message = messages.get(message_key)
        if isinstance(message, dict) and "message" in message:
            return message["message"]
    return value


def _extension_settings(preferences_data: dict[str, Any], extension_id: str) -> dict[str, Any]:
    return ((preferences_data.get("extensions") or {}).get("settings") or {}).get(extension_id) or {}


def _chromium_timestamp_to_iso(value: Optional[Any]) -> Optional[str]:
    if value in (None, "", 0, "0"):
        return None
    try:
        microseconds = int(value)
    except (TypeError, ValueError):
        return None
    if microseconds <= 0:
        return None
    return (datetime(1601, 1, 1) + timedelta(microseconds=microseconds)).isoformat()


def _summarize_cache(profile: Any, sample_limit: int) -> dict:
    urls = []
    count = 0
    for cache_key in profile.cache.cache_keys():
        count += 1
        if len(urls) < sample_limit:
            urls.append(cache_key.url)
    return {
        "present": True,
        "cache_entry_count": count,
        "urls_sample": urls,
    }


def _summarize_local_storage(profile: Any, sample_limit: int) -> dict:
    storage_keys = list(profile.iter_local_storage_hosts())
    return {
        "present": True,
        "storage_key_count": len(storage_keys),
        "storage_keys_sample": storage_keys[:sample_limit],
    }


def _summarize_session_storage(profile: Any, sample_limit: int) -> dict:
    hosts = list(profile.iter_session_storage_hosts())
    return {
        "present": True,
        "host_count": len(hosts),
        "hosts_sample": hosts[:sample_limit],
    }


def _summarize_indexeddb(profile: Any, sample_limit: int) -> dict:
    hosts = list(profile.iter_indexeddb_hosts())
    return {
        "present": True,
        "host_id_count": len(hosts),
        "host_ids_sample": hosts[:sample_limit],
    }


def _summarize_history(profile: Any, sample_limit: int) -> dict:
    count = 0
    sample_records = []
    for record in profile.iterate_history_records(url=None):
        count += 1
        if len(sample_records) < sample_limit:
            sample_records.append({"url": record.url, "title": record.title})
    return {
        "present": True,
        "history_record_count": count,
        "records_sample": sample_records,
    }


def _summarize_downloads(profile: Any, sample_limit: int) -> dict:
    count = 0
    sample_records = []
    for record in profile.iter_downloads():
        count += 1
        if len(sample_records) < sample_limit:
            sample_records.append({"url": record.url, "target_path": record.target_path})
    return {
        "present": True,
        "download_count": count,
        "downloads_sample": sample_records,
    }


def _summarize_bookmarks(profile_path: Path, sample_limit: int) -> dict:
    bookmarks_path = profile_path / "Bookmarks"
    bookmark_data = json.loads(bookmarks_path.read_text(encoding="utf-8"))
    count = 0
    sample_records = []
    for root_name, root_node in (bookmark_data.get("roots") or {}).items():
        if not isinstance(root_node, dict):
            continue
        for child in root_node.get("children", []):
            if not isinstance(child, dict):
                continue
            for record in _iter_bookmark_url_nodes(root_name, child):
                count += 1
                if len(sample_records) < sample_limit:
                    sample_records.append({"name": record["name"], "url": record["url"]})
    return {
        "present": True,
        "bookmark_count": count,
        "bookmarks_sample": sample_records,
    }


def _summarize_logins(profile_path: Path, sample_limit: int) -> dict:
    login_db_path = _artifact_presence(profile_path, "logins")
    count = 0
    sample_records = []
    for row in _login_db_rows(login_db_path):
        count += 1
        if len(sample_records) < sample_limit:
            sample_records.append(
                {
                    "origin_url": _sqlite_row_value(row, "origin_url"),
                    "username_value": _sqlite_row_value(row, "username_value"),
                    "password_encryption": _login_encryption_scheme(_login_password_blob(row)),
                }
            )
    return {
        "present": True,
        "login_count": count,
        "logins_sample": sample_records,
        "login_db_path": str(login_db_path),
    }


def _summarize_cookies(profile_path: Path, sample_limit: int) -> dict:
    cookies_path = _artifact_presence(profile_path, "cookies")
    count = 0
    sample_records = []
    for row in _cookie_db_rows(cookies_path):
        count += 1
        if len(sample_records) < sample_limit:
            sample_records.append(
                {
                    "host_key": _sqlite_row_value(row, "host_key"),
                    "name": _sqlite_row_value(row, "name"),
                    "path": _sqlite_row_value(row, "path"),
                }
            )
    return {
        "present": True,
        "cookie_count": count,
        "cookies_sample": sample_records,
        "cookie_db_path": str(cookies_path),
    }


def _session_command_to_record(command: Any, source_file: Path) -> dict:
    return {
        "source_file": source_file.name,
        "file_type": _session_file_type(source_file).name.lower(),
        "offset": getattr(command, "offset", None),
        "command_type": getattr(getattr(command, "id_type", None), "name", None),
        "session_id": getattr(command, "session_id", None),
        "index": getattr(command, "index", None),
        "url": getattr(command, "url", None),
        "title": getattr(command, "title", None),
        "timestamp_iso": None
        if getattr(command, "timestamp", None) is None
        else command.timestamp.isoformat(),
        "referrer_url": getattr(command, "referrer_url", None),
        "original_request_url": getattr(command, "original_request_url", None),
        "transition_core": None
        if getattr(command, "transition_type", None) is None
        else command.transition_type.core_transition,
        "transition_qualifiers": []
        if getattr(command, "transition_type", None) is None
        else list(command.transition_type.qualifiers),
        "has_post_data": getattr(command, "has_post_data", None),
        "http_status": getattr(command, "http_status", None),
        "record_location": f"{source_file.name} @ {getattr(command, 'offset', 0)}",
    }


def _summarize_sessions(profile_path: Path, sample_limit: int) -> dict:
    if ccl_chromium_snss2 is None:
        raise RuntimeError("ccl_chromium_reader dependency is unavailable")

    count = 0
    sample_records = []
    file_count = 0
    for session_file in _iter_session_files(profile_path):
        file_count += 1
        with session_file.open("rb") as stream:
            snss_file = ccl_chromium_snss2.SnssFile(_session_file_type(session_file), stream)
            for command in snss_file.iter_session_commands():
                if not isinstance(command, ccl_chromium_snss2.NavigationEntry):
                    continue
                count += 1
                if len(sample_records) < sample_limit:
                    sample_records.append(_session_command_to_record(command, session_file))
    return {
        "present": True,
        "session_file_count": file_count,
        "navigation_entry_count": count,
        "sessions_sample": sample_records,
    }


def _summarize_favicons(profile_path: Path, sample_limit: int) -> dict:
    favicons_path = _artifact_presence(profile_path, "favicons")
    sample_records = []
    with _sqlite_connection(favicons_path) as connection:
        count = 0
        for row in connection.execute(
            """
            SELECT icon_mapping.page_url, favicons.url AS icon_url
            FROM icon_mapping
            JOIN favicons ON icon_mapping.icon_id = favicons.id
            """
        ):
            count += 1
            if len(sample_records) < sample_limit:
                sample_records.append(
                    {
                        "page_url": _sqlite_row_value(row, "page_url"),
                        "icon_url": _sqlite_row_value(row, "icon_url"),
                    }
                )
    return {
        "present": True,
        "favicon_mapping_count": count,
        "favicons_sample": sample_records,
        "favicons_db_path": str(favicons_path),
    }


def _summarize_web_data(profile_path: Path, sample_limit: int) -> dict:
    web_data_path = _artifact_presence(profile_path, "web_data")
    categories = {}
    with _sqlite_connection(web_data_path) as connection:
        for category, table_name in (
            ("autofill", "autofill"),
            ("keywords", "keywords"),
            ("profiles", "autofill_profiles"),
        ):
            if not _sqlite_table_exists(connection, table_name):
                continue
            count = connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            categories[category] = {"count": count}
    return {
        "present": True,
        "web_data_path": str(web_data_path),
        "categories": categories,
        "supported_categories": list(categories.keys())[:sample_limit],
    }


def _summarize_extensions(profile_path: Path, sample_limit: int) -> dict:
    extensions_path = _artifact_presence(profile_path, "extensions")
    sample_records = []
    count = 0
    for extension_dir in sorted(extensions_path.iterdir()):
        if not extension_dir.is_dir():
            continue
        count += 1
        if len(sample_records) < sample_limit:
            sample_records.append({"extension_id": extension_dir.name})
    return {
        "present": True,
        "extension_count": count,
        "extensions_sample": sample_records,
        "extensions_path": str(extensions_path),
    }


def _summarize_preferences(profile_path: Path, sample_limit: int) -> dict:
    sources = []
    for source_name, source_path, data in _iter_present_json_preferences(profile_path):
        sources.append(
            {
                "source_file": source_name,
                "top_level_key_count": len(data) if isinstance(data, dict) else None,
                "top_level_keys_sample": []
                if not isinstance(data, dict)
                else sorted(list(data.keys()))[:sample_limit],
                "path": str(source_path),
            }
        )
    return {
        "present": True,
        "source_count": len(sources),
        "sources": sources,
    }


def _transition_qualifiers(qualifier: Any) -> list[str]:
    try:
        return [
            flag.name
            for flag in type(qualifier)
            if int(flag) and flag & qualifier
        ]
    except TypeError:
        if int(qualifier) and getattr(qualifier, "name", None):
            return [qualifier.name]
        return []


def _iter_bookmark_url_nodes(
    root_name: str, node: dict[str, Any], folder_path: tuple[str, ...] = ()
) -> Iterator[dict]:
    node_type = node.get("type")
    if node_type == "url":
        yield {
            "id": node.get("id"),
            "guid": node.get("guid"),
            "name": node.get("name"),
            "url": node.get("url"),
            "date_added_iso": _chromium_timestamp_to_iso(node.get("date_added")),
            "date_last_used_iso": _chromium_timestamp_to_iso(node.get("date_last_used")),
            "source_root": root_name,
            "folder_path": list(folder_path),
            "folder_path_display": " / ".join(folder_path),
            "meta_info": _jsonify(node.get("meta_info") or {}),
            "record_location": f"Bookmark ID: {node.get('id')}",
        }
        return

    if node_type != "folder":
        return

    name = node.get("name")
    if name:
        folder_path = folder_path + (name,)

    for child in node.get("children", []):
        if isinstance(child, dict):
            yield from _iter_bookmark_url_nodes(root_name, child, folder_path)


def _stage_paths_for_artifacts(artifact_names: Iterable[str]) -> list[Path]:
    stage_paths = []
    seen = set()
    for artifact_name in artifact_names:
        for stage_path in _ARTIFACT_LAYOUT[artifact_name]["stage_paths"]:
            if stage_path not in seen:
                stage_paths.append(stage_path)
                seen.add(stage_path)
    return stage_paths


@contextmanager
def _staged_profile(profile_path: Path, artifact_names: Iterable[str]) -> Iterator[Path]:
    # ignore_cleanup_errors so Windows file locks (AV/Chrome) don't crash the
    # tempdir teardown after the tool already finished.
    with tempfile.TemporaryDirectory(
        prefix="chromium-profile-", ignore_cleanup_errors=True
    ) as temp_dir:
        staged_profile = Path(temp_dir) / "profile"
        staged_profile.mkdir(parents=True, exist_ok=True)
        for stage_path in _stage_paths_for_artifacts(artifact_names):
            source = profile_path / stage_path
            if not source.exists():
                continue
            destination = staged_profile / stage_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                try:
                    shutil.copytree(source, destination, dirs_exist_ok=True)
                except (PermissionError, OSError):
                    # AV/Chrome may hold a brief lock; skip the offender.
                    continue
            else:
                try:
                    shutil.copy2(source, destination)
                except (PermissionError, OSError):
                    continue
        yield staged_profile


async def chromium_profile_summary(profile_path: str, sample_limit: int = 10) -> dict:
    """Summarize deep Chromium artifacts available in a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("sample_limit", sample_limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    cache_key = _build_cache_key("chromium:summary", profile_dir, sample_limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    available_artifacts = [
        artifact_name
        for artifact_name in _ARTIFACT_LAYOUT
        if any(path.exists() for path in _artifact_presence_paths(profile_dir, artifact_name))
    ]

    result = _base_result(profile_dir, "profile_summary", profile_dir)
    result.update(
        {
            "artifacts": {artifact_name: {"present": False} for artifact_name in _ARTIFACT_LAYOUT},
            "available_artifacts": available_artifacts,
        }
    )

    if not available_artifacts:
        result["message"] = "No supported Chromium deep artifacts found in this profile"
        await cache.set(cache_key, result)
        return result

    with _staged_profile(profile_dir, available_artifacts) as staged_profile:
        with ChromiumProfileFolder(staged_profile) as profile:
            for artifact_name, summary_func in (
                ("local_storage", _summarize_local_storage),
                ("session_storage", _summarize_session_storage),
                ("indexeddb", _summarize_indexeddb),
                ("cache", _summarize_cache),
                ("history", _summarize_history),
                ("downloads", _summarize_downloads),
            ):
                if artifact_name not in available_artifacts:
                    continue
                try:
                    result["artifacts"][artifact_name] = summary_func(profile, sample_limit)
                except Exception as exc:  # pragma: no cover - defensive path
                    result["artifacts"][artifact_name] = {
                        "present": True,
                        "error": str(exc),
                    }

        if "sessions" in available_artifacts:
            try:
                result["artifacts"]["sessions"] = _summarize_sessions(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["sessions"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "favicons" in available_artifacts:
            try:
                result["artifacts"]["favicons"] = _summarize_favicons(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["favicons"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "web_data" in available_artifacts:
            try:
                result["artifacts"]["web_data"] = _summarize_web_data(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["web_data"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "extensions" in available_artifacts:
            try:
                result["artifacts"]["extensions"] = _summarize_extensions(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["extensions"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "preferences" in available_artifacts:
            try:
                result["artifacts"]["preferences"] = _summarize_preferences(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["preferences"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "bookmarks" in available_artifacts:
            try:
                result["artifacts"]["bookmarks"] = _summarize_bookmarks(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["bookmarks"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "logins" in available_artifacts:
            try:
                result["artifacts"]["logins"] = _summarize_logins(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["logins"] = {
                    "present": True,
                    "error": str(exc),
                }

        if "cookies" in available_artifacts:
            try:
                result["artifacts"]["cookies"] = _summarize_cookies(
                    staged_profile, sample_limit
                )
            except Exception as exc:  # pragma: no cover - defensive path
                result["artifacts"]["cookies"] = {
                    "present": True,
                    "error": str(exc),
                }

    await cache.set(cache_key, result)
    return result


async def chromium_parse_local_storage(
    profile_path: str,
    storage_key: Optional[str] = None,
    script_key: Optional[str] = None,
    limit: int = 100,
    include_deletions: bool = False,
) -> dict:
    """Parse Chromium Local Storage records from a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "local_storage")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "local_storage", artifact_path)

    storage_key = _normalize_filter(storage_key)
    script_key = _normalize_filter(script_key)
    cache_key = _build_cache_key(
        "chromium:local_storage",
        profile_dir,
        storage_key,
        script_key,
        limit,
        include_deletions,
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["local_storage"]) as staged_profile:
            with ChromiumProfileFolder(staged_profile) as profile:
                iterator = profile.iter_local_storage_with_batches(
                    storage_key=storage_key,
                    script_key=script_key,
                    include_deletions=include_deletions,
                    raise_on_no_result=False,
                )
                records, truncated = _collect_records(
                    iterator,
                    limit,
                    lambda item: {
                        "storage_key": item[0].storage_key,
                        "script_key": item[0].script_key,
                        "value": item[0].value,
                        "is_live": item[0].is_live,
                        "leveldb_sequence_number": item[0].leveldb_seq_number,
                        "record_location": item[0].record_location,
                        "batch": None
                        if item[1] is None
                        else {
                            "timestamp_iso": item[1].timestamp.isoformat(),
                            "start_sequence": item[1].start,
                            "end_sequence": item[1].end,
                        },
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium Local Storage: {exc}",
            error_type="chromium_local_storage_failed",
        )

    result = _base_result(profile_dir, "local_storage", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_session_storage(
    profile_path: str,
    host: Optional[str] = None,
    key: Optional[str] = None,
    limit: int = 100,
    include_deletions: bool = False,
) -> dict:
    """Parse Chromium Session Storage records from a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "session_storage")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "session_storage", artifact_path)

    host = _normalize_filter(host)
    key = _normalize_filter(key)
    cache_key = _build_cache_key(
        "chromium:session_storage",
        profile_dir,
        host,
        key,
        limit,
        include_deletions,
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["session_storage"]) as staged_profile:
            with ChromiumProfileFolder(staged_profile) as profile:
                iterator = profile.iter_session_storage(
                    host=host,
                    key=key,
                    include_deletions=include_deletions,
                    raise_on_no_result=False,
                )
                records, truncated = _collect_records(
                    iterator,
                    limit,
                    lambda record: {
                        "host": record.host,
                        "key": record.key,
                        "value": record.value,
                        "is_deleted": record.is_deleted,
                        "leveldb_sequence_number": record.leveldb_sequence_number,
                        "record_location": record.record_location,
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium Session Storage: {exc}",
            error_type="chromium_session_storage_failed",
        )

    result = _base_result(profile_dir, "session_storage", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_indexeddb(
    profile_path: str,
    host_id: Optional[str] = None,
    database_name: Optional[str] = None,
    object_store_name: Optional[str] = None,
    limit: int = 100,
    include_deletions: bool = False,
) -> dict:
    """Parse Chromium IndexedDB records from a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "indexeddb")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "indexeddb", artifact_path)

    host_id = _normalize_filter(host_id)
    database_name = _normalize_filter(database_name)
    object_store_name = _normalize_filter(object_store_name)
    cache_key = _build_cache_key(
        "chromium:indexeddb",
        profile_dir,
        host_id,
        database_name,
        object_store_name,
        limit,
        include_deletions,
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    decode_state = {"count": 0, "samples": []}

    def _decode_error_handler(key_obj: Any, raw_data: bytes) -> None:
        decode_state["count"] += 1
        if len(decode_state["samples"]) < _MAX_ERROR_SAMPLES:
            decode_state["samples"].append(
                {"key": repr(key_obj), "raw_length": len(raw_data)}
            )

    try:
        with _staged_profile(profile_dir, ["indexeddb"]) as staged_profile:
            with ChromiumProfileFolder(staged_profile) as profile:
                iterator = profile.iter_indexeddb_records(
                    host_id=host_id,
                    database_name=database_name,
                    object_store_name=object_store_name,
                    raise_on_no_result=False,
                    include_deletions=include_deletions,
                    bad_deserializer_data_handler=_decode_error_handler,
                )
                records, truncated = _collect_records(
                    iterator,
                    limit,
                    lambda record: {
                        "database_name": record.database_name,
                        "database_origin": record.database_origin,
                        "object_store_name": record.object_store_name,
                        "key_type": record.key.key_type.name,
                        "key": _jsonify(record.key.value),
                        "raw_key_hex": record.key.raw_key.hex(),
                        "value": _jsonify(record.value),
                        "is_live": record.is_live,
                        "leveldb_sequence_number": record.ldb_seq_no,
                        "origin_file": str(record.origin_file),
                        "record_location": record.record_location,
                        "external_value_path": record.external_value_path,
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium IndexedDB: {exc}",
            error_type="chromium_indexeddb_failed",
        )

    result = _base_result(profile_dir, "indexeddb", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "decode_error_count": decode_state["count"],
            "decode_error_samples": decode_state["samples"],
        }
    )
    await cache.set(cache_key, result)
    return result


async def chromium_parse_cache(
    profile_path: str,
    url: Optional[str] = None,
    limit: int = 100,
    include_body: bool = False,
    max_body_bytes: int = _CACHE_BODY_PREVIEW_BYTES,
    decompress: bool = True,
) -> dict:
    """Parse Chromium HTTP cache records from a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error
    if error := _validate_positive_int("max_body_bytes", max_body_bytes):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "cache")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "cache", artifact_path)

    url = _normalize_filter(url)
    cache_key = _build_cache_key(
        "chromium:cache",
        profile_dir,
        url,
        limit,
        include_body,
        max_body_bytes,
        decompress,
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["cache"]) as staged_profile:
            with ChromiumProfileFolder(staged_profile) as profile:
                iterator = profile.iterate_cache(
                    url=url,
                    decompress=decompress,
                    omit_cached_data=not include_body,
                )
                records, truncated = _collect_records(
                    iterator,
                    limit,
                    lambda record: {
                        "url": record.key.url,
                        "raw_key": record.key.raw_key,
                        "duplicate_key_index": record.duplicate_key_index,
                        "was_decompressed": record.was_decompressed,
                        "metadata_location": str(record.metadata_location),
                        "data_location": str(record.data_location),
                        "request_time_iso": None
                        if record.metadata is None
                        else record.metadata.request_time.isoformat(),
                        "response_time_iso": None
                        if record.metadata is None
                        else record.metadata.response_time.isoformat(),
                        "response_declarations": []
                        if record.metadata is None
                        else sorted(list(record.metadata.http_header_declarations)),
                        "response_headers": {}
                        if record.metadata is None
                        else _jsonify(
                            {
                                header_name: values
                                for header_name, values in _group_headers(
                                    record.metadata.http_header_attributes
                                ).items()
                            }
                        ),
                        "other_cache_attributes": {}
                        if record.metadata is None
                        else _jsonify(dict(record.metadata.other_cache_attributes)),
                        "body": None
                        if not include_body or record.data is None
                        else _serialize_bytes(record.data, max_body_bytes),
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium cache: {exc}",
            error_type="chromium_cache_failed",
        )

    result = _base_result(profile_dir, "cache", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "body_included": include_body,
            "decompress": decompress,
        }
    )
    await cache.set(cache_key, result)
    return result


async def chromium_parse_history(
    profile_path: str,
    url: Optional[str] = None,
    title: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium browsing history records from a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "history")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "history", artifact_path)

    url = _normalize_filter(url)
    title = _normalize_filter(title)
    cache_key = _build_cache_key("chromium:history", profile_dir, url, title, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["history"]) as staged_profile:
            with ChromiumProfileFolder(staged_profile) as profile:
                iterator = profile.iterate_history_records(url=url)
                if title is not None:
                    iterator = (record for record in iterator if _exact_match(title, record.title))
                records, truncated = _collect_records(
                    iterator,
                    limit,
                    lambda record: {
                        "record_id": record.rec_id,
                        "url": record.url,
                        "title": record.title,
                        "visit_time_iso": record.visit_time.isoformat(),
                        "visit_duration_ms": int(record.visit_duration.total_seconds() * 1000),
                        "transition_core": record.transition.core.name,
                        "transition_qualifiers": _transition_qualifiers(
                            record.transition.qualifier
                        ),
                        "from_visit_id": record.from_visit_id,
                        "opener_visit_id": record.opener_visit_id,
                        "parent_visit_id": record.parent_visit_id,
                        "has_parent": record.has_parent,
                        "record_location": record.record_location,
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium history: {exc}",
            error_type="chromium_history_failed",
        )

    result = _base_result(profile_dir, "history", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_downloads(
    profile_path: str,
    download_url: Optional[str] = None,
    tab_url: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium download records from a profile."""
    if ChromiumProfileFolder is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "downloads")
    has_download_artifact = artifact_path.exists() or (profile_dir / "shared_proto_db").exists()
    if not has_download_artifact:
        return _empty_artifact_result(profile_dir, "downloads", profile_dir)

    download_url = _normalize_filter(download_url)
    tab_url = _normalize_filter(tab_url)
    cache_key = _build_cache_key(
        "chromium:downloads", profile_dir, download_url, tab_url, limit
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["downloads"]) as staged_profile:
            with ChromiumProfileFolder(staged_profile) as profile:
                iterator = profile.iter_downloads(download_url=download_url, tab_url=tab_url)
                records, truncated = _collect_records(
                    iterator,
                    limit,
                    lambda record: {
                        "record_source": record.record_source.name,
                        "record_id": record.record_id,
                        "guid": record.guid,
                        "hash": record.hash,
                        "url": record.url,
                        "url_chain": list(record.url_chain),
                        "tab_url": record.tab_url,
                        "tab_referrer_url": record.tab_referrer_url,
                        "target_path": record.target_path,
                        "mime_type": record.mime_type,
                        "original_mime_type": record.original_mime_type,
                        "total_bytes": int(record.total_bytes),
                        "start_time_iso": record.start_time.isoformat(),
                        "end_time_iso": record.end_time.isoformat(),
                        "record_location": record.record_location,
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium downloads: {exc}",
            error_type="chromium_downloads_failed",
        )

    result = _base_result(profile_dir, "downloads", profile_dir)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_sessions(
    profile_path: str,
    file_name: Optional[str] = None,
    url: Optional[str] = None,
    title: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium session restore files from a profile."""
    if ccl_chromium_snss2 is None:
        return _dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "sessions")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "sessions", artifact_path)

    file_name = _normalize_filter(file_name)
    url = _normalize_filter(url)
    title = _normalize_filter(title)
    cache_key = _build_cache_key("chromium:sessions", profile_dir, file_name, url, title, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    stats = {"parsed_file_count": 0, "parse_error_count": 0, "parse_error_samples": []}

    try:
        with _staged_profile(profile_dir, ["sessions"]) as staged_profile:

            def _iter_records() -> Iterator[dict]:
                for session_file in _iter_session_files(staged_profile):
                    if not _exact_match(file_name, session_file.name):
                        continue
                    stats["parsed_file_count"] += 1
                    try:
                        with session_file.open("rb") as stream:
                            snss_file = ccl_chromium_snss2.SnssFile(
                                _session_file_type(session_file), stream
                            )
                            for command in snss_file.iter_session_commands():
                                if not isinstance(command, ccl_chromium_snss2.NavigationEntry):
                                    continue
                                record = _session_command_to_record(command, session_file)
                                if not _exact_match(url, record["url"]):
                                    continue
                                if not _exact_match(title, record["title"]):
                                    continue
                                yield record
                    except Exception as exc:
                        stats["parse_error_count"] += 1
                        if len(stats["parse_error_samples"]) < _MAX_ERROR_SAMPLES:
                            stats["parse_error_samples"].append(
                                {"file_name": session_file.name, "error": str(exc)}
                            )

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium sessions: {exc}",
            error_type="chromium_sessions_failed",
        )

    result = _base_result(profile_dir, "sessions", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "parsed_file_count": stats["parsed_file_count"],
            "parse_error_count": stats["parse_error_count"],
            "parse_error_samples": stats["parse_error_samples"],
        }
    )
    await cache.set(cache_key, result)
    return result


async def chromium_parse_favicons(
    profile_path: str,
    page_url: Optional[str] = None,
    icon_url: Optional[str] = None,
    limit: int = 100,
    include_image: bool = False,
    max_image_bytes: int = 4096,
) -> dict:
    """Parse Chromium favicons from the Favicons database."""
    if error := _validate_positive_int("limit", limit):
        return error
    if error := _validate_positive_int("max_image_bytes", max_image_bytes):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "favicons")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "favicons", artifact_path)

    page_url = _normalize_filter(page_url)
    icon_url = _normalize_filter(icon_url)
    cache_key = _build_cache_key(
        "chromium:favicons", profile_dir, page_url, icon_url, limit, include_image, max_image_bytes
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["favicons"]) as staged_profile:
            staged_db_path = _artifact_presence(staged_profile, "favicons")
            with _sqlite_connection(staged_db_path) as connection:
                if not _sqlite_table_exists(connection, "icon_mapping") or not _sqlite_table_exists(
                    connection, "favicons"
                ):
                    raise RuntimeError("Favicons database missing expected tables")

                def _iter_records() -> Iterator[dict]:
                    for row in connection.execute(
                        """
                        SELECT
                            icon_mapping.page_url,
                            favicons.id AS icon_id,
                            favicons.url AS icon_url,
                            favicons.icon_type,
                            favicon_bitmaps.id AS bitmap_id,
                            favicon_bitmaps.last_updated,
                            favicon_bitmaps.last_requested,
                            favicon_bitmaps.image_data,
                            favicon_bitmaps.width,
                            favicon_bitmaps.height
                        FROM icon_mapping
                        JOIN favicons ON icon_mapping.icon_id = favicons.id
                        LEFT JOIN favicon_bitmaps ON favicons.id = favicon_bitmaps.icon_id
                        """
                    ):
                        if not _exact_match(page_url, _sqlite_row_value(row, "page_url")):
                            continue
                        if not _exact_match(icon_url, _sqlite_row_value(row, "icon_url")):
                            continue
                        image_data = _sqlite_row_value(row, "image_data") or b""
                        yield {
                            "page_url": _sqlite_row_value(row, "page_url"),
                            "icon_id": _sqlite_row_value(row, "icon_id"),
                            "icon_url": _sqlite_row_value(row, "icon_url"),
                            "icon_type": _sqlite_row_value(row, "icon_type"),
                            "bitmap_id": _sqlite_row_value(row, "bitmap_id"),
                            "last_updated_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "last_updated")
                            ),
                            "last_requested_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "last_requested")
                            ),
                            "width": _sqlite_row_value(row, "width"),
                            "height": _sqlite_row_value(row, "height"),
                            "image": None
                            if not include_image or not image_data
                            else _serialize_bytes(image_data, max_image_bytes),
                        }

                records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium favicons: {exc}",
            error_type="chromium_favicons_failed",
        )

    result = _base_result(profile_dir, "favicons", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "image_included": include_image,
        }
    )
    await cache.set(cache_key, result)
    return result


async def chromium_parse_web_data(
    profile_path: str,
    category: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse common Chromium Web Data tables from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error

    supported_categories = ("autofill", "keywords", "profiles")
    category = _normalize_filter(category)
    if category is not None and category not in supported_categories:
        return _input_error(
            f"Unsupported web data category: {category}",
            supported_categories=list(supported_categories),
        )

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "web_data")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "web_data", artifact_path)

    cache_key = _build_cache_key("chromium:web_data", profile_dir, category, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["web_data"]) as staged_profile:
            staged_db_path = _artifact_presence(staged_profile, "web_data")
            with _sqlite_connection(staged_db_path) as connection:
                category_specs = {
                    "autofill": {
                        "table": "autofill",
                        "transform": lambda row: {
                            "category": "autofill",
                            "name": _sqlite_row_value(row, "name"),
                            "value": _sqlite_row_value(row, "value"),
                            "count": _sqlite_row_value(row, "count"),
                            "date_created_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "date_created")
                            ),
                            "date_last_used_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "date_last_used")
                            ),
                        },
                    },
                    "keywords": {
                        "table": "keywords",
                        "transform": lambda row: {
                            "category": "keywords",
                            "short_name": _sqlite_row_value(row, "short_name"),
                            "keyword": _sqlite_row_value(row, "keyword"),
                            "url": _sqlite_row_value(row, "url"),
                            "favicon_url": _sqlite_row_value(row, "favicon_url"),
                            "safe_for_autoreplace": _sqlite_row_value(row, "safe_for_autoreplace"),
                            "originating_url": _sqlite_row_value(row, "originating_url"),
                            "date_created_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "date_created")
                            ),
                        },
                    },
                    "profiles": {
                        "table": "autofill_profiles",
                        "transform": lambda row: {
                            "category": "profiles",
                            "guid": _sqlite_row_value(row, "guid"),
                            "company_name": _sqlite_row_value(row, "company_name"),
                            "language_code": _sqlite_row_value(row, "language_code"),
                            "use_count": _sqlite_row_value(row, "use_count"),
                            "use_date_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "use_date")
                            ),
                            "date_modified_iso": _chromium_timestamp_to_iso(
                                _sqlite_row_value(row, "date_modified")
                            ),
                        },
                    },
                }

                selected_categories = (
                    (category,) if category is not None else supported_categories
                )

                def _iter_records() -> Iterator[dict]:
                    for category_name in selected_categories:
                        spec = category_specs[category_name]
                        if not _sqlite_table_exists(connection, spec["table"]):
                            continue
                        for row in connection.execute(f"SELECT * FROM {spec['table']}"):
                            yield spec["transform"](row)

                records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium Web Data: {exc}",
            error_type="chromium_web_data_failed",
        )

    result = _base_result(profile_dir, "web_data", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "category": category,
        }
    )
    await cache.set(cache_key, result)
    return result


async def chromium_parse_extensions(
    profile_path: str,
    extension_id: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium installed-extension metadata from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "extensions")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "extensions", artifact_path)

    extension_id = _normalize_filter(extension_id)
    name = _normalize_filter(name)
    cache_key = _build_cache_key("chromium:extensions", profile_dir, extension_id, name, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["extensions"]) as staged_profile:
            extensions_path = _artifact_presence(staged_profile, "extensions")
            extension_settings_lookup = {}
            for _, _, preferences_data in _iter_present_json_preferences(staged_profile):
                if not isinstance(preferences_data, dict):
                    continue
                settings = ((preferences_data.get("extensions") or {}).get("settings") or {})
                for ext_id, ext_settings in settings.items():
                    extension_settings_lookup.setdefault(ext_id, {}).update(ext_settings)

            def _iter_records() -> Iterator[dict]:
                for extension_dir in sorted(extensions_path.iterdir()):
                    if not extension_dir.is_dir():
                        continue
                    if not _exact_match(extension_id, extension_dir.name):
                        continue
                    for version_dir in sorted(extension_dir.iterdir()):
                        manifest_path = version_dir / "manifest.json"
                        if not manifest_path.is_file():
                            continue
                        manifest = _load_json_file(manifest_path)
                        resolved_name = _resolve_extension_message(version_dir, manifest, "name")
                        if not _exact_match(name, resolved_name):
                            continue
                        settings = extension_settings_lookup.get(extension_dir.name, {})
                        yield {
                            "extension_id": extension_dir.name,
                            "version": version_dir.name,
                            "name": resolved_name,
                            "description": _resolve_extension_message(
                                version_dir, manifest, "description"
                            ),
                            "manifest_version": manifest.get("manifest_version"),
                            "default_locale": manifest.get("default_locale"),
                            "permissions": _jsonify(manifest.get("permissions") or []),
                            "host_permissions": _jsonify(manifest.get("host_permissions") or []),
                            "optional_permissions": _jsonify(
                                manifest.get("optional_permissions") or []
                            ),
                            "update_url": manifest.get("update_url"),
                            "homepage_url": manifest.get("homepage_url"),
                            "state": settings.get("state"),
                            "location": settings.get("location"),
                            "from_webstore": settings.get("from_webstore"),
                            "was_installed_by_default": settings.get(
                                "was_installed_by_default"
                            ),
                            "creation_flags": settings.get("creation_flags"),
                            "manifest_path": str(manifest_path),
                            "extension_path": str(version_dir),
                        }

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium extensions: {exc}",
            error_type="chromium_extensions_failed",
        )

    result = _base_result(profile_dir, "extensions", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_preferences(
    profile_path: str,
    key_path: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse selected Chromium preferences from Preferences and Secure Preferences."""
    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "preferences")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "preferences", artifact_path)

    key_path = _normalize_filter(key_path)
    cache_key = _build_cache_key("chromium:preferences", profile_dir, key_path, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["preferences"]) as staged_profile:

            def _iter_records() -> Iterator[dict]:
                for source_name, source_path, preferences_data in _iter_present_json_preferences(staged_profile):
                    if key_path is not None:
                        try:
                            value = _get_json_path_value(preferences_data, key_path)
                        except (KeyError, IndexError, ValueError, TypeError):
                            continue
                        yield {
                            "source_file": source_name,
                            "path": str(source_path),
                            "key_path": key_path,
                            "value": _jsonify(value),
                        }
                        continue

                    for default_key_path in _PREFERENCE_KEY_PATHS:
                        try:
                            value = _get_json_path_value(preferences_data, default_key_path)
                        except (KeyError, IndexError, ValueError, TypeError):
                            continue
                        yield {
                            "source_file": source_name,
                            "path": str(source_path),
                            "key_path": default_key_path,
                            "value": _jsonify(value),
                        }

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium preferences: {exc}",
            error_type="chromium_preferences_failed",
        )

    result = _base_result(profile_dir, "preferences", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_bookmarks(
    profile_path: str,
    url: Optional[str] = None,
    title: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium bookmark URL entries from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "bookmarks")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "bookmarks", artifact_path)

    url = _normalize_filter(url)
    title = _normalize_filter(title)
    cache_key = _build_cache_key("chromium:bookmarks", profile_dir, url, title, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["bookmarks"]) as staged_profile:
            bookmarks_path = staged_profile / "Bookmarks"
            bookmark_data = json.loads(bookmarks_path.read_text(encoding="utf-8"))

            def _iter_records() -> Iterator[dict]:
                for root_name, root_node in (bookmark_data.get("roots") or {}).items():
                    if not isinstance(root_node, dict):
                        continue
                    for child in root_node.get("children", []):
                        if not isinstance(child, dict):
                            continue
                        for record in _iter_bookmark_url_nodes(root_name, child):
                            if not _exact_match(url, record["url"]):
                                continue
                            if not _exact_match(title, record["name"]):
                                continue
                            yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium bookmarks: {exc}",
            error_type="chromium_bookmarks_failed",
        )

    result = _base_result(profile_dir, "bookmarks", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_parse_logins(
    profile_path: str,
    origin_url: Optional[str] = None,
    username_value: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium saved-login metadata from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "logins")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "logins", artifact_path)

    origin_url = _normalize_filter(origin_url)
    username_value = _normalize_filter(username_value)
    cache_key = _build_cache_key(
        "chromium:logins", profile_dir, origin_url, username_value, limit
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["logins"]) as staged_profile:
            staged_db_path = _artifact_presence(staged_profile, "logins")

            def _iter_records() -> Iterator[sqlite3.Row]:
                for row in _login_db_rows(staged_db_path):
                    if not _exact_match(origin_url, _sqlite_row_value(row, "origin_url")):
                        continue
                    if not _exact_match(username_value, _sqlite_row_value(row, "username_value")):
                        continue
                    yield row

            records, truncated = _collect_records(
                _iter_records(), limit, lambda row: _login_metadata_from_row(row)
            )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium logins: {exc}",
            error_type="chromium_logins_failed",
        )

    result = _base_result(profile_dir, "logins", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_decrypt_logins(
    profile_path: str,
    local_state_path: Optional[str] = None,
    master_key_b64: Optional[str] = None,
    origin_url: Optional[str] = None,
    username_value: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Decrypt Chromium saved logins using Local State or a supplied master key."""
    if AESGCM is None:
        return _cryptography_dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "logins")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "decrypt_logins", artifact_path)

    provided_master_key, error = _provided_master_key(master_key_b64)
    if error:
        return error

    resolved_local_state_path, error = _resolve_local_state_path(profile_dir, local_state_path)
    if error:
        return error

    origin_url = _normalize_filter(origin_url)
    username_value = _normalize_filter(username_value)
    cache_key = _build_cache_key(
        "chromium:decrypt_logins",
        profile_dir,
        artifact_path,
        resolved_local_state_path,
        master_key_b64,
        origin_url,
        username_value,
        limit,
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    master_key = provided_master_key
    master_key_source = "provided_master_key" if provided_master_key is not None else None
    master_key_error = None

    if master_key is None and resolved_local_state_path is not None:
        if _platform_is_windows():
            try:
                master_key = _chromium_master_key_from_local_state(resolved_local_state_path)
                master_key_source = "local_state_dpapi"
            except Exception as exc:
                master_key_error = str(exc)
        else:
            master_key_error = (
                "Local State decryption requires Windows DPAPI unless master_key_b64 is provided"
            )

    try:
        with _staged_profile(profile_dir, ["logins"]) as staged_profile:
            staged_db_path = _artifact_presence(staged_profile, "logins")

            def _iter_records() -> Iterator[sqlite3.Row]:
                for row in _login_db_rows(staged_db_path):
                    if not _exact_match(origin_url, _sqlite_row_value(row, "origin_url")):
                        continue
                    if not _exact_match(username_value, _sqlite_row_value(row, "username_value")):
                        continue
                    yield row

            def _transform(row: sqlite3.Row) -> dict:
                record = _login_metadata_from_row(row)
                password_blob = _login_password_blob(row)
                scheme = record["password_encryption"]

                if scheme == "empty":
                    record["decrypt_status"] = "empty"
                    record["decrypted_password"] = ""
                    record["decrypt_error"] = None
                    return record

                try:
                    record["decrypted_password"] = _decrypt_chromium_login_blob(
                        password_blob, master_key
                    )
                    record["decrypt_status"] = "decrypted"
                    record["decrypt_error"] = None
                except ValueError as exc:
                    record["decrypted_password"] = None
                    if str(exc) == "master_key_required":
                        record["decrypt_status"] = "master_key_required"
                        record["decrypt_error"] = (
                            "Provide master_key_b64 or run on Windows with Local State available"
                        )
                    else:
                        record["decrypt_status"] = "decrypt_failed"
                        record["decrypt_error"] = str(exc)
                except InvalidTag:
                    record["decrypted_password"] = None
                    record["decrypt_status"] = "invalid_tag"
                    record["decrypt_error"] = "Master key or ciphertext is invalid"
                except NotImplementedError as exc:
                    record["decrypted_password"] = None
                    record["decrypt_status"] = "unsupported_encryption"
                    record["decrypt_error"] = str(exc)
                except OSError as exc:
                    record["decrypted_password"] = None
                    record["decrypt_status"] = (
                        "windows_dpapi_required" if not _platform_is_windows() else "dpapi_failed"
                    )
                    record["decrypt_error"] = str(exc)
                except Exception as exc:  # pragma: no cover - defensive path
                    record["decrypted_password"] = None
                    record["decrypt_status"] = "decrypt_failed"
                    record["decrypt_error"] = str(exc)

                return record

            records, truncated = _collect_records(_iter_records(), limit, _transform)
    except Exception as exc:
        return _input_error(
            f"Failed to decrypt Chromium logins: {exc}",
            error_type="chromium_decrypt_logins_failed",
        )

    decrypted_count = sum(1 for record in records if record.get("decrypt_status") == "decrypted")
    result = _base_result(profile_dir, "decrypt_logins", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "decrypted_count": decrypted_count,
            "failed_count": len(records) - decrypted_count,
            "master_key_source": master_key_source,
            "master_key_available": master_key is not None,
            "local_state_path": None
            if resolved_local_state_path is None
            else str(resolved_local_state_path),
            "master_key_error": master_key_error,
        }
    )
    await cache.set(cache_key, result)
    return result


async def chromium_parse_cookies(
    profile_path: str,
    host_key: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Chromium cookies from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "cookies")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "cookies", artifact_path)

    host_key = _normalize_filter(host_key)
    name = _normalize_filter(name)
    cache_key = _build_cache_key("chromium:cookies", profile_dir, artifact_path, host_key, name, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["cookies"]) as staged_profile:
            staged_db_path = _artifact_presence(staged_profile, "cookies")

            def _iter_records() -> Iterator[sqlite3.Row]:
                for row in _cookie_db_rows(staged_db_path):
                    if not _exact_match(host_key, _sqlite_row_value(row, "host_key")):
                        continue
                    if not _exact_match(name, _sqlite_row_value(row, "name")):
                        continue
                    yield row

            records, truncated = _collect_records(
                _iter_records(),
                limit,
                lambda row: {
                    "host_key": _sqlite_row_value(row, "host_key"),
                    "name": _sqlite_row_value(row, "name"),
                    "value": _sqlite_row_value(row, "value"),
                    "path": _sqlite_row_value(row, "path"),
                    "creation_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "creation_utc")
                    ),
                    "expires_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "expires_utc")
                    ),
                    "last_access_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "last_access_utc")
                    ),
                    "last_update_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "last_update_utc")
                    ),
                    "is_secure": bool(_sqlite_row_value(row, "is_secure", 0)),
                    "is_httponly": bool(_sqlite_row_value(row, "is_httponly", 0)),
                    "has_expires": bool(_sqlite_row_value(row, "has_expires", 0)),
                    "is_persistent": bool(_sqlite_row_value(row, "is_persistent", 0)),
                    "priority": _sqlite_row_value(row, "priority"),
                    "samesite": _sqlite_row_value(row, "samesite"),
                    "source_scheme": _sqlite_row_value(row, "source_scheme"),
                    "source_port": _sqlite_row_value(row, "source_port"),
                    "top_frame_site_key": _sqlite_row_value(row, "top_frame_site_key"),
                    "source_type": _sqlite_row_value(row, "source_type"),
                    **_cookie_encrypted_value_metadata(row),
                },
            )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Chromium cookies: {exc}",
            error_type="chromium_cookies_failed",
        )

    result = _base_result(profile_dir, "cookies", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def chromium_decrypt_cookies(
    profile_path: str,
    local_state_path: Optional[str] = None,
    master_key_b64: Optional[str] = None,
    host_key: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Decrypt Chromium cookies using Local State or a supplied master key."""
    if AESGCM is None:
        return _cryptography_dependency_error()

    if error := _validate_positive_int("limit", limit):
        return error

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    artifact_path = _artifact_presence(profile_dir, "cookies")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "decrypt_cookies", artifact_path)

    provided_master_key, error = _provided_master_key(master_key_b64)
    if error:
        return error

    resolved_local_state_path, error = _resolve_local_state_path(profile_dir, local_state_path)
    if error:
        return error

    host_key = _normalize_filter(host_key)
    name = _normalize_filter(name)
    cache_key = _build_cache_key(
        "chromium:decrypt_cookies",
        profile_dir,
        artifact_path,
        resolved_local_state_path,
        master_key_b64,
        host_key,
        name,
        limit,
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    master_key = provided_master_key
    master_key_source = "provided_master_key" if provided_master_key is not None else None
    master_key_error = None

    if master_key is None and resolved_local_state_path is not None:
        if _platform_is_windows():
            try:
                master_key = _chromium_master_key_from_local_state(resolved_local_state_path)
                master_key_source = "local_state_dpapi"
            except Exception as exc:
                master_key_error = str(exc)
        else:
            master_key_error = (
                "Local State decryption requires Windows DPAPI unless master_key_b64 is provided"
            )

    try:
        with _staged_profile(profile_dir, ["cookies"]) as staged_profile:
            staged_db_path = _artifact_presence(staged_profile, "cookies")

            def _iter_records() -> Iterator[sqlite3.Row]:
                for row in _cookie_db_rows(staged_db_path):
                    if not _exact_match(host_key, _sqlite_row_value(row, "host_key")):
                        continue
                    if not _exact_match(name, _sqlite_row_value(row, "name")):
                        continue
                    yield row

            def _transform(row: sqlite3.Row) -> dict:
                encrypted_value = _sqlite_row_value(row, "encrypted_value", b"") or b""
                record = {
                    "host_key": _sqlite_row_value(row, "host_key"),
                    "name": _sqlite_row_value(row, "name"),
                    "value": _sqlite_row_value(row, "value"),
                    "path": _sqlite_row_value(row, "path"),
                    "creation_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "creation_utc")
                    ),
                    "expires_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "expires_utc")
                    ),
                    "last_access_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "last_access_utc")
                    ),
                    "last_update_utc_iso": _chromium_timestamp_to_iso(
                        _sqlite_row_value(row, "last_update_utc")
                    ),
                    "is_secure": bool(_sqlite_row_value(row, "is_secure", 0)),
                    "is_httponly": bool(_sqlite_row_value(row, "is_httponly", 0)),
                    "has_expires": bool(_sqlite_row_value(row, "has_expires", 0)),
                    "is_persistent": bool(_sqlite_row_value(row, "is_persistent", 0)),
                    "priority": _sqlite_row_value(row, "priority"),
                    "samesite": _sqlite_row_value(row, "samesite"),
                    "source_scheme": _sqlite_row_value(row, "source_scheme"),
                    "source_port": _sqlite_row_value(row, "source_port"),
                    "top_frame_site_key": _sqlite_row_value(row, "top_frame_site_key"),
                    "source_type": _sqlite_row_value(row, "source_type"),
                    "value_encryption": _login_encryption_scheme(encrypted_value),
                    **_cookie_encrypted_value_metadata(row),
                }

                if record["value"] and not encrypted_value:
                    record["decrypted_value"] = record["value"]
                    record["decrypt_status"] = "plaintext"
                    record["decrypt_error"] = None
                    return record

                if not encrypted_value:
                    record["decrypted_value"] = ""
                    record["decrypt_status"] = "empty"
                    record["decrypt_error"] = None
                    return record

                try:
                    record["decrypted_value"] = _decrypt_chromium_login_blob(
                        encrypted_value, master_key
                    )
                    record["decrypt_status"] = "decrypted"
                    record["decrypt_error"] = None
                except ValueError as exc:
                    record["decrypted_value"] = None
                    if str(exc) == "master_key_required":
                        record["decrypt_status"] = "master_key_required"
                        record["decrypt_error"] = (
                            "Provide master_key_b64 or run on Windows with Local State available"
                        )
                    else:
                        record["decrypt_status"] = "decrypt_failed"
                        record["decrypt_error"] = str(exc)
                except InvalidTag:
                    record["decrypted_value"] = None
                    record["decrypt_status"] = "invalid_tag"
                    record["decrypt_error"] = "Master key or ciphertext is invalid"
                except NotImplementedError as exc:
                    record["decrypted_value"] = None
                    record["decrypt_status"] = "unsupported_encryption"
                    record["decrypt_error"] = str(exc)
                except OSError as exc:
                    record["decrypted_value"] = None
                    record["decrypt_status"] = (
                        "windows_dpapi_required" if not _platform_is_windows() else "dpapi_failed"
                    )
                    record["decrypt_error"] = str(exc)
                except Exception as exc:  # pragma: no cover - defensive path
                    record["decrypted_value"] = None
                    record["decrypt_status"] = "decrypt_failed"
                    record["decrypt_error"] = str(exc)

                return record

            records, truncated = _collect_records(_iter_records(), limit, _transform)
    except Exception as exc:
        return _input_error(
            f"Failed to decrypt Chromium cookies: {exc}",
            error_type="chromium_decrypt_cookies_failed",
        )

    decrypted_count = sum(1 for record in records if record.get("decrypt_status") in {"decrypted", "plaintext"})
    result = _base_result(profile_dir, "decrypt_cookies", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "decrypted_count": decrypted_count,
            "failed_count": len(records) - decrypted_count,
            "master_key_source": master_key_source,
            "master_key_available": master_key is not None,
            "local_state_path": None
            if resolved_local_state_path is None
            else str(resolved_local_state_path),
            "master_key_error": master_key_error,
        }
    )
    await cache.set(cache_key, result)
    return result


def _group_headers(headers: Iterable[tuple[str, str]]) -> dict:
    grouped_headers = {}
    for name, value in headers:
        grouped_headers.setdefault(name, [])
        grouped_headers[name].append(value)
    return grouped_headers
