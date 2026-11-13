"""Firefox basic artifact parsing tools."""

import base64
import copy
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import unquote, urlparse

from forensics_utils_mcp_server.cache import cache

try:
    import lz4.block
except ImportError:  # pragma: no cover - exercised via dependency checks
    lz4 = None
else:  # pragma: no cover - import alias setup
    lz4 = lz4.block


_ARTIFACT_LAYOUT = {
    "places": {
        "presence_path": Path("places.sqlite"),
        "stage_paths": (
            Path("places.sqlite"),
            Path("places.sqlite-journal"),
            Path("places.sqlite-wal"),
            Path("places.sqlite-shm"),
        ),
    },
    "cookies": {
        "presence_path": Path("cookies.sqlite"),
        "stage_paths": (
            Path("cookies.sqlite"),
            Path("cookies.sqlite-journal"),
            Path("cookies.sqlite-wal"),
            Path("cookies.sqlite-shm"),
        ),
    },
    "sessions": {
        "presence_paths": (Path("sessionstore.jsonlz4"), Path("sessionstore-backups")),
        "stage_paths": (Path("sessionstore.jsonlz4"), Path("sessionstore-backups")),
    },
    "favicons": {
        "presence_path": Path("favicons.sqlite"),
        "stage_paths": (
            Path("favicons.sqlite"),
            Path("favicons.sqlite-journal"),
            Path("favicons.sqlite-wal"),
            Path("favicons.sqlite-shm"),
        ),
    },
    "extensions": {
        "presence_path": Path("extensions.json"),
        "stage_paths": (Path("extensions.json"), Path("extensions")),
    },
    "preferences": {
        "presence_path": Path("prefs.js"),
        "stage_paths": (Path("prefs.js"), Path("user.js")),
    },
    "logins": {
        "presence_path": Path("logins.json"),
        "stage_paths": (
            Path("logins.json"),
            Path("key4.db"),
            Path("logins.db"),
            Path("cert9.db"),
            Path("pkcs11.txt"),
        ),
    },
    "web_data": {
        "presence_paths": (
            Path("formhistory.sqlite"),
            Path("permissions.sqlite"),
            Path("content-prefs.sqlite"),
            Path("search.json.mozlz4"),
        ),
        "stage_paths": (
            Path("formhistory.sqlite"),
            Path("formhistory.sqlite-journal"),
            Path("formhistory.sqlite-wal"),
            Path("formhistory.sqlite-shm"),
            Path("permissions.sqlite"),
            Path("permissions.sqlite-journal"),
            Path("permissions.sqlite-wal"),
            Path("permissions.sqlite-shm"),
            Path("content-prefs.sqlite"),
            Path("content-prefs.sqlite-journal"),
            Path("content-prefs.sqlite-wal"),
            Path("content-prefs.sqlite-shm"),
            Path("search.json.mozlz4"),
        ),
    },
    "local_storage": {
        "presence_paths": (Path("webappsstore.sqlite"), Path("storage", "default")),
        "stage_paths": (
            Path("webappsstore.sqlite"),
            Path("webappsstore.sqlite-journal"),
            Path("webappsstore.sqlite-wal"),
            Path("webappsstore.sqlite-shm"),
            Path("storage", "default"),
        ),
    },
    "indexeddb": {
        "presence_path": Path("storage", "default"),
        "stage_paths": (Path("storage", "default"),),
    },
    "cache": {
        "presence_path": Path("storage", "default"),
        "stage_paths": (Path("storage", "default"),),
    },
}

_FIREFOX_VISIT_TYPES = {
    1: "link",
    2: "typed",
    3: "bookmark",
    4: "embed",
    5: "redirect_permanent",
    6: "redirect_temporary",
    7: "download",
    8: "framed_link",
    9: "reload",
}
_MOZLZ4_MAGIC = b"mozLz40\0"
_FAVICON_PREVIEW_BYTES = 4096
_CACHE_BODY_PREVIEW_BYTES = 16384
_PREF_LINE_RE = re.compile(r'^user_pref\("(?P<key>(?:\\.|[^\"])*)",\s*(?P<value>.+)\);$')


def _lz4_dependency_error() -> dict:
    return {
        "status": "error",
        "error_type": "dependency_not_found",
        "message": "Python package 'lz4' is required for Firefox session parsing",
        "details": {"package": "lz4", "install_command": "pip install lz4>=4.4.5"},
    }


def _input_error(message: str, error_type: str = "invalid_input", **details: Any) -> dict:
    result = {"status": "error", "error_type": error_type, "message": message}
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


def _validate_positive_int(name: str, value: int) -> Optional[dict]:
    if value < 1:
        return _input_error(f"{name} must be greater than 0", parameter=name, value=value)
    return None


def _exact_match(expected: Optional[str], actual: Optional[str]) -> bool:
    if expected is None:
        return True
    return actual == expected


def _artifact_presence_paths(profile_path: Path, artifact_name: str) -> tuple[Path, ...]:
    artifact = _ARTIFACT_LAYOUT[artifact_name]
    if "presence_paths" in artifact:
        return tuple(profile_path / value for value in artifact["presence_paths"])
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


def _base_result(profile_path: Path, artifact_type: str, artifact_path: Path) -> dict:
    return {
        "status": "success",
        "browser_family": "firefox",
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


def _serialize_bytes(data: bytes, max_bytes: int) -> dict:
    preview = data[:max_bytes]
    return {
        "encoding": "base64",
        "size_bytes": len(data),
        "preview_base64": base64.b64encode(preview).decode("ascii"),
        "truncated": len(preview) < len(data),
    }


def _coerce_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    return None


def _decode_text_bytes(value: Optional[bytes]) -> Optional[str]:
    if value is None:
        return None
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _firefox_decrypt_dependency_error() -> dict:
    return {
        "status": "error",
        "error_type": "dependency_not_found",
        "message": "Optional Firefox login decryption dependency 'firefox_decrypt' is not installed",
        "details": {
            "package": "firefox_decrypt",
            "install_command": "pip install \"firefox-decrypt @ git+https://github.com/unode/firefox_decrypt.git\"",
        },
    }


def _jsonify(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return _serialize_bytes(value, _FAVICON_PREVIEW_BYTES)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if depth >= 4:
        return repr(value)
    if isinstance(value, dict):
        return {str(key): _jsonify(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(item, depth + 1) for item in value]
    if hasattr(value, "__dict__"):
        return {
            key: _jsonify(item, depth + 1)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    return repr(value)


def _unix_seconds_to_iso(value: Optional[Any]) -> Optional[str]:
    if value in (None, "", 0, "0"):
        return None
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def _unix_seconds_or_ms_to_iso(value: Optional[Any]) -> Optional[str]:
    if value in (None, "", 0, "0"):
        return None
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return None
    if numeric >= 10_000_000_000:
        return _unix_ms_to_iso(numeric)
    return _unix_seconds_to_iso(numeric)


def _unix_ms_to_iso(value: Optional[Any]) -> Optional[str]:
    if value in (None, "", 0, "0"):
        return None
    try:
        milliseconds = int(value)
    except (TypeError, ValueError):
        return None
    if milliseconds <= 0:
        return None
    return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc).isoformat()


def _unix_micros_to_iso(value: Optional[Any]) -> Optional[str]:
    if value in (None, "", 0, "0"):
        return None
    try:
        microseconds = int(value)
    except (TypeError, ValueError):
        return None
    if microseconds <= 0:
        return None
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc).isoformat()


def _sqlite_row_value(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    return row[key] if key in row.keys() else default


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


def _stage_paths_for_artifacts(artifact_names: Iterable[str]) -> list[Path]:
    stage_paths: list[Path] = []
    seen: set[Path] = set()
    for artifact_name in artifact_names:
        for stage_path in _ARTIFACT_LAYOUT[artifact_name]["stage_paths"]:
            if stage_path not in seen:
                stage_paths.append(stage_path)
                seen.add(stage_path)
    return stage_paths


@contextmanager
def _staged_profile(profile_path: Path, artifact_names: Iterable[str]) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(
        prefix="firefox-profile-", ignore_cleanup_errors=True
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
                    continue
            else:
                try:
                    shutil.copy2(source, destination)
                except (PermissionError, OSError):
                    continue
        yield staged_profile


def _visit_type_name(value: Optional[int]) -> str:
    if value is None:
        return "unknown"
    return _FIREFOX_VISIT_TYPES.get(value, f"unknown_{value}")


def _iter_download_candidate_rows(connection: sqlite3.Connection) -> Iterator[sqlite3.Row]:
    yield from connection.execute(
        """
        SELECT
            p.id AS place_id,
            p.url AS download_url,
            p.title AS title,
            h.id AS visit_id,
            h.visit_date,
            h.visit_type,
            h.from_visit,
            src.url AS source_url,
            src.title AS source_title
        FROM moz_places p
        JOIN moz_historyvisits h ON h.place_id = p.id
        LEFT JOIN moz_historyvisits from_visit ON from_visit.id = h.from_visit
        LEFT JOIN moz_places src ON src.id = from_visit.place_id
        WHERE p.url LIKE 'file:%' OR h.visit_type = 7
        ORDER BY h.visit_date DESC
        """
    )


def _download_file_name(download_url: Optional[str]) -> Optional[str]:
    if not download_url:
        return None
    parsed = urlparse(download_url)
    return Path(unquote(parsed.path)).name or None


def _bookmark_tree_info(bookmark_id: int, bookmark_rows_by_id: dict[int, sqlite3.Row]) -> tuple[Optional[str], list[str], list[str]]:
    current = bookmark_rows_by_id.get(bookmark_id)
    if current is None:
        return None, [], []
    parent_id = current["parent"]
    full_path: list[str] = []
    while parent_id in bookmark_rows_by_id:
        parent = bookmark_rows_by_id[parent_id]
        parent_title = parent["title"] or ""
        if parent_id == 1 or parent_title in {"", "places root"}:
            break
        full_path.append(parent_title)
        parent_id = parent["parent"]
    full_path.reverse()
    source_root = full_path[0] if full_path else None
    folder_path = full_path[1:] if len(full_path) > 1 else []
    return source_root, folder_path, full_path


def _parse_pref_value(raw_value: str) -> Any:
    raw_value = raw_value.strip()
    if raw_value == "true":
        return True
    if raw_value == "false":
        return False
    if raw_value == "null":
        return None
    if raw_value.startswith('"') and raw_value.endswith('"'):
        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            return raw_value[1:-1]
    try:
        return int(raw_value)
    except ValueError:
        pass
    try:
        return float(raw_value)
    except ValueError:
        pass
    return raw_value


def _parse_prefs_file(prefs_path: Path) -> list[dict]:
    results = []
    for line_number, raw_line in enumerate(prefs_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw_line.strip()
        if not line.startswith("user_pref("):
            continue
        match = _PREF_LINE_RE.match(line)
        if match is None:
            continue
        key = bytes(match.group("key"), "utf-8").decode("unicode_escape")
        results.append(
            {
                "key_path": key,
                "value": _parse_pref_value(match.group("value")),
                "source_file": prefs_path.name,
                "line_number": line_number,
            }
        )
    return results


def _decompress_mozlz4(file_path: Path) -> dict:
    if lz4 is None:
        raise RuntimeError("Python package 'lz4' is required")
    raw = file_path.read_bytes()
    if not raw.startswith(_MOZLZ4_MAGIC):
        raise RuntimeError(f"File does not use mozLz4 format: {file_path.name}")
    decompressed = lz4.decompress(raw[len(_MOZLZ4_MAGIC) :])
    return json.loads(decompressed)


def _iter_session_files(profile_path: Path) -> Iterator[Path]:
    main_file = profile_path / "sessionstore.jsonlz4"
    if main_file.is_file():
        yield main_file
    backups_dir = profile_path / "sessionstore-backups"
    if backups_dir.is_dir():
        for candidate in sorted(backups_dir.iterdir()):
            if candidate.is_file() and candidate.suffix == ".jsonlz4":
                yield candidate


def _iter_session_records(profile_path: Path) -> Iterator[dict]:
    for session_file in _iter_session_files(profile_path):
        session_data = _decompress_mozlz4(session_file)
        selected_window = session_data.get("selectedWindow")
        for window_index, window in enumerate(session_data.get("windows", []), start=1):
            selected_tab = window.get("selected")
            for tab_index, tab in enumerate(window.get("tabs", []), start=1):
                current_entry_index = tab.get("index", 1)
                for entry_index, entry in enumerate(tab.get("entries", []), start=1):
                    yield {
                        "source_file": session_file.name,
                        "window_index": window_index,
                        "tab_index": tab_index,
                        "entry_index": entry_index,
                        "is_selected_window": selected_window == window_index,
                        "is_selected_tab": selected_tab == tab_index,
                        "is_current_entry": current_entry_index == entry_index,
                        "url": entry.get("url"),
                        "title": entry.get("title"),
                        "original_uri": entry.get("originalURI"),
                        "referrer": entry.get("referrerInfo"),
                        "triggering_principal_base64": entry.get("triggeringPrincipal_base64"),
                        "docshell_uuid": tab.get("userTypedValue"),
                    }


def _iter_session_storage_records(profile_path: Path) -> Iterator[dict]:
    for session_file in _iter_session_files(profile_path):
        session_data = _decompress_mozlz4(session_file)
        for window_index, window in enumerate(session_data.get("windows", []), start=1):
            for tab_index, tab in enumerate(window.get("tabs", []), start=1):
                storage = tab.get("storage")
                if not isinstance(storage, dict):
                    continue
                for host, values in storage.items():
                    if isinstance(values, dict):
                        for storage_key, storage_value in values.items():
                            yield {
                                "source_file": session_file.name,
                                "window_index": window_index,
                                "tab_index": tab_index,
                                "host": host,
                                "key": storage_key,
                                "value": _jsonify(storage_value),
                            }
                    else:
                        yield {
                            "source_file": session_file.name,
                            "window_index": window_index,
                            "tab_index": tab_index,
                            "host": host,
                            "key": None,
                            "value": _jsonify(values),
                        }


def _iter_storage_default_origins(profile_path: Path) -> Iterator[Path]:
    storage_default = profile_path / "storage" / "default"
    if not storage_default.is_dir():
        return
    for child in sorted(storage_default.iterdir()):
        if child.is_dir():
            yield child


def _search_engines_from_mozlz4(path: Path) -> list[dict]:
    data = _decompress_mozlz4(path)
    results = []
    for engine in data.get("engines", []):
        results.append(
            {
                "category": "search_engines",
                "id": engine.get("id"),
                "name": engine.get("_name"),
                "is_config_engine": engine.get("_isConfigEngine"),
                "meta_data": _jsonify(engine.get("_metaData") or {}),
            }
        )
    return results


def _local_storage_value_payload(raw_value: Any, compression_type: Any) -> tuple[Optional[str], Optional[dict]]:
    byte_value = _coerce_bytes(raw_value)
    if byte_value is None:
        if raw_value is None:
            return None, None
        return str(raw_value), None
    decoded = _decode_text_bytes(byte_value)
    if compression_type in {None, 0} and decoded is not None:
        return decoded, None
    if decoded is not None and compression_type in {None, 0}:
        return decoded, None
    return decoded, _serialize_bytes(byte_value, _FAVICON_PREVIEW_BYTES)


def _iter_local_storage_records(profile_path: Path) -> Iterator[dict]:
    legacy_db = profile_path / "webappsstore.sqlite"
    if legacy_db.exists():
        with _sqlite_connection(legacy_db) as connection:
            if _sqlite_table_exists(connection, "webappsstore2"):
                for row in connection.execute("SELECT * FROM webappsstore2"):
                    value_text, value_binary = _local_storage_value_payload(row["value"], 0)
                    yield {
                        "source": "webappsstore2",
                        "origin_attributes": row["originAttributes"],
                        "origin_key": row["originKey"],
                        "scope": row["scope"],
                        "key": row["key"],
                        "value": value_text,
                        "value_binary": value_binary,
                    }

    for origin_dir in _iter_storage_default_origins(profile_path):
        ls_db = origin_dir / "ls" / "data.sqlite"
        if not ls_db.exists():
            continue
        with _sqlite_connection(ls_db) as connection:
            if not _sqlite_table_exists(connection, "data"):
                continue
            metadata_row = None
            if _sqlite_table_exists(connection, "database"):
                metadata_row = connection.execute("SELECT * FROM database LIMIT 1").fetchone()
            for row in connection.execute("SELECT * FROM data"):
                value_text, value_binary = _local_storage_value_payload(
                    row["value"], row["compression_type"]
                )
                yield {
                    "source": "storage_ls",
                    "host_id": origin_dir.name,
                    "origin": None if metadata_row is None else metadata_row["origin"],
                    "key": row["key"],
                    "utf16_length": row["utf16_length"],
                    "conversion_type": row["conversion_type"],
                    "compression_type": row["compression_type"],
                    "last_access_time_iso": _unix_micros_to_iso(row["last_access_time"]),
                    "value": value_text,
                    "value_binary": value_binary,
                }


def _indexeddb_database_rows(sqlite_path: Path) -> tuple[Optional[sqlite3.Row], dict[int, sqlite3.Row]]:
    with _sqlite_connection(sqlite_path) as connection:
        database_row = None
        if _sqlite_table_exists(connection, "database"):
            database_row = connection.execute("SELECT * FROM database LIMIT 1").fetchone()
        object_stores: dict[int, sqlite3.Row] = {}
        if _sqlite_table_exists(connection, "object_store"):
            object_stores = {
                row["id"]: row
                for row in connection.execute("SELECT * FROM object_store")
            }
    return database_row, object_stores


def _serialize_indexeddb_value(value: Any) -> tuple[Optional[str], Optional[dict]]:
    byte_value = _coerce_bytes(value)
    if byte_value is None:
        if value is None:
            return None, None
        return str(value), None
    decoded = _decode_text_bytes(byte_value)
    if decoded is not None:
        return decoded, None
    return None, _serialize_bytes(byte_value, _FAVICON_PREVIEW_BYTES)


def _iter_indexeddb_records(profile_path: Path) -> Iterator[dict]:
    for origin_dir in _iter_storage_default_origins(profile_path):
        idb_dir = origin_dir / "idb"
        if not idb_dir.is_dir():
            continue
        for sqlite_path in sorted(idb_dir.glob("*.sqlite")):
            if sqlite_path.name.endswith(("-wal.sqlite", "-shm.sqlite")):
                continue
            with _sqlite_connection(sqlite_path) as connection:
                if not _sqlite_table_exists(connection, "database") or not _sqlite_table_exists(connection, "object_data"):
                    continue
                database_row = connection.execute("SELECT * FROM database LIMIT 1").fetchone()
                object_stores = {}
                if _sqlite_table_exists(connection, "object_store"):
                    object_stores = {
                        row["id"]: row
                        for row in connection.execute("SELECT * FROM object_store")
                    }
                for row in connection.execute("SELECT * FROM object_data"):
                    key_text, key_binary = _serialize_indexeddb_value(row["key"])
                    data_text, data_binary = _serialize_indexeddb_value(row["data"])
                    object_store = object_stores.get(row["object_store_id"])
                    yield {
                        "host_id": origin_dir.name,
                        "database_name": None if database_row is None else database_row["name"],
                        "origin": None if database_row is None else database_row["origin"],
                        "database_version": None if database_row is None else database_row["version"],
                        "object_store_id": row["object_store_id"],
                        "object_store_name": None if object_store is None else object_store["name"],
                        "object_store_key_path": None if object_store is None else object_store["key_path"],
                        "key": key_text,
                        "key_binary": key_binary,
                        "index_data_values": row["index_data_values"],
                        "file_ids": row["file_ids"],
                        "data": data_text,
                        "data_binary": data_binary,
                        "source_file": sqlite_path.name,
                    }


def _cache_request_url(row: sqlite3.Row) -> str:
    base = row["request_url_no_query"] or ""
    query = row["request_url_query"] or ""
    fragment = row["request_url_fragment"] or ""
    url = base
    if query:
        url = f"{url}?{query}"
    if fragment:
        url = f"{url}#{fragment}"
    return url


def _cache_morgue_file(cache_dir: Path, response_body_id: Optional[str]) -> Optional[Path]:
    if not response_body_id:
        return None
    morgue_dir = cache_dir / "morgue"
    if not morgue_dir.is_dir():
        return None
    matches = list(morgue_dir.rglob(f"{response_body_id}.final"))
    return matches[0] if matches else None


def _group_rows_by_entry_id(connection: sqlite3.Connection, table_name: str) -> dict[int, list[sqlite3.Row]]:
    grouped: dict[int, list[sqlite3.Row]] = {}
    if not _sqlite_table_exists(connection, table_name):
        return grouped
    for row in connection.execute(f"SELECT * FROM {table_name}"):
        grouped.setdefault(row["entry_id"], []).append(row)
    return grouped


def _iter_cache_records(profile_path: Path, include_body: bool, max_body_bytes: int) -> Iterator[dict]:
    for origin_dir in _iter_storage_default_origins(profile_path):
        cache_dir = origin_dir / "cache"
        cache_db = cache_dir / "caches.sqlite"
        if not cache_db.exists():
            continue
        with _sqlite_connection(cache_db) as connection:
            if not _sqlite_table_exists(connection, "entries"):
                continue
            response_headers_by_entry = _group_rows_by_entry_id(connection, "response_headers")
            response_urls_by_entry = _group_rows_by_entry_id(connection, "response_url_list")
            for row in connection.execute("SELECT * FROM entries ORDER BY id DESC"):
                response_body_id = row["response_body_id"]
                morgue_file = _cache_morgue_file(cache_dir, response_body_id) if include_body else None
                body = None
                if include_body and morgue_file is not None:
                    body = _serialize_bytes(morgue_file.read_bytes(), max_body_bytes)
                yield {
                    "host_id": origin_dir.name,
                    "entry_id": row["id"],
                    "request_method": row["request_method"],
                    "request_url": _cache_request_url(row),
                    "request_referrer": row["request_referrer"],
                    "request_mode": row["request_mode"],
                    "request_credentials": row["request_credentials"],
                    "response_type": row["response_type"],
                    "response_status": row["response_status"],
                    "response_status_text": row["response_status_text"],
                    "response_url_list": [header_row["url"] for header_row in response_urls_by_entry.get(row["id"], [])],
                    "response_headers": {
                        header_row["name"]: header_row["value"]
                        for header_row in response_headers_by_entry.get(row["id"], [])
                    },
                    "response_body_id": response_body_id,
                    "response_body_disk_size": row["response_body_disk_size"],
                    "response_body_path": None if morgue_file is None else str(morgue_file),
                    "body": body,
                    "cache_id": row["cache_id"],
                    "request_cache": row["request_cache"],
                    "security_info_id": row["response_security_info_id"],
                }


def _firefox_decrypt_command() -> Optional[list[str]]:
    executable = shutil.which("firefox-decrypt")
    if executable:
        return [executable]
    if importlib.util.find_spec("firefox_decrypt") is not None:
        return [sys.executable, "-m", "firefox_decrypt"]
    return None


def _summarize_places(profile_path: Path, sample_limit: int) -> dict:
    places_path = _artifact_presence(profile_path, "places")
    with _sqlite_connection(places_path) as connection:
        history_count = connection.execute("SELECT COUNT(*) FROM moz_historyvisits").fetchone()[0]
        bookmark_count = connection.execute(
            "SELECT COUNT(*) FROM moz_bookmarks WHERE type = 1"
        ).fetchone()[0]
        download_count = sum(1 for _ in _iter_download_candidate_rows(connection))
        sample_history = [
            {"url": row["url"], "title": row["title"]}
            for row in connection.execute(
                "SELECT url, title FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT ?",
                (sample_limit,),
            )
        ]
    return {
        "present": True,
        "history_count": history_count,
        "bookmark_count": bookmark_count,
        "download_count": download_count,
        "history_sample": sample_history,
    }


def _summarize_cookies(profile_path: Path, sample_limit: int) -> dict:
    cookies_path = _artifact_presence(profile_path, "cookies")
    with _sqlite_connection(cookies_path) as connection:
        cookie_count = connection.execute("SELECT COUNT(*) FROM moz_cookies").fetchone()[0]
        sample = [
            {"host": row["host"], "name": row["name"]}
            for row in connection.execute(
                "SELECT host, name FROM moz_cookies ORDER BY lastAccessed DESC LIMIT ?",
                (sample_limit,),
            )
        ]
    return {"present": True, "cookie_count": cookie_count, "cookies_sample": sample}


def _summarize_sessions(profile_path: Path, sample_limit: int) -> dict:
    files = list(_iter_session_files(profile_path))
    sample = [file_path.name for file_path in files[:sample_limit]]
    main_windows = None
    if files:
        main_windows = len((_decompress_mozlz4(files[0]).get("windows") or []))
    return {
        "present": True,
        "session_file_count": len(files),
        "session_files_sample": sample,
        "main_window_count": main_windows,
    }


def _summarize_favicons(profile_path: Path, sample_limit: int) -> dict:
    favicons_path = _artifact_presence(profile_path, "favicons")
    with _sqlite_connection(favicons_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM moz_icons_to_pages").fetchone()[0]
        sample = [
            {"page_url": row["page_url"], "icon_url": row["icon_url"]}
            for row in connection.execute(
                """
                SELECT p.page_url, i.icon_url
                FROM moz_pages_w_icons p
                JOIN moz_icons_to_pages ip ON ip.page_id = p.id
                JOIN moz_icons i ON i.id = ip.icon_id
                LIMIT ?
                """,
                (sample_limit,),
            )
        ]
    return {"present": True, "favicon_mapping_count": count, "favicons_sample": sample}


def _summarize_extensions(profile_path: Path, sample_limit: int) -> dict:
    extensions_path = _artifact_presence(profile_path, "extensions")
    data = json.loads(extensions_path.read_text(encoding="utf-8"))
    addons = data.get("addons") or []
    sample = [{"id": addon.get("id"), "name": (addon.get("defaultLocale") or {}).get("name")} for addon in addons[:sample_limit]]
    return {"present": True, "extension_count": len(addons), "extensions_sample": sample}


def _summarize_preferences(profile_path: Path, sample_limit: int) -> dict:
    prefs_path = _artifact_presence(profile_path, "preferences")
    prefs = _parse_prefs_file(prefs_path)
    sample = [{"key_path": pref["key_path"], "value": pref["value"]} for pref in prefs[:sample_limit]]
    return {"present": True, "preference_count": len(prefs), "preferences_sample": sample}


def _summarize_logins(profile_path: Path, sample_limit: int) -> dict:
    logins_path = _artifact_presence(profile_path, "logins")
    data = json.loads(logins_path.read_text(encoding="utf-8"))
    logins = data.get("logins") or []
    sample = [{"hostname": login.get("hostname"), "guid": login.get("guid"), "encType": login.get("encType")} for login in logins[:sample_limit]]
    return {
        "present": True,
        "login_count": len(logins),
        "key4_db_present": (profile_path / "key4.db").exists(),
        "logins_sample": sample,
    }


def _summarize_session_storage(profile_path: Path, sample_limit: int) -> dict:
    records = list(_iter_session_storage_records(profile_path))
    sample = [
        {"host": record["host"], "key": record["key"], "source_file": record["source_file"]}
        for record in records[:sample_limit]
    ]
    return {
        "present": True,
        "session_storage_record_count": len(records),
        "session_storage_sample": sample,
    }


def _summarize_web_data(profile_path: Path, sample_limit: int) -> dict:
    categories = []
    if (profile_path / "formhistory.sqlite").exists():
        categories.append("form_history")
    if (profile_path / "permissions.sqlite").exists():
        categories.append("permissions")
    if (profile_path / "content-prefs.sqlite").exists():
        categories.append("content_prefs")
    if (profile_path / "search.json.mozlz4").exists():
        categories.append("search_engines")
    return {
        "present": True,
        "category_count": len(categories),
        "categories": categories[:sample_limit],
    }


def _summarize_local_storage(profile_path: Path, sample_limit: int) -> dict:
    records = list(_iter_local_storage_records(profile_path))
    sample = [
        {
            "source": record["source"],
            "key": record["key"],
            "origin": record.get("origin") or record.get("origin_key") or record.get("host_id"),
        }
        for record in records[:sample_limit]
    ]
    return {
        "present": True,
        "local_storage_record_count": len(records),
        "local_storage_sample": sample,
    }


def _summarize_indexeddb(profile_path: Path, sample_limit: int) -> dict:
    records = list(_iter_indexeddb_records(profile_path))
    sample = [
        {
            "host_id": record["host_id"],
            "database_name": record["database_name"],
            "object_store_name": record["object_store_name"],
        }
        for record in records[:sample_limit]
    ]
    return {
        "present": True,
        "indexeddb_record_count": len(records),
        "indexeddb_sample": sample,
    }


def _summarize_cache(profile_path: Path, sample_limit: int) -> dict:
    records = list(_iter_cache_records(profile_path, include_body=False, max_body_bytes=_CACHE_BODY_PREVIEW_BYTES))
    sample = [
        {
            "host_id": record["host_id"],
            "request_url": record["request_url"],
            "response_status": record["response_status"],
        }
        for record in records[:sample_limit]
    ]
    return {
        "present": True,
        "cache_record_count": len(records),
        "cache_sample": sample,
    }


async def firefox_profile_summary(profile_path: str, sample_limit: int = 10) -> dict:
    """Summarize basic Firefox artifacts available in a browser profile."""
    if error := _validate_positive_int("sample_limit", sample_limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error

    cache_key = _build_cache_key("firefox:summary", profile_dir, sample_limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    artifacts = {
        "history": {"present": False},
        "bookmarks": {"present": False},
        "downloads": {"present": False},
        "cookies": {"present": False},
        "sessions": {"present": False},
        "session_storage": {"present": False},
        "favicons": {"present": False},
        "extensions": {"present": False},
        "preferences": {"present": False},
        "logins": {"present": False},
        "web_data": {"present": False},
        "local_storage": {"present": False},
        "indexeddb": {"present": False},
        "cache": {"present": False},
    }
    available_artifacts: list[str] = []
    result = _base_result(profile_dir, "profile_summary", profile_dir)
    result["artifacts"] = artifacts
    result["available_artifacts"] = available_artifacts

    with _staged_profile(profile_dir, _ARTIFACT_LAYOUT.keys()) as staged_profile:
        if _artifact_presence(staged_profile, "places").exists():
            try:
                places_summary = _summarize_places(staged_profile, sample_limit)
                artifacts["history"] = {"present": True, "history_count": places_summary["history_count"], "history_sample": places_summary["history_sample"]}
                artifacts["bookmarks"] = {"present": True, "bookmark_count": places_summary["bookmark_count"]}
                artifacts["downloads"] = {"present": True, "download_count": places_summary["download_count"]}
                available_artifacts.extend(["history", "bookmarks", "downloads"])
            except Exception as exc:
                artifacts["history"] = {"present": True, "error": str(exc)}
                artifacts["bookmarks"] = {"present": True, "error": str(exc)}
                artifacts["downloads"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "cookies").exists():
            try:
                artifacts["cookies"] = _summarize_cookies(staged_profile, sample_limit)
                available_artifacts.append("cookies")
            except Exception as exc:
                artifacts["cookies"] = {"present": True, "error": str(exc)}

        if any(path.exists() for path in _artifact_presence_paths(staged_profile, "sessions")):
            try:
                artifacts["sessions"] = _summarize_sessions(staged_profile, sample_limit)
                available_artifacts.append("sessions")
            except Exception as exc:
                artifacts["sessions"] = {"present": True, "error": str(exc)}
            try:
                artifacts["session_storage"] = _summarize_session_storage(staged_profile, sample_limit)
                available_artifacts.append("session_storage")
            except Exception as exc:
                artifacts["session_storage"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "favicons").exists():
            try:
                artifacts["favicons"] = _summarize_favicons(staged_profile, sample_limit)
                available_artifacts.append("favicons")
            except Exception as exc:
                artifacts["favicons"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "extensions").exists():
            try:
                artifacts["extensions"] = _summarize_extensions(staged_profile, sample_limit)
                available_artifacts.append("extensions")
            except Exception as exc:
                artifacts["extensions"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "preferences").exists():
            try:
                artifacts["preferences"] = _summarize_preferences(staged_profile, sample_limit)
                available_artifacts.append("preferences")
            except Exception as exc:
                artifacts["preferences"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "logins").exists():
            try:
                artifacts["logins"] = _summarize_logins(staged_profile, sample_limit)
                available_artifacts.append("logins")
            except Exception as exc:
                artifacts["logins"] = {"present": True, "error": str(exc)}

        if any(path.exists() for path in _artifact_presence_paths(staged_profile, "web_data")):
            try:
                artifacts["web_data"] = _summarize_web_data(staged_profile, sample_limit)
                available_artifacts.append("web_data")
            except Exception as exc:
                artifacts["web_data"] = {"present": True, "error": str(exc)}

        if any(path.exists() for path in _artifact_presence_paths(staged_profile, "local_storage")):
            try:
                artifacts["local_storage"] = _summarize_local_storage(staged_profile, sample_limit)
                available_artifacts.append("local_storage")
            except Exception as exc:
                artifacts["local_storage"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "indexeddb").exists():
            try:
                artifacts["indexeddb"] = _summarize_indexeddb(staged_profile, sample_limit)
                available_artifacts.append("indexeddb")
            except Exception as exc:
                artifacts["indexeddb"] = {"present": True, "error": str(exc)}

        if _artifact_presence(staged_profile, "cache").exists():
            try:
                artifacts["cache"] = _summarize_cache(staged_profile, sample_limit)
                available_artifacts.append("cache")
            except Exception as exc:
                artifacts["cache"] = {"present": True, "error": str(exc)}

    if not available_artifacts:
        result["message"] = "No supported Firefox artifacts found in this profile"

    await cache.set(cache_key, result)
    return result


async def firefox_parse_history(
    profile_path: str,
    url: Optional[str] = None,
    title: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox browsing history records from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "places")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "history", artifact_path)

    url = _normalize_filter(url)
    title = _normalize_filter(title)
    cache_key = _build_cache_key("firefox:history", profile_dir, url, title, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["places"]) as staged_profile:
            staged_places = _artifact_presence(staged_profile, "places")
            with _sqlite_connection(staged_places) as connection:
                def _iter_records() -> Iterator[sqlite3.Row]:
                    for row in connection.execute(
                        """
                        SELECT
                            p.id AS place_id,
                            p.url,
                            p.title,
                            p.description,
                            p.preview_image_url,
                            p.visit_count,
                            p.hidden,
                            p.typed,
                            p.guid,
                            h.id AS visit_id,
                            h.visit_date,
                            h.visit_type,
                            h.from_visit,
                            src.url AS from_url,
                            src.title AS from_title
                        FROM moz_places p
                        JOIN moz_historyvisits h ON h.place_id = p.id
                        LEFT JOIN moz_historyvisits from_visit ON from_visit.id = h.from_visit
                        LEFT JOIN moz_places src ON src.id = from_visit.place_id
                        ORDER BY h.visit_date DESC
                        """
                    ):
                        if not _exact_match(url, row["url"]):
                            continue
                        if not _exact_match(title, row["title"]):
                            continue
                        yield row

                records, truncated = _collect_records(
                    _iter_records(),
                    limit,
                    lambda row: {
                        "visit_id": row["visit_id"],
                        "place_id": row["place_id"],
                        "url": row["url"],
                        "title": row["title"],
                        "description": row["description"],
                        "preview_image_url": row["preview_image_url"],
                        "visit_date_iso": _unix_micros_to_iso(row["visit_date"]),
                        "visit_type": row["visit_type"],
                        "visit_type_name": _visit_type_name(row["visit_type"]),
                        "visit_count": row["visit_count"],
                        "hidden": bool(row["hidden"]),
                        "typed": bool(row["typed"]),
                        "guid": row["guid"],
                        "from_visit_id": row["from_visit"],
                        "from_url": row["from_url"],
                        "from_title": row["from_title"],
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox history: {exc}",
            error_type="firefox_history_failed",
        )

    result = _base_result(profile_dir, "history", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_bookmarks(
    profile_path: str,
    url: Optional[str] = None,
    title: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox bookmark entries from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "places")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "bookmarks", artifact_path)

    url = _normalize_filter(url)
    title = _normalize_filter(title)
    cache_key = _build_cache_key("firefox:bookmarks", profile_dir, url, title, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["places"]) as staged_profile:
            staged_places = _artifact_presence(staged_profile, "places")
            with _sqlite_connection(staged_places) as connection:
                bookmark_rows = list(
                    connection.execute(
                        "SELECT id, parent, type, title, guid, dateAdded, lastModified FROM moz_bookmarks"
                    )
                )
                bookmark_rows_by_id = {row["id"]: row for row in bookmark_rows}

                def _iter_records() -> Iterator[sqlite3.Row]:
                    for row in connection.execute(
                        """
                        SELECT
                            b.id,
                            b.parent,
                            b.title AS bookmark_title,
                            b.guid,
                            b.dateAdded,
                            b.lastModified,
                            p.url,
                            p.title AS page_title
                        FROM moz_bookmarks b
                        JOIN moz_places p ON p.id = b.fk
                        WHERE b.type = 1
                        ORDER BY b.lastModified DESC
                        """
                    ):
                        if not _exact_match(url, row["url"]):
                            continue
                        bookmark_title = row["bookmark_title"] or row["page_title"]
                        if not _exact_match(title, bookmark_title):
                            continue
                        yield row

                def _transform(row: sqlite3.Row) -> dict:
                    source_root, folder_path, full_folder_path = _bookmark_tree_info(row["id"], bookmark_rows_by_id)
                    bookmark_title = row["bookmark_title"] or row["page_title"]
                    return {
                        "bookmark_id": row["id"],
                        "guid": row["guid"],
                        "title": bookmark_title,
                        "bookmark_title": row["bookmark_title"],
                        "page_title": row["page_title"],
                        "url": row["url"],
                        "date_added_iso": _unix_micros_to_iso(row["dateAdded"]),
                        "last_modified_iso": _unix_micros_to_iso(row["lastModified"]),
                        "source_root": source_root,
                        "folder_path": folder_path,
                        "full_folder_path": full_folder_path,
                        "folder_path_display": " / ".join(full_folder_path),
                    }

                records, truncated = _collect_records(_iter_records(), limit, _transform)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox bookmarks: {exc}",
            error_type="firefox_bookmarks_failed",
        )

    result = _base_result(profile_dir, "bookmarks", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_downloads(
    profile_path: str,
    download_url: Optional[str] = None,
    source_url: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox download candidates from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "places")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "downloads", artifact_path)

    download_url = _normalize_filter(download_url)
    source_url = _normalize_filter(source_url)
    cache_key = _build_cache_key("firefox:downloads", profile_dir, download_url, source_url, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["places"]) as staged_profile:
            staged_places = _artifact_presence(staged_profile, "places")
            with _sqlite_connection(staged_places) as connection:
                def _iter_records() -> Iterator[sqlite3.Row]:
                    for row in _iter_download_candidate_rows(connection):
                        if not _exact_match(download_url, row["download_url"]):
                            continue
                        if not _exact_match(source_url, row["source_url"]):
                            continue
                        yield row

                records, truncated = _collect_records(
                    _iter_records(),
                    limit,
                    lambda row: {
                        "visit_id": row["visit_id"],
                        "place_id": row["place_id"],
                        "download_url": row["download_url"],
                        "file_name": _download_file_name(row["download_url"]),
                        "title": row["title"],
                        "source_url": row["source_url"],
                        "source_title": row["source_title"],
                        "visit_date_iso": _unix_micros_to_iso(row["visit_date"]),
                        "visit_type": row["visit_type"],
                        "visit_type_name": _visit_type_name(row["visit_type"]),
                        "record_source": "places_file_url",
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox downloads: {exc}",
            error_type="firefox_downloads_failed",
        )

    result = _base_result(profile_dir, "downloads", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_cookies(
    profile_path: str,
    host: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox cookies from a profile."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "cookies")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "cookies", artifact_path)

    host = _normalize_filter(host)
    name = _normalize_filter(name)
    cache_key = _build_cache_key("firefox:cookies", profile_dir, host, name, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["cookies"]) as staged_profile:
            staged_cookies = _artifact_presence(staged_profile, "cookies")
            with _sqlite_connection(staged_cookies) as connection:
                def _iter_records() -> Iterator[sqlite3.Row]:
                    for row in connection.execute(
                        "SELECT * FROM moz_cookies ORDER BY lastAccessed DESC"
                    ):
                        if not _exact_match(host, row["host"]):
                            continue
                        if not _exact_match(name, row["name"]):
                            continue
                        yield row

                records, truncated = _collect_records(
                    _iter_records(),
                    limit,
                    lambda row: {
                        "cookie_id": row["id"],
                        "origin_attributes": row["originAttributes"],
                        "host": row["host"],
                        "name": row["name"],
                        "value": row["value"],
                        "path": row["path"],
                        "expiry_iso": _unix_seconds_or_ms_to_iso(row["expiry"]),
                        "last_accessed_iso": _unix_micros_to_iso(row["lastAccessed"]),
                        "creation_time_iso": _unix_micros_to_iso(row["creationTime"]),
                        "update_time_iso": _unix_micros_to_iso(row["updateTime"]),
                        "is_secure": bool(row["isSecure"]),
                        "is_httponly": bool(row["isHttpOnly"]),
                        "same_site": row["sameSite"],
                        "scheme_map": row["schemeMap"],
                        "is_partitioned": bool(row["isPartitionedAttributeSet"]),
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox cookies: {exc}",
            error_type="firefox_cookies_failed",
        )

    result = _base_result(profile_dir, "cookies", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_sessions(
    profile_path: str,
    file_name: Optional[str] = None,
    url: Optional[str] = None,
    title: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox session restore files from a profile."""
    if lz4 is None:
        return _lz4_dependency_error()
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
    cache_key = _build_cache_key("firefox:sessions", profile_dir, file_name, url, title, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["sessions"]) as staged_profile:
            def _iter_records() -> Iterator[dict]:
                for record in _iter_session_records(staged_profile):
                    if not _exact_match(file_name, record["source_file"]):
                        continue
                    if not _exact_match(url, record["url"]):
                        continue
                    if not _exact_match(title, record["title"]):
                        continue
                    yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox sessions: {exc}",
            error_type="firefox_sessions_failed",
        )

    result = _base_result(profile_dir, "sessions", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_favicons(
    profile_path: str,
    page_url: Optional[str] = None,
    icon_url: Optional[str] = None,
    limit: int = 100,
    include_image: bool = False,
    max_image_bytes: int = _FAVICON_PREVIEW_BYTES,
) -> dict:
    """Parse Firefox favicons from a profile."""
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
    cache_key = _build_cache_key("firefox:favicons", profile_dir, page_url, icon_url, limit, include_image, max_image_bytes)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["favicons"]) as staged_profile:
            staged_favicons = _artifact_presence(staged_profile, "favicons")
            with _sqlite_connection(staged_favicons) as connection:
                def _iter_records() -> Iterator[sqlite3.Row]:
                    for row in connection.execute(
                        """
                        SELECT
                            p.page_url,
                            i.icon_url,
                            i.width,
                            i.color,
                            i.expire_ms,
                            i.flags,
                            i.root,
                            i.data
                        FROM moz_pages_w_icons p
                        JOIN moz_icons_to_pages ip ON ip.page_id = p.id
                        JOIN moz_icons i ON i.id = ip.icon_id
                        """
                    ):
                        if not _exact_match(page_url, row["page_url"]):
                            continue
                        if not _exact_match(icon_url, row["icon_url"]):
                            continue
                        yield row

                records, truncated = _collect_records(
                    _iter_records(),
                    limit,
                    lambda row: {
                        "page_url": row["page_url"],
                        "icon_url": row["icon_url"],
                        "width": row["width"],
                        "color": row["color"],
                        "expire_ms_iso": _unix_ms_to_iso(row["expire_ms"]),
                        "flags": row["flags"],
                        "root": row["root"],
                        "image": None
                        if not include_image or not row["data"]
                        else _serialize_bytes(row["data"], max_image_bytes),
                    },
                )
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox favicons: {exc}",
            error_type="firefox_favicons_failed",
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


async def firefox_parse_extensions(
    profile_path: str,
    extension_id: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox extension metadata from a profile."""
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
    cache_key = _build_cache_key("firefox:extensions", profile_dir, extension_id, name, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["extensions"]) as staged_profile:
            extensions_path = _artifact_presence(staged_profile, "extensions")
            data = json.loads(extensions_path.read_text(encoding="utf-8"))

            def _iter_records() -> Iterator[dict]:
                for addon in data.get("addons") or []:
                    addon_name = (addon.get("defaultLocale") or {}).get("name")
                    if not _exact_match(extension_id, addon.get("id")):
                        continue
                    if not _exact_match(name, addon_name):
                        continue
                    yield {
                        "id": addon.get("id"),
                        "version": addon.get("version"),
                        "type": addon.get("type"),
                        "name": addon_name,
                        "description": (addon.get("defaultLocale") or {}).get("description"),
                        "active": addon.get("active"),
                        "visible": addon.get("visible"),
                        "user_disabled": addon.get("userDisabled"),
                        "app_disabled": addon.get("appDisabled"),
                        "embedder_disabled": addon.get("embedderDisabled"),
                        "hidden": addon.get("hidden"),
                        "install_date_iso": _unix_ms_to_iso(addon.get("installDate")),
                        "update_date_iso": _unix_ms_to_iso(addon.get("updateDate")),
                        "path": addon.get("path"),
                        "source_uri": addon.get("sourceURI"),
                        "signed_state": addon.get("signedState"),
                        "permissions": _jsonify((addon.get("userPermissions") or {}).get("permissions") or []),
                        "origins": _jsonify((addon.get("userPermissions") or {}).get("origins") or []),
                    }

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox extensions: {exc}",
            error_type="firefox_extensions_failed",
        )

    result = _base_result(profile_dir, "extensions", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_preferences(
    profile_path: str,
    key_path: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox preferences from prefs.js."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "preferences")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "preferences", artifact_path)

    key_path = _normalize_filter(key_path)
    cache_key = _build_cache_key("firefox:preferences", profile_dir, key_path, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["preferences"]) as staged_profile:
            prefs_path = _artifact_presence(staged_profile, "preferences")
            prefs = _parse_prefs_file(prefs_path)
            if key_path is not None:
                prefs = [pref for pref in prefs if pref["key_path"] == key_path]
            records, truncated = _collect_records(prefs, limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox preferences: {exc}",
            error_type="firefox_preferences_failed",
        )

    result = _base_result(profile_dir, "preferences", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_logins(
    profile_path: str,
    hostname: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox saved-login metadata from logins.json."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "logins")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "logins", artifact_path)

    hostname = _normalize_filter(hostname)
    cache_key = _build_cache_key("firefox:logins", profile_dir, hostname, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["logins"]) as staged_profile:
            logins_path = _artifact_presence(staged_profile, "logins")
            data = json.loads(logins_path.read_text(encoding="utf-8"))

            def _iter_records() -> Iterator[dict]:
                for login in data.get("logins") or []:
                    if not _exact_match(hostname, login.get("hostname")):
                        continue
                    yield {
                        "id": login.get("id"),
                        "guid": login.get("guid"),
                        "hostname": login.get("hostname"),
                        "http_realm": login.get("httpRealm"),
                        "form_submit_url": login.get("formSubmitURL"),
                        "username_field": login.get("usernameField"),
                        "password_field": login.get("passwordField"),
                        "enc_type": login.get("encType"),
                        "time_created_iso": _unix_ms_to_iso(login.get("timeCreated")),
                        "time_last_used_iso": _unix_ms_to_iso(login.get("timeLastUsed")),
                        "time_password_changed_iso": _unix_ms_to_iso(login.get("timePasswordChanged")),
                        "times_used": login.get("timesUsed"),
                        "sync_counter": login.get("syncCounter"),
                        "ever_synced": login.get("everSynced"),
                        "encrypted_username_present": bool(login.get("encryptedUsername")),
                        "encrypted_password_present": bool(login.get("encryptedPassword")),
                        "encrypted_unknown_fields_present": bool(login.get("encryptedUnknownFields")),
                    }

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox logins: {exc}",
            error_type="firefox_logins_failed",
        )

    result = _base_result(profile_dir, "logins", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "key4_db_present": (profile_dir / "key4.db").exists(),
        }
    )
    await cache.set(cache_key, result)
    return result


async def firefox_parse_session_storage(
    profile_path: str,
    host: Optional[str] = None,
    key: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox session storage records from sessionstore JSON if present."""
    if lz4 is None:
        return _lz4_dependency_error()
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "sessions")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "session_storage", artifact_path)

    host = _normalize_filter(host)
    key = _normalize_filter(key)
    cache_key = _build_cache_key("firefox:session_storage", profile_dir, host, key, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["sessions"]) as staged_profile:
            def _iter_records() -> Iterator[dict]:
                for record in _iter_session_storage_records(staged_profile):
                    if not _exact_match(host, record["host"]):
                        continue
                    if not _exact_match(key, record["key"]):
                        continue
                    yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox session storage: {exc}",
            error_type="firefox_session_storage_failed",
        )

    result = _base_result(profile_dir, "session_storage", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_web_data(
    profile_path: str,
    category: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox web-data-like artifacts such as form history, permissions, content prefs, and search engines."""
    if lz4 is None:
        return _lz4_dependency_error()
    if error := _validate_positive_int("limit", limit):
        return error
    supported_categories = {"form_history", "permissions", "content_prefs", "search_engines"}
    category = _normalize_filter(category)
    if category is not None and category not in supported_categories:
        return _input_error(
            f"Unsupported web data category: {category}",
            supported_categories=sorted(supported_categories),
        )

    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "web_data")
    if not any(path.exists() for path in _artifact_presence_paths(profile_dir, "web_data")):
        return _empty_artifact_result(profile_dir, "web_data", artifact_path)

    cache_key = _build_cache_key("firefox:web_data", profile_dir, category, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["web_data"]) as staged_profile:
            def _iter_records() -> Iterator[dict]:
                if category in {None, "form_history"}:
                    formhistory_db = staged_profile / "formhistory.sqlite"
                    if formhistory_db.exists():
                        with _sqlite_connection(formhistory_db) as connection:
                            if _sqlite_table_exists(connection, "moz_formhistory"):
                                for row in connection.execute("SELECT * FROM moz_formhistory ORDER BY lastUsed DESC"):
                                    yield {
                                        "category": "form_history",
                                        "fieldname": row["fieldname"],
                                        "value": row["value"],
                                        "times_used": row["timesUsed"],
                                        "first_used_iso": _unix_ms_to_iso(row["firstUsed"]),
                                        "last_used_iso": _unix_ms_to_iso(row["lastUsed"]),
                                        "guid": row["guid"],
                                    }

                if category in {None, "permissions"}:
                    permissions_db = staged_profile / "permissions.sqlite"
                    if permissions_db.exists():
                        with _sqlite_connection(permissions_db) as connection:
                            if _sqlite_table_exists(connection, "moz_perms"):
                                for row in connection.execute("SELECT * FROM moz_perms ORDER BY modificationTime DESC"):
                                    yield {
                                        "category": "permissions",
                                        "origin": row["origin"],
                                        "type": row["type"],
                                        "permission": row["permission"],
                                        "expire_type": row["expireType"],
                                        "expire_time_iso": _unix_seconds_or_ms_to_iso(row["expireTime"]),
                                        "modification_time_iso": _unix_seconds_or_ms_to_iso(row["modificationTime"]),
                                    }

                if category in {None, "content_prefs"}:
                    content_prefs_db = staged_profile / "content-prefs.sqlite"
                    if content_prefs_db.exists():
                        with _sqlite_connection(content_prefs_db) as connection:
                            if all(_sqlite_table_exists(connection, table) for table in ("prefs", "settings", "groups")):
                                for row in connection.execute(
                                    """
                                    SELECT g.name AS group_name, s.name AS setting_name, p.value, p.timestamp
                                    FROM prefs p
                                    LEFT JOIN groups g ON g.id = p.groupID
                                    LEFT JOIN settings s ON s.id = p.settingID
                                    ORDER BY p.timestamp DESC
                                    """
                                ):
                                    yield {
                                        "category": "content_prefs",
                                        "group": row["group_name"],
                                        "setting": row["setting_name"],
                                        "value": row["value"],
                                        "timestamp_iso": _unix_ms_to_iso(row["timestamp"]),
                                    }

                if category in {None, "search_engines"}:
                    search_file = staged_profile / "search.json.mozlz4"
                    if search_file.exists():
                        for record in _search_engines_from_mozlz4(search_file):
                            yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox web data: {exc}",
            error_type="firefox_web_data_failed",
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


async def firefox_decrypt_cookies(
    profile_path: str,
    host: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Return Firefox cookies as already-decrypted plaintext values."""
    parsed = await firefox_parse_cookies(profile_path, host=host, name=name, limit=limit)
    if parsed.get("status") != "success":
        return parsed

    records = []
    for record in parsed.get("records", []):
        record_copy = copy.deepcopy(record)
        record_copy["decrypted_value"] = record_copy.get("value")
        record_copy["decrypt_status"] = "plaintext"
        records.append(record_copy)

    result = _base_result(Path(profile_path), "decrypt_cookies", Path(parsed["artifact_path"]))
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": parsed.get("truncated", False),
            "decrypted_count": len(records),
        }
    )
    return result


async def firefox_parse_local_storage(
    profile_path: str,
    origin_key: Optional[str] = None,
    key: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox local storage records from webappsstore and storage/default/ls."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "local_storage")
    if not any(path.exists() for path in _artifact_presence_paths(profile_dir, "local_storage")):
        return _empty_artifact_result(profile_dir, "local_storage", artifact_path)

    origin_key = _normalize_filter(origin_key)
    key = _normalize_filter(key)
    cache_key = _build_cache_key("firefox:local_storage", profile_dir, origin_key, key, limit)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["local_storage"]) as staged_profile:
            def _iter_records() -> Iterator[dict]:
                for record in _iter_local_storage_records(staged_profile):
                    record_origin = record.get("origin") or record.get("origin_key") or record.get("host_id")
                    if not _exact_match(origin_key, record_origin):
                        continue
                    if not _exact_match(key, record["key"]):
                        continue
                    yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox local storage: {exc}",
            error_type="firefox_local_storage_failed",
        )

    result = _base_result(profile_dir, "local_storage", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_indexeddb(
    profile_path: str,
    host_id: Optional[str] = None,
    database_name: Optional[str] = None,
    object_store_name: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """Parse Firefox IndexedDB records from storage/default/*/idb."""
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
        "firefox:indexeddb", profile_dir, host_id, database_name, object_store_name, limit
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["indexeddb"]) as staged_profile:
            def _iter_records() -> Iterator[dict]:
                for record in _iter_indexeddb_records(staged_profile):
                    if not _exact_match(host_id, record["host_id"]):
                        continue
                    if not _exact_match(database_name, record["database_name"]):
                        continue
                    if not _exact_match(object_store_name, record["object_store_name"]):
                        continue
                    yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox IndexedDB: {exc}",
            error_type="firefox_indexeddb_failed",
        )

    result = _base_result(profile_dir, "indexeddb", artifact_path)
    result.update({"record_count": len(records), "records": records, "truncated": truncated})
    await cache.set(cache_key, result)
    return result


async def firefox_parse_cache(
    profile_path: str,
    url: Optional[str] = None,
    limit: int = 100,
    include_body: bool = False,
    max_body_bytes: int = _CACHE_BODY_PREVIEW_BYTES,
) -> dict:
    """Parse Firefox storage/default cache records."""
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
    cache_key = _build_cache_key("firefox:cache", profile_dir, url, limit, include_body, max_body_bytes)
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    try:
        with _staged_profile(profile_dir, ["cache"]) as staged_profile:
            def _iter_records() -> Iterator[dict]:
                for record in _iter_cache_records(staged_profile, include_body=include_body, max_body_bytes=max_body_bytes):
                    if not _exact_match(url, record["request_url"]):
                        continue
                    yield record

            records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    except Exception as exc:
        return _input_error(
            f"Failed to parse Firefox cache: {exc}",
            error_type="firefox_cache_failed",
        )

    result = _base_result(profile_dir, "cache", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "body_included": include_body,
        }
    )
    await cache.set(cache_key, result)
    return result


async def firefox_decrypt_logins(
    profile_path: str,
    primary_password: Optional[str] = None,
    hostname: Optional[str] = None,
    limit: int = 100,
    nss_lib_path: Optional[str] = None,
) -> dict:
    """Attempt to decrypt Firefox saved logins via firefox_decrypt."""
    if error := _validate_positive_int("limit", limit):
        return error
    profile_dir, error = _validate_profile_path(profile_path)
    if error:
        return error
    artifact_path = _artifact_presence(profile_dir, "logins")
    if not artifact_path.exists():
        return _empty_artifact_result(profile_dir, "decrypt_logins", artifact_path)

    hostname = _normalize_filter(hostname)
    cache_key = _build_cache_key(
        "firefox:decrypt_logins", profile_dir, hostname, limit, bool(primary_password), nss_lib_path
    )
    if cached_result := await _get_cached_result(cache_key):
        return cached_result

    command = _firefox_decrypt_command()
    if command is None:
        return _firefox_decrypt_dependency_error()

    try:
        with _staged_profile(profile_dir, ["logins"]) as staged_profile:
            env = None
            if nss_lib_path is not None:
                env = dict(os.environ)
                env["NSS_LIB_PATH"] = nss_lib_path
            proc = subprocess.run(
                [*command, "--format", "json", "--no-interactive", "--non-fatal-decryption", str(staged_profile)],
                input=("" if primary_password is None else primary_password) + "\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=120,
            )
    except subprocess.TimeoutExpired:
        return _input_error(
            "firefox_decrypt timed out while decrypting logins",
            error_type="firefox_decrypt_timeout",
        )
    except Exception as exc:
        return _input_error(
            f"Failed to run firefox_decrypt: {exc}",
            error_type="firefox_decrypt_failed",
        )

    stderr = proc.stderr.strip()
    if proc.returncode != 0:
        error_type = "firefox_decrypt_failed"
        lowered = stderr.lower()
        if "master password" in lowered or "primary password" in lowered:
            error_type = "primary_password_required"
        elif "nss" in lowered:
            error_type = "nss_not_available"
        return _input_error(
            stderr or "firefox_decrypt exited with a non-zero status",
            error_type=error_type,
        )

    try:
        decrypted_rows = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        return _input_error(
            f"firefox_decrypt did not return valid JSON: {exc}",
            error_type="firefox_decrypt_invalid_output",
        )

    def _iter_records() -> Iterator[dict]:
        for row in decrypted_rows:
            if not isinstance(row, dict):
                continue
            if not _exact_match(hostname, row.get("url")):
                continue
            yield {
                "hostname": row.get("url"),
                "username": row.get("user"),
                "password": row.get("password"),
                "decrypt_status": "decrypted",
            }

    records, truncated = _collect_records(_iter_records(), limit, lambda record: record)
    result = _base_result(profile_dir, "decrypt_logins", artifact_path)
    result.update(
        {
            "record_count": len(records),
            "records": records,
            "truncated": truncated,
            "decrypted_count": len(records),
            "nss_lib_path": nss_lib_path,
        }
    )
    await cache.set(cache_key, result)
    return result
