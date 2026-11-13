"""Tests for Firefox artifact tools."""

import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import lz4.block
import pytest
import pytest_asyncio

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.tools import firefox_tools


@pytest_asyncio.fixture(autouse=True)
async def clear_cache_between_tests():
    await cache.clear()
    yield
    await cache.clear()


@pytest.fixture
def firefox_profile_dir(tmp_path):
    profile_dir = tmp_path / "profile.default-release"
    profile_dir.mkdir(parents=True)
    return profile_dir


def create_places_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                hidden INTEGER,
                typed INTEGER,
                last_visit_date INTEGER,
                guid TEXT,
                description TEXT,
                preview_image_url TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                from_visit INTEGER,
                place_id INTEGER,
                visit_date INTEGER,
                visit_type INTEGER,
                session INTEGER,
                source INTEGER,
                triggeringPlaceId INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE moz_bookmarks (
                id INTEGER PRIMARY KEY,
                type INTEGER,
                fk INTEGER,
                parent INTEGER,
                position INTEGER,
                title TEXT,
                dateAdded INTEGER,
                lastModified INTEGER,
                guid TEXT
            )
            """
        )

        connection.executemany(
            "INSERT INTO moz_places VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    "https://example.test/home",
                    "Home",
                    2,
                    0,
                    1,
                    1776610000000000,
                    "place-guid-1",
                    "Landing page",
                    "https://example.test/preview.png",
                ),
                (
                    2,
                    "file:///C:/Users/Administrator/Downloads/report.pdf",
                    "report.pdf",
                    1,
                    0,
                    0,
                    1776610001000000,
                    "place-guid-2",
                    None,
                    None,
                ),
            ],
        )
        connection.executemany(
            "INSERT INTO moz_historyvisits VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (10, 0, 1, 1776610000000000, 2, 1, 0, None),
                (11, 10, 2, 1776610001000000, 7, 1, 0, None),
            ],
        )
        connection.executemany(
            "INSERT INTO moz_bookmarks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 2, None, 0, 0, "", 1776610000000000, 1776610000000000, "root"),
                (2, 2, None, 1, 0, "toolbar", 1776610000000000, 1776610000000000, "toolbar-guid"),
                (3, 2, None, 2, 0, "Research", 1776610000000000, 1776610000000000, "folder-guid"),
                (4, 1, 1, 3, 0, "Docs", 1776610000000000, 1776610002000000, "bookmark-guid"),
            ],
        )
        connection.commit()
    finally:
        connection.close()


def create_cookies_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE moz_cookies (
                id INTEGER PRIMARY KEY,
                originAttributes TEXT,
                name TEXT,
                value TEXT,
                host TEXT,
                path TEXT,
                expiry INTEGER,
                lastAccessed INTEGER,
                creationTime INTEGER,
                isSecure INTEGER,
                isHttpOnly INTEGER,
                inBrowserElement INTEGER,
                sameSite INTEGER,
                schemeMap INTEGER,
                isPartitionedAttributeSet INTEGER,
                updateTime INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO moz_cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                "",
                "sessionid",
                "value-123",
                ".example.test",
                "/",
                1777610000,
                1776610001000000,
                1776610000000000,
                1,
                1,
                0,
                0,
                2,
                0,
                1776610002000000,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def create_favicons_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "CREATE TABLE moz_icons (id INTEGER PRIMARY KEY, icon_url TEXT, width INTEGER, root INTEGER, color TEXT, expire_ms INTEGER, flags INTEGER, data BLOB)"
        )
        connection.execute(
            "CREATE TABLE moz_pages_w_icons (id INTEGER PRIMARY KEY, page_url TEXT, page_url_hash INTEGER)"
        )
        connection.execute(
            "CREATE TABLE moz_icons_to_pages (page_id INTEGER, icon_id INTEGER, expire_ms INTEGER)"
        )
        connection.execute(
            "INSERT INTO moz_icons VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "https://example.test/favicon.ico", 32, 0, "#ffffff", 1777610000000, 0, b"\x89PNGdata"),
        )
        connection.execute(
            "INSERT INTO moz_pages_w_icons VALUES (?, ?, ?)",
            (1, "https://example.test/home", 1),
        )
        connection.execute(
            "INSERT INTO moz_icons_to_pages VALUES (?, ?, ?)",
            (1, 1, 1777610000000),
        )
        connection.commit()
    finally:
        connection.close()


def write_sessionstore(profile_dir: Path) -> None:
    session_data = {
        "version": ["sessionrestore", 1],
        "selectedWindow": 1,
        "windows": [
            {
                "selected": 1,
                "tabs": [
                    {
                        "index": 2,
                        "storage": {
                            "https://session.example.test": {
                                "token": "abc123",
                                "theme": "dark",
                            }
                        },
                        "entries": [
                            {"url": "https://example.test/first", "title": "First"},
                            {"url": "https://example.test/second", "title": "Second"},
                        ],
                    }
                ],
            }
        ],
    }
    raw = json.dumps(session_data).encode("utf-8")
    compressed = b"mozLz40\0" + lz4.block.compress(raw)
    (profile_dir / "sessionstore.jsonlz4").write_bytes(compressed)
    backups_dir = profile_dir / "sessionstore-backups"
    backups_dir.mkdir()
    (backups_dir / "previous.jsonlz4").write_bytes(compressed)


def write_extensions_json(profile_dir: Path) -> None:
    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "addon@example.test",
                        "version": "1.2.3",
                        "type": "extension",
                        "defaultLocale": {
                            "name": "Example Add-on",
                            "description": "Example extension",
                        },
                        "active": True,
                        "visible": True,
                        "userDisabled": False,
                        "appDisabled": False,
                        "embedderDisabled": False,
                        "hidden": False,
                        "installDate": 1776610000000,
                        "updateDate": 1776610001000,
                        "path": "C:/Extensions/example",
                        "sourceURI": "file:///tmp/example.xpi",
                        "signedState": 2,
                        "userPermissions": {"permissions": ["cookies"], "origins": ["https://*.example.test/*"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def write_prefs_js(profile_dir: Path) -> None:
    (profile_dir / "prefs.js").write_text(
        '\n'.join(
            [
                'user_pref("browser.startup.homepage", "https://start.example.test");',
                'user_pref("browser.search.region", "VN");',
                'user_pref("browser.toolbars.bookmarks.visibility", "always");',
                'user_pref("browser.startup.page", 3);',
            ]
        ),
        encoding="utf-8",
    )


def write_logins_json(profile_dir: Path) -> None:
    (profile_dir / "logins.json").write_text(
        json.dumps(
            {
                "nextId": 2,
                "logins": [
                    {
                        "id": 1,
                        "hostname": "https://auth.example.test",
                        "httpRealm": None,
                        "formSubmitURL": "https://auth.example.test/login",
                        "usernameField": "username",
                        "passwordField": "password",
                        "encryptedUsername": "enc-user",
                        "encryptedPassword": "enc-pass",
                        "guid": "{login-guid}",
                        "encType": 1,
                        "timeCreated": 1776610000000,
                        "timeLastUsed": 1776610001000,
                        "timePasswordChanged": 1776610002000,
                        "timesUsed": 3,
                        "syncCounter": 1,
                        "everSynced": False,
                        "encryptedUnknownFields": "enc-extra",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (profile_dir / "key4.db").write_bytes(b"sqlite-placeholder")


def create_webappsstore_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE webappsstore2 (
                originAttributes TEXT,
                originKey TEXT,
                scope TEXT,
                key TEXT,
                value BLOB
            )
            """
        )
        connection.execute(
            "INSERT INTO webappsstore2 VALUES (?, ?, ?, ?, ?)",
            ("", "https://legacy.example.test", "legacy", "theme", b"dark"),
        )
        connection.commit()
    finally:
        connection.close()


def create_firefox_ls_db(db_path: Path, origin: str) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE data (
                key TEXT,
                utf16_length INTEGER,
                conversion_type INTEGER,
                compression_type INTEGER,
                last_access_time INTEGER,
                value BLOB
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE database (
                origin TEXT,
                usage INTEGER,
                last_vacuum_time INTEGER,
                last_analyze_time INTEGER,
                last_vacuum_size INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO database VALUES (?, ?, ?, ?, ?)",
            (origin, 42, 1776610000000000, 0, 4096),
        )
        connection.execute(
            "INSERT INTO data VALUES (?, ?, ?, ?, ?, ?)",
            ("pref-key", 8, 1, 0, 1776610000000000, b'{"enabled":true}'),
        )
        connection.commit()
    finally:
        connection.close()


def create_firefox_indexeddb_db(db_path: Path, origin: str, database_name: str) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE database (
                name TEXT,
                origin TEXT,
                version INTEGER,
                last_vacuum_time INTEGER,
                last_analyze_time INTEGER,
                last_vacuum_size INTEGER
            )
            """
        )
        connection.execute(
            "CREATE TABLE object_store (id INTEGER PRIMARY KEY, auto_increment INTEGER, name TEXT, key_path TEXT)"
        )
        connection.execute(
            "CREATE TABLE object_data (object_store_id INTEGER, key BLOB, index_data_values BLOB, file_ids BLOB, data BLOB)"
        )
        connection.execute(
            "INSERT INTO database VALUES (?, ?, ?, ?, ?, ?)",
            (database_name, origin, 1, 1776610000000000, 0, 4096),
        )
        connection.execute(
            "INSERT INTO object_store VALUES (?, ?, ?, ?)",
            (1, 0, "items", "id"),
        )
        connection.execute(
            "INSERT INTO object_data VALUES (?, ?, ?, ?, ?)",
            (1, b'item-1', None, None, b'{"hello":"world"}'),
        )
        connection.commit()
    finally:
        connection.close()


def create_firefox_cache_db(db_path: Path, body_id: str) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE entries (
                id INTEGER PRIMARY KEY,
                request_method TEXT,
                request_url_no_query TEXT,
                request_url_no_query_hash BLOB,
                request_url_query TEXT,
                request_url_query_hash BLOB,
                request_referrer TEXT,
                request_headers_guard INTEGER,
                request_mode INTEGER,
                request_credentials INTEGER,
                request_contentpolicytype INTEGER,
                request_cache INTEGER,
                request_body_id TEXT,
                response_type INTEGER,
                response_status INTEGER,
                response_status_text TEXT,
                response_headers_guard INTEGER,
                response_body_id TEXT,
                response_security_info_id INTEGER,
                response_principal_info TEXT,
                cache_id INTEGER,
                request_redirect INTEGER,
                request_referrer_policy INTEGER,
                request_integrity TEXT,
                request_url_fragment TEXT,
                response_padding_size INTEGER,
                request_body_disk_size INTEGER,
                response_body_disk_size INTEGER
            )
            """
        )
        connection.execute(
            "CREATE TABLE response_headers (name TEXT, value TEXT, entry_id INTEGER)"
        )
        connection.execute(
            "CREATE TABLE response_url_list (url TEXT, entry_id INTEGER)"
        )
        connection.execute(
            "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                "GET",
                "https://cache.example.test/sw.js",
                None,
                "",
                None,
                "about:client",
                1,
                2,
                1,
                20,
                0,
                None,
                2,
                200,
                "OK",
                3,
                body_id,
                None,
                "https://cache.example.test/sw.js",
                1,
                3,
                0,
                "",
                "",
                None,
                0,
                12,
            ),
        )
        connection.execute(
            "INSERT INTO response_headers VALUES (?, ?, ?)",
            ("content-type", "application/javascript", 1),
        )
        connection.execute(
            "INSERT INTO response_url_list VALUES (?, ?)",
            ("https://cache.example.test/sw.js", 1),
        )
        connection.commit()
    finally:
        connection.close()


def create_formhistory_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE moz_formhistory (
                id INTEGER PRIMARY KEY,
                fieldname TEXT,
                value TEXT,
                timesUsed INTEGER,
                firstUsed INTEGER,
                lastUsed INTEGER,
                guid TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO moz_formhistory VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1, "username", "analyst", 3, 1776610000000, 1776610001000, "form-guid"),
        )
        connection.commit()
    finally:
        connection.close()


def create_permissions_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE moz_perms (
                id INTEGER PRIMARY KEY,
                origin TEXT,
                type TEXT,
                permission INTEGER,
                expireType INTEGER,
                expireTime INTEGER,
                modificationTime INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO moz_perms VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1, "https://perm.example.test", "storageAccessAPI", 1, 2, 1777610000000, 1776610000000),
        )
        connection.commit()
    finally:
        connection.close()


def create_content_prefs_db(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute(
            "CREATE TABLE prefs (id INTEGER PRIMARY KEY, groupID INTEGER, settingID INTEGER, value TEXT, timestamp INTEGER)"
        )
        connection.execute("INSERT INTO groups VALUES (?, ?)", (1, "https://pref.example.test"))
        connection.execute("INSERT INTO settings VALUES (?, ?)", (1, "font.size.variable.x-western"))
        connection.execute(
            "INSERT INTO prefs VALUES (?, ?, ?, ?, ?)",
            (1, 1, 1, "16", 1776610000000),
        )
        connection.commit()
    finally:
        connection.close()


def write_search_mozlz4(profile_dir: Path) -> None:
    data = {
        "version": 1,
        "engines": [
            {"id": "duckduckgo", "_name": "DuckDuckGo", "_isConfigEngine": True, "_metaData": {}},
            {"id": "google", "_name": "Google", "_isConfigEngine": True, "_metaData": {"orderHint": 1}},
        ],
        "metaData": {},
    }
    compressed = b"mozLz40\0" + lz4.block.compress(json.dumps(data).encode("utf-8"))
    (profile_dir / "search.json.mozlz4").write_bytes(compressed)


@pytest.mark.asyncio
async def test_firefox_profile_summary_reports_available_artifacts(firefox_profile_dir):
    create_places_db(firefox_profile_dir / "places.sqlite")
    create_cookies_db(firefox_profile_dir / "cookies.sqlite")
    create_favicons_db(firefox_profile_dir / "favicons.sqlite")
    write_sessionstore(firefox_profile_dir)
    write_extensions_json(firefox_profile_dir)
    write_prefs_js(firefox_profile_dir)
    write_logins_json(firefox_profile_dir)

    result = await firefox_tools.firefox_profile_summary(str(firefox_profile_dir))

    assert result["status"] == "success"
    assert set(result["available_artifacts"]) >= {
        "history",
        "bookmarks",
        "downloads",
        "cookies",
        "sessions",
        "favicons",
        "extensions",
        "preferences",
        "logins",
    }
    assert result["artifacts"]["logins"]["key4_db_present"] is True


@pytest.mark.asyncio
async def test_firefox_parse_history_filters_records(firefox_profile_dir):
    create_places_db(firefox_profile_dir / "places.sqlite")

    result = await firefox_tools.firefox_parse_history(
        str(firefox_profile_dir),
        url="https://example.test/home",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["visit_type_name"] == "typed"
    assert result["records"][0]["from_url"] is None


@pytest.mark.asyncio
async def test_firefox_parse_bookmarks_includes_folder_path(firefox_profile_dir):
    create_places_db(firefox_profile_dir / "places.sqlite")

    result = await firefox_tools.firefox_parse_bookmarks(
        str(firefox_profile_dir),
        title="Docs",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["source_root"] == "toolbar"
    assert result["records"][0]["folder_path"] == ["Research"]


@pytest.mark.asyncio
async def test_firefox_parse_downloads_returns_file_url_candidates(firefox_profile_dir):
    create_places_db(firefox_profile_dir / "places.sqlite")

    result = await firefox_tools.firefox_parse_downloads(str(firefox_profile_dir))

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["download_url"].startswith("file:///")
    assert result["records"][0]["source_url"] == "https://example.test/home"
    assert result["records"][0]["visit_type_name"] == "download"


@pytest.mark.asyncio
async def test_firefox_parse_cookies_reads_cookie_rows(firefox_profile_dir):
    create_cookies_db(firefox_profile_dir / "cookies.sqlite")

    result = await firefox_tools.firefox_parse_cookies(
        str(firefox_profile_dir),
        host=".example.test",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["name"] == "sessionid"
    assert result["records"][0]["is_secure"] is True


@pytest.mark.asyncio
async def test_firefox_parse_sessions_reads_mozlz4_files(firefox_profile_dir):
    write_sessionstore(firefox_profile_dir)

    result = await firefox_tools.firefox_parse_sessions(
        str(firefox_profile_dir),
        title="Second",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 2
    assert {record["source_file"] for record in result["records"]} == {
        "sessionstore.jsonlz4",
        "previous.jsonlz4",
    }
    assert all(record["is_current_entry"] is True for record in result["records"])


@pytest.mark.asyncio
async def test_firefox_parse_session_storage_reads_storage_from_sessionstore(firefox_profile_dir):
    write_sessionstore(firefox_profile_dir)

    result = await firefox_tools.firefox_parse_session_storage(
        str(firefox_profile_dir),
        host="https://session.example.test",
        key="token",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 2
    assert all(record["value"] == "abc123" for record in result["records"])


@pytest.mark.asyncio
async def test_firefox_parse_favicons_includes_image_preview(firefox_profile_dir):
    create_favicons_db(firefox_profile_dir / "favicons.sqlite")

    result = await firefox_tools.firefox_parse_favicons(
        str(firefox_profile_dir),
        include_image=True,
        max_image_bytes=4,
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["image"]["truncated"] is True


@pytest.mark.asyncio
async def test_firefox_parse_extensions_preferences_and_logins(firefox_profile_dir):
    write_extensions_json(firefox_profile_dir)
    write_prefs_js(firefox_profile_dir)
    write_logins_json(firefox_profile_dir)

    extensions = await firefox_tools.firefox_parse_extensions(
        str(firefox_profile_dir),
        extension_id="addon@example.test",
    )
    preferences = await firefox_tools.firefox_parse_preferences(
        str(firefox_profile_dir),
        key_path="browser.startup.homepage",
    )
    logins = await firefox_tools.firefox_parse_logins(
        str(firefox_profile_dir),
        hostname="https://auth.example.test",
    )

    assert extensions["status"] == "success"
    assert extensions["record_count"] == 1
    assert extensions["records"][0]["name"] == "Example Add-on"
    assert preferences["status"] == "success"
    assert preferences["records"][0]["value"] == "https://start.example.test"
    assert logins["status"] == "success"
    assert logins["record_count"] == 1
    assert logins["key4_db_present"] is True
    assert logins["records"][0]["encrypted_password_present"] is True


@pytest.mark.asyncio
async def test_firefox_parse_local_storage_reads_legacy_and_modern_storage(firefox_profile_dir):
    create_webappsstore_db(firefox_profile_dir / "webappsstore.sqlite")
    ls_dir = firefox_profile_dir / "storage" / "default" / "https+++modern.example.test" / "ls"
    ls_dir.mkdir(parents=True)
    create_firefox_ls_db(ls_dir / "data.sqlite", "https://modern.example.test")

    result = await firefox_tools.firefox_parse_local_storage(str(firefox_profile_dir), limit=10)

    assert result["status"] == "success"
    assert result["record_count"] == 2
    sources = {record["source"] for record in result["records"]}
    assert sources == {"webappsstore2", "storage_ls"}


@pytest.mark.asyncio
async def test_firefox_parse_web_data_reads_multiple_categories(firefox_profile_dir):
    create_formhistory_db(firefox_profile_dir / "formhistory.sqlite")
    create_permissions_db(firefox_profile_dir / "permissions.sqlite")
    create_content_prefs_db(firefox_profile_dir / "content-prefs.sqlite")
    write_search_mozlz4(firefox_profile_dir)

    result = await firefox_tools.firefox_parse_web_data(
        str(firefox_profile_dir),
        limit=10,
    )

    assert result["status"] == "success"
    categories = {record["category"] for record in result["records"]}
    assert categories == {"form_history", "permissions", "content_prefs", "search_engines"}


@pytest.mark.asyncio
async def test_firefox_parse_indexeddb_reads_object_data(firefox_profile_dir):
    idb_dir = firefox_profile_dir / "storage" / "default" / "https+++video.example.test" / "idb"
    idb_dir.mkdir(parents=True)
    create_firefox_indexeddb_db(
        idb_dir / "123456example.sqlite",
        "https://video.example.test",
        "VideoDB",
    )

    result = await firefox_tools.firefox_parse_indexeddb(
        str(firefox_profile_dir),
        database_name="VideoDB",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["object_store_name"] == "items"
    assert result["records"][0]["data"] == '{"hello":"world"}'


@pytest.mark.asyncio
async def test_firefox_parse_cache_reads_headers_and_body_preview(firefox_profile_dir):
    cache_root = firefox_profile_dir / "storage" / "default" / "https+++cache.example.test" / "cache"
    morgue_dir = cache_root / "morgue" / "12"
    morgue_dir.mkdir(parents=True)
    create_firefox_cache_db(cache_root / "caches.sqlite", "{abcd1234-0000-0000-0000-000000000000}")
    (morgue_dir / "{abcd1234-0000-0000-0000-000000000000}.final").write_bytes(b"hello firefox")

    result = await firefox_tools.firefox_parse_cache(
        str(firefox_profile_dir),
        include_body=True,
        max_body_bytes=5,
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["response_headers"]["content-type"] == "application/javascript"
    assert result["records"][0]["body"]["truncated"] is True


@pytest.mark.asyncio
async def test_firefox_decrypt_cookies_returns_plaintext_parity(firefox_profile_dir):
    create_cookies_db(firefox_profile_dir / "cookies.sqlite")

    result = await firefox_tools.firefox_decrypt_cookies(str(firefox_profile_dir), limit=5)

    assert result["status"] == "success"
    assert result["decrypted_count"] == 1
    assert result["records"][0]["decrypt_status"] == "plaintext"
    assert result["records"][0]["decrypted_value"] == "value-123"


@pytest.mark.asyncio
async def test_firefox_decrypt_logins_uses_firefox_decrypt_cli(monkeypatch, firefox_profile_dir):
    write_logins_json(firefox_profile_dir)

    monkeypatch.setattr(firefox_tools, "_firefox_decrypt_command", lambda: ["firefox-decrypt"])

    def fake_run(command, input, text, capture_output, env, timeout):
        assert command[0] == "firefox-decrypt"
        assert "--format" in command
        assert input == "\n"
        assert text is True
        del capture_output, env, timeout
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "url": "https://auth.example.test",
                        "user": "analyst",
                        "password": "decrypted-secret",
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr(firefox_tools.subprocess, "run", fake_run)

    result = await firefox_tools.firefox_decrypt_logins(
        str(firefox_profile_dir),
        primary_password="",
        hostname="https://auth.example.test",
    )

    assert result["status"] == "success"
    assert result["decrypted_count"] == 1
    assert result["records"][0]["password"] == "decrypted-secret"
