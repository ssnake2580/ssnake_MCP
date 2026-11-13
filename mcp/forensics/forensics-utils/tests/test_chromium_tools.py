"""Tests for Chromium deep-artifact tools."""

import base64
from dataclasses import dataclass
from datetime import datetime
import json
import sqlite3
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
import pytest_asyncio

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.tools import chromium_tools


@pytest_asyncio.fixture(autouse=True)
async def clear_cache_between_tests():
    """Reset the shared cache between tests."""
    await cache.clear()
    yield
    await cache.clear()


@pytest.fixture
def chromium_profile_dir(tmp_path):
    """Create a profile directory with Chromium deep artifact folders."""
    profile_dir = tmp_path / "Default"
    (profile_dir / "Local Storage" / "leveldb").mkdir(parents=True)
    (profile_dir / "Session Storage").mkdir(parents=True)
    (profile_dir / "IndexedDB").mkdir(parents=True)
    (profile_dir / "Cache" / "Cache_Data").mkdir(parents=True)
    return profile_dir


def create_cookie_db(db_path, rows):
    """Create a minimal Chromium cookie SQLite database for tests."""
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE cookies (
                creation_utc INTEGER,
                host_key TEXT,
                top_frame_site_key TEXT,
                name TEXT,
                value TEXT,
                encrypted_value BLOB,
                path TEXT,
                expires_utc INTEGER,
                is_secure INTEGER,
                is_httponly INTEGER,
                last_access_utc INTEGER,
                has_expires INTEGER,
                is_persistent INTEGER,
                priority INTEGER,
                samesite INTEGER,
                source_scheme INTEGER,
                source_port INTEGER,
                last_update_utc INTEGER,
                source_type INTEGER
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO cookies (
                creation_utc,
                host_key,
                top_frame_site_key,
                name,
                value,
                encrypted_value,
                path,
                expires_utc,
                is_secure,
                is_httponly,
                last_access_utc,
                has_expires,
                is_persistent,
                priority,
                samesite,
                source_scheme,
                source_port,
                last_update_utc,
                source_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        connection.commit()
    finally:
        connection.close()


def create_login_db(db_path, rows):
    """Create a minimal Chromium Login Data SQLite database for tests."""
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE logins (
                origin_url TEXT,
                action_url TEXT,
                username_element TEXT,
                username_value TEXT,
                password_element TEXT,
                password_value BLOB,
                submit_element TEXT,
                signon_realm TEXT,
                date_created INTEGER,
                blacklisted_by_user INTEGER,
                scheme INTEGER,
                times_used INTEGER,
                date_last_used INTEGER,
                date_password_modified INTEGER,
                display_name TEXT,
                icon_url TEXT,
                federation_url TEXT,
                skip_zero_click INTEGER,
                generation_upload_status INTEGER
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO logins (
                origin_url,
                action_url,
                username_element,
                username_value,
                password_element,
                password_value,
                submit_element,
                signon_realm,
                date_created,
                blacklisted_by_user,
                scheme,
                times_used,
                date_last_used,
                date_password_modified,
                display_name,
                icon_url,
                federation_url,
                skip_zero_click,
                generation_upload_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        connection.commit()
    finally:
        connection.close()


def create_favicons_db(db_path, rows):
    """Create a minimal Chromium Favicons database for tests."""
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("CREATE TABLE favicons (id INTEGER PRIMARY KEY, url TEXT, icon_type INTEGER)")
        connection.execute(
            "CREATE TABLE icon_mapping (page_url TEXT, icon_id INTEGER)"
        )
        connection.execute(
            """
            CREATE TABLE favicon_bitmaps (
                id INTEGER PRIMARY KEY,
                icon_id INTEGER,
                last_updated INTEGER,
                last_requested INTEGER,
                image_data BLOB,
                width INTEGER,
                height INTEGER
            )
            """
        )
        for row in rows:
            connection.execute(
                "INSERT INTO favicons (id, url, icon_type) VALUES (?, ?, ?)",
                row["favicon"],
            )
            connection.execute(
                "INSERT INTO icon_mapping (page_url, icon_id) VALUES (?, ?)",
                row["mapping"],
            )
            connection.execute(
                """
                INSERT INTO favicon_bitmaps (
                    id,
                    icon_id,
                    last_updated,
                    last_requested,
                    image_data,
                    width,
                    height
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                row["bitmap"],
            )
        connection.commit()
    finally:
        connection.close()


def create_web_data_db(db_path):
    """Create a minimal Chromium Web Data database for tests."""
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE autofill (
                name TEXT,
                value TEXT,
                count INTEGER,
                date_created INTEGER,
                date_last_used INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE keywords (
                short_name TEXT,
                keyword TEXT,
                url TEXT,
                favicon_url TEXT,
                safe_for_autoreplace INTEGER,
                originating_url TEXT,
                date_created INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE autofill_profiles (
                guid TEXT,
                company_name TEXT,
                language_code TEXT,
                use_count INTEGER,
                use_date INTEGER,
                date_modified INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO autofill VALUES (?, ?, ?, ?, ?)",
            ("email", "user@example.com", 4, 13312345678900000, 13312345678910000),
        )
        connection.execute(
            "INSERT INTO keywords VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "Example Search",
                "ex",
                "https://search.example/?q={searchTerms}",
                "https://search.example/favicon.ico",
                1,
                "https://search.example",
                13312345678920000,
            ),
        )
        connection.execute(
            "INSERT INTO autofill_profiles VALUES (?, ?, ?, ?, ?, ?)",
            ("guid-1", "Example Corp", "en", 2, 13312345678930000, 13312345678940000),
        )
        connection.commit()
    finally:
        connection.close()


class FakeSummaryCacheStore:
    """Fake cache store for profile summary tests."""

    def cache_keys(self):
        return [SimpleNamespace(url="https://cache.example/item")]


class FakeSummaryProfile:
    """Fake Chromium profile with all deep artifacts present."""

    def __init__(self, path):
        self.path = path
        self.cache = FakeSummaryCacheStore()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def iter_local_storage_hosts(self):
        return iter(["https://app.example"])

    def iter_session_storage_hosts(self):
        return iter(["app.example"])

    def iter_indexeddb_hosts(self):
        return iter(["https_app.example_0"])


@dataclass
class FakeLocalStorageRecord:
    storage_key: str
    script_key: str
    value: str
    is_live: bool
    leveldb_seq_number: int
    record_location: str


@dataclass
class FakeLocalStorageBatch:
    timestamp: datetime
    start: int
    end: int


class FakeLocalStorageProfile:
    """Fake Chromium profile for Local Storage tests."""

    init_count = 0

    def __init__(self, path):
        self.path = path
        FakeLocalStorageProfile.init_count += 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def iter_local_storage_with_batches(
        self,
        storage_key=None,
        script_key=None,
        include_deletions=False,
        raise_on_no_result=False,
    ):
        del storage_key, script_key, include_deletions, raise_on_no_result
        batch = FakeLocalStorageBatch(datetime(2024, 1, 1, 12, 0, 0), 10, 11)
        return iter(
            [
                (
                    FakeLocalStorageRecord(
                        storage_key="https://app.example",
                        script_key="token",
                        value="abc123",
                        is_live=True,
                        leveldb_seq_number=10,
                        record_location="Leveldb Seq: 10",
                    ),
                    batch,
                ),
                (
                    FakeLocalStorageRecord(
                        storage_key="https://app.example",
                        script_key="theme",
                        value="dark",
                        is_live=True,
                        leveldb_seq_number=11,
                        record_location="Leveldb Seq: 11",
                    ),
                    batch,
                ),
            ]
        )


class FakeKeyType:
    """Fake IndexedDB key type."""

    name = "String"


@dataclass
class FakeIndexedDbKey:
    value: object
    raw_key: bytes
    key_type: object


@dataclass
class FakeIndexedDbRecord:
    database_name: str
    database_origin: str
    object_store_name: str
    key: FakeIndexedDbKey
    value: object
    is_live: bool
    ldb_seq_no: int
    origin_file: str
    record_location: str
    external_value_path: str | None = None


class FakeIndexedDbProfile:
    """Fake Chromium profile for IndexedDB tests."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def iter_indexeddb_records(
        self,
        host_id=None,
        database_name=None,
        object_store_name=None,
        raise_on_no_result=False,
        include_deletions=False,
        bad_deserializer_data_handler=None,
    ):
        del host_id, database_name, object_store_name, raise_on_no_result, include_deletions
        if bad_deserializer_data_handler is not None:
            bad_deserializer_data_handler(SimpleNamespace(value="bad-key"), b"broken")

        record = FakeIndexedDbRecord(
            database_name="AppDB",
            database_origin="https://app.example",
            object_store_name="items",
            key=FakeIndexedDbKey(
                value={"id": 7},
                raw_key=b"\x01\x02",
                key_type=FakeKeyType(),
            ),
            value={
                "binary": b"\x01\x02\x03",
                "seen_at": datetime(2024, 1, 2, 3, 4, 5),
                "nested": ["ok", 42],
            },
            is_live=True,
            ldb_seq_no=55,
            origin_file="IndexedDB/test.ldb",
            record_location="File: IndexedDB/test.ldb Seq: 55",
            external_value_path="1/00/1",
        )
        return iter([record])


class FakeCacheMetadata:
    """Fake Chromium cache metadata."""

    def __init__(self):
        self.request_time = datetime(2024, 3, 1, 10, 0, 0)
        self.response_time = datetime(2024, 3, 1, 10, 0, 1)
        self.other_cache_attributes = {"security_bits": 256}

    @property
    def http_header_declarations(self):
        return iter(["HTTP/1.1 200 OK"])

    @property
    def http_header_attributes(self):
        return iter(
            [
                ("content-type", "text/plain"),
                ("cache-control", "max-age=3600"),
            ]
        )


@dataclass
class FakeCacheResult:
    key: object
    metadata: object
    data: bytes
    metadata_location: object
    data_location: object
    was_decompressed: bool
    duplicate_key_index: int


class FakeLocation:
    """Stringable cache location."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class FakeCacheProfile:
    """Fake Chromium profile for cache parsing tests."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def iterate_cache(self, url=None, decompress=True, omit_cached_data=False):
        del url, decompress, omit_cached_data
        result = FakeCacheResult(
            key=SimpleNamespace(raw_key="https://cache.example/item", url="https://cache.example/item"),
            metadata=FakeCacheMetadata(),
            data=b"abcdefgh",
            metadata_location=FakeLocation("index @ 12"),
            data_location=FakeLocation("data_0 @ 44"),
            was_decompressed=False,
            duplicate_key_index=0,
        )
        return iter([result])


class FakeTransitionValue(int):
    """Minimal transition flag object used by fake history records."""

    name = "forward_back"

    def __and__(self, other):
        return int(self) & int(other)


@dataclass
class FakeHistoryTransition:
    core: object
    qualifier: object


@dataclass
class FakeHistoryRecord:
    rec_id: int
    url: str
    title: str
    visit_time: datetime
    visit_duration: object
    transition: object
    from_visit_id: int
    opener_visit_id: int
    parent_visit_id: int
    has_parent: bool
    record_location: str


@dataclass
class FakeDownloadRecord:
    record_source: object
    record_id: int
    guid: str
    hash: str
    url: str
    url_chain: tuple[str, ...]
    tab_url: str
    tab_referrer_url: str
    target_path: str
    mime_type: str
    original_mime_type: str
    total_bytes: str
    start_time: datetime
    end_time: datetime
    record_location: str


class FakeHistoryProfile:
    """Fake Chromium profile for history and download tests."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def iterate_history_records(self, url=None):
        records = [
            FakeHistoryRecord(
                rec_id=1,
                url="https://app.example/home",
                title="Home",
                visit_time=datetime(2024, 4, 1, 10, 0, 0),
                visit_duration=SimpleNamespace(total_seconds=lambda: 1.5),
                transition=FakeHistoryTransition(
                    core=SimpleNamespace(name="typed"),
                    qualifier=FakeTransitionValue(1),
                ),
                from_visit_id=0,
                opener_visit_id=0,
                parent_visit_id=0,
                has_parent=False,
                record_location="SQLite Rowid: 1",
            ),
            FakeHistoryRecord(
                rec_id=2,
                url="https://app.example/about",
                title="About",
                visit_time=datetime(2024, 4, 1, 11, 0, 0),
                visit_duration=SimpleNamespace(total_seconds=lambda: 0.5),
                transition=FakeHistoryTransition(
                    core=SimpleNamespace(name="link"),
                    qualifier=FakeTransitionValue(0),
                ),
                from_visit_id=1,
                opener_visit_id=0,
                parent_visit_id=1,
                has_parent=True,
                record_location="SQLite Rowid: 2",
            ),
        ]
        if url is None:
            return iter(records)
        return iter(record for record in records if record.url == url)

    def iter_downloads(self, download_url=None, tab_url=None):
        record = FakeDownloadRecord(
            record_source=SimpleNamespace(name="history_db"),
            record_id=77,
            guid="download-guid",
            hash="deadbeef",
            url="https://download.example/file.zip",
            url_chain=("https://download.example/file.zip",),
            tab_url="https://app.example/downloads",
            tab_referrer_url="https://app.example/home",
            target_path="C:/Downloads/file.zip",
            mime_type="application/zip",
            original_mime_type="application/zip",
            total_bytes="4096",
            start_time=datetime(2024, 4, 1, 12, 0, 0),
            end_time=datetime(2024, 4, 1, 12, 0, 5),
            record_location="SQLite Rowid: 77",
        )
        if download_url is not None and record.url != download_url:
            return iter([])
        if tab_url is not None and record.tab_url != tab_url:
            return iter([])
        return iter([record])


@dataclass
class FakeSnssNavigationEntry:
    offset: int
    id_type: object
    session_id: int
    index: int
    url: str
    title: str
    referrer_url: str | None
    original_request_url: str | None
    timestamp: datetime | None
    transition_type: object | None
    has_post_data: bool | None
    http_status: int | None


class FakeSnssFile:
    """Fake SNSS file reader used by session parsing tests."""

    def __init__(self, file_type, stream):
        self.file_type = file_type
        self.file_name = stream.name.split("/")[-1]

    def iter_session_commands(self):
        return iter(
            [
                FakeSnssNavigationEntry(
                    offset=8,
                    id_type=SimpleNamespace(name="CommandUpdateTabNavigation"),
                    session_id=12,
                    index=0,
                    url="https://session.example/home",
                    title="Home Session",
                    referrer_url=None,
                    original_request_url=None,
                    timestamp=datetime(2024, 5, 1, 9, 0, 0),
                    transition_type=SimpleNamespace(
                        core_transition="Typed",
                        qualifiers=("ForwardBack",),
                    ),
                    has_post_data=False,
                    http_status=200,
                )
            ]
        )


class FakeSnssModule:
    """Fake ccl_chromium_snss2 module."""

    NavigationEntry = FakeSnssNavigationEntry
    SnssFile = FakeSnssFile
    SnssFileType = SimpleNamespace(
        Session=SimpleNamespace(name="Session"),
        Tab=SimpleNamespace(name="Tab"),
    )


@pytest.mark.asyncio
async def test_chromium_profile_summary(monkeypatch, chromium_profile_dir):
    """Profile summary should report available deep Chromium artifacts."""
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", FakeSummaryProfile)

    result = await chromium_tools.chromium_profile_summary(str(chromium_profile_dir))

    assert result["status"] == "success"
    assert result["artifact_type"] == "profile_summary"
    assert result["artifacts"]["local_storage"]["present"] is True
    assert result["artifacts"]["indexeddb"]["host_id_count"] == 1
    assert result["artifacts"]["cache"]["cache_entry_count"] == 1


@pytest.mark.asyncio
async def test_chromium_profile_summary_missing_dependency(tmp_path, monkeypatch):
    """The tools should fail cleanly when the Chromium parser dependency is unavailable."""
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", None)

    result = await chromium_tools.chromium_profile_summary(str(tmp_path))

    assert result["status"] == "error"
    assert result["error_type"] == "dependency_not_found"


@pytest.mark.asyncio
async def test_chromium_parse_local_storage_uses_cache(monkeypatch, chromium_profile_dir):
    """Local Storage parsing should truncate at the requested limit and use cache on repeat calls."""
    FakeLocalStorageProfile.init_count = 0
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", FakeLocalStorageProfile)

    first = await chromium_tools.chromium_parse_local_storage(str(chromium_profile_dir), limit=1)
    second = await chromium_tools.chromium_parse_local_storage(str(chromium_profile_dir), limit=1)

    assert first["status"] == "success"
    assert first["record_count"] == 1
    assert first["truncated"] is True
    assert first["records"][0]["batch"]["start_sequence"] == 10
    assert second["cached"] is True
    assert FakeLocalStorageProfile.init_count == 1


@pytest.mark.asyncio
async def test_chromium_parse_indexeddb_normalizes_values(monkeypatch, chromium_profile_dir):
    """IndexedDB parsing should normalize complex values into JSON-safe structures."""
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", FakeIndexedDbProfile)

    result = await chromium_tools.chromium_parse_indexeddb(str(chromium_profile_dir))

    assert result["status"] == "success"
    assert result["decode_error_count"] == 1
    assert result["records"][0]["value"]["binary"]["encoding"] == "base64"
    assert result["records"][0]["value"]["seen_at"] == "2024-01-02T03:04:05"
    assert result["records"][0]["raw_key_hex"] == "0102"


@pytest.mark.asyncio
async def test_chromium_parse_cache_includes_body_preview(monkeypatch, chromium_profile_dir):
    """Cache parsing should expose headers and truncate body previews when requested."""
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", FakeCacheProfile)

    result = await chromium_tools.chromium_parse_cache(
        str(chromium_profile_dir),
        include_body=True,
        max_body_bytes=4,
    )

    assert result["status"] == "success"
    assert result["body_included"] is True
    assert result["records"][0]["response_headers"]["content-type"] == ["text/plain"]
    assert result["records"][0]["body"]["truncated"] is True


@pytest.mark.asyncio
async def test_chromium_parse_history_filters_and_shapes_records(monkeypatch, chromium_profile_dir):
    """History parsing should support exact filters and normalized output."""
    (chromium_profile_dir / "History").write_text("placeholder", encoding="utf-8")
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", FakeHistoryProfile)

    result = await chromium_tools.chromium_parse_history(
        str(chromium_profile_dir),
        url="https://app.example/about",
        limit=5,
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["title"] == "About"
    assert result["records"][0]["transition_core"] == "link"
    assert result["records"][0]["visit_duration_ms"] == 500


@pytest.mark.asyncio
async def test_chromium_parse_downloads_returns_normalized_records(monkeypatch, chromium_profile_dir):
    """Download parsing should normalize records from Chromium history/shared_proto_db."""
    (chromium_profile_dir / "History").write_text("placeholder", encoding="utf-8")
    monkeypatch.setattr(chromium_tools, "ChromiumProfileFolder", FakeHistoryProfile)

    result = await chromium_tools.chromium_parse_downloads(str(chromium_profile_dir), limit=10)

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["record_source"] == "history_db"
    assert result["records"][0]["total_bytes"] == 4096
    assert result["records"][0]["target_path"].endswith("file.zip")


@pytest.mark.asyncio
async def test_chromium_parse_bookmarks_reads_json_profile(chromium_profile_dir):
    """Bookmark parsing should walk Chromium bookmark JSON and flatten URL entries."""
    bookmark_data = {
        "roots": {
            "bookmark_bar": {
                "children": [
                    {
                        "type": "folder",
                        "name": "Research",
                        "children": [
                            {
                                "type": "url",
                                "id": "10",
                                "guid": "guid-10",
                                "name": "Docs",
                                "url": "https://docs.example",
                                "date_added": "13312345678900000",
                                "date_last_used": "13312345678900001",
                            }
                        ],
                    }
                ]
            }
        }
    }
    (chromium_profile_dir / "Bookmarks").write_text(
        json.dumps(bookmark_data),
        encoding="utf-8",
    )

    result = await chromium_tools.chromium_parse_bookmarks(
        str(chromium_profile_dir),
        title="Docs",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["url"] == "https://docs.example"
    assert result["records"][0]["folder_path"] == ["Research"]
    assert result["records"][0]["source_root"] == "bookmark_bar"


@pytest.mark.asyncio
async def test_chromium_parse_cookies_reads_network_db_and_uses_cache(chromium_profile_dir):
    """Cookie parsing should support Network/Cookies and reuse cache on repeat calls."""
    network_dir = chromium_profile_dir / "Network"
    network_dir.mkdir(parents=True)
    cookie_db = network_dir / "Cookies"
    create_cookie_db(
        cookie_db,
        [
            (
                13312345678900000,
                ".example.com",
                "https://example.com",
                "sessionid",
                "plain-value",
                b"v10encrypted",
                "/",
                13322345678900000,
                1,
                1,
                13312345678910000,
                1,
                1,
                1,
                0,
                2,
                443,
                13312345678920000,
                1,
            ),
            (
                13312345678930000,
                ".other.test",
                None,
                "prefs",
                "json",
                b"",
                "/prefs",
                13332345678900000,
                0,
                0,
                13312345678940000,
                1,
                1,
                0,
                0,
                1,
                80,
                13312345678950000,
                0,
            ),
        ],
    )

    first = await chromium_tools.chromium_parse_cookies(
        str(chromium_profile_dir),
        host_key=".example.com",
        limit=1,
    )
    second = await chromium_tools.chromium_parse_cookies(
        str(chromium_profile_dir),
        host_key=".example.com",
        limit=1,
    )

    assert first["status"] == "success"
    assert first["artifact_path"].replace("\\", "/").endswith("Network/Cookies")
    assert first["record_count"] == 1
    assert first["records"][0]["name"] == "sessionid"
    assert first["records"][0]["encrypted_value_present"] is True
    assert first["records"][0]["encrypted_value_size_bytes"] == len(b"v10encrypted")
    assert first["records"][0]["is_secure"] is True
    assert second["cached"] is True


@pytest.mark.asyncio
async def test_chromium_parse_logins_reads_login_data(chromium_profile_dir):
    """Login parsing should read Chromium Login Data metadata without decrypting passwords."""
    login_db = chromium_profile_dir / "Login Data"
    master_key = b"0123456789abcdef0123456789abcdef"
    nonce = b"123456789012"
    encrypted_password = b"v10" + nonce + AESGCM(master_key).encrypt(
        nonce, b"super-secret", None
    )
    create_login_db(
        login_db,
        [
            (
                "https://app.example/login",
                "https://app.example/login",
                "username",
                "analyst",
                "password",
                encrypted_password,
                "submit",
                "https://app.example/",
                13312345678900000,
                0,
                0,
                3,
                13312345678910000,
                13312345678920000,
                "App Example",
                "https://app.example/icon.ico",
                None,
                0,
                1,
            )
        ],
    )

    result = await chromium_tools.chromium_parse_logins(
        str(chromium_profile_dir),
        origin_url="https://app.example/login",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["username_value"] == "analyst"
    assert result["records"][0]["password_encryption"] == "v10"
    assert result["records"][0]["password_blob_present"] is True


@pytest.mark.asyncio
async def test_chromium_decrypt_logins_with_provided_master_key(chromium_profile_dir):
    """Login decryption should support an explicitly supplied Chromium master key."""
    login_db = chromium_profile_dir / "Login Data"
    master_key = b"0123456789abcdef0123456789abcdef"
    nonce = b"abcdefghijkl"
    encrypted_password = b"v10" + nonce + AESGCM(master_key).encrypt(
        nonce, b"pa55w0rd!", None
    )
    create_login_db(
        login_db,
        [
            (
                "https://vault.example/login",
                "https://vault.example/login",
                "username",
                "operator",
                "password",
                encrypted_password,
                "submit",
                "https://vault.example/",
                13312345678900000,
                0,
                0,
                1,
                13312345678910000,
                13312345678920000,
                "Vault",
                None,
                None,
                0,
                0,
            )
        ],
    )

    result = await chromium_tools.chromium_decrypt_logins(
        str(chromium_profile_dir),
        master_key_b64=base64.b64encode(master_key).decode("ascii"),
    )

    assert result["status"] == "success"
    assert result["decrypted_count"] == 1
    assert result["master_key_source"] == "provided_master_key"
    assert result["records"][0]["decrypt_status"] == "decrypted"
    assert result["records"][0]["decrypted_password"] == "pa55w0rd!"


@pytest.mark.asyncio
async def test_chromium_decrypt_logins_uses_local_state_on_windows(monkeypatch, chromium_profile_dir):
    """Login decryption should derive a master key from Local State in Windows mode."""
    login_db = chromium_profile_dir / "Login Data"
    master_key = b"abcdefghijklmnopqrstuvwxyz123456"
    nonce = b"nonce-for123"
    encrypted_password = b"v11" + nonce + AESGCM(master_key).encrypt(
        nonce, b"windows-secret", None
    )
    create_login_db(
        login_db,
        [
            (
                "https://secure.example/login",
                "https://secure.example/login",
                "email",
                "user@example.com",
                "password",
                encrypted_password,
                "submit",
                "https://secure.example/",
                13312345678900000,
                0,
                0,
                7,
                13312345678910000,
                13312345678920000,
                "Secure Example",
                None,
                None,
                0,
                0,
            )
        ],
    )
    local_state_path = chromium_profile_dir.parent / "Local State"
    wrapped_key = b"wrapped-master-key"
    local_state_path.write_text(
        json.dumps(
            {
                "os_crypt": {
                    "encrypted_key": base64.b64encode(b"DPAPI" + wrapped_key).decode("ascii")
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(chromium_tools, "_platform_is_windows", lambda: True)
    monkeypatch.setattr(
        chromium_tools,
        "_windows_dpapi_decrypt",
        lambda data: master_key if data == wrapped_key else b"",
    )

    result = await chromium_tools.chromium_decrypt_logins(str(chromium_profile_dir))

    assert result["status"] == "success"
    assert result["master_key_source"] == "local_state_dpapi"
    assert result["local_state_path"].endswith("Local State")
    assert result["records"][0]["decrypt_status"] == "decrypted"
    assert result["records"][0]["decrypted_password"] == "windows-secret"


@pytest.mark.asyncio
async def test_chromium_decrypt_cookies_with_provided_master_key(chromium_profile_dir):
    """Cookie decryption should support a provided Chromium master key."""
    network_dir = chromium_profile_dir / "Network"
    network_dir.mkdir(parents=True)
    cookie_db = network_dir / "Cookies"
    master_key = b"fedcba9876543210fedcba9876543210"
    nonce = b"cookie-nonce"
    encrypted_value = b"v10" + nonce + AESGCM(master_key).encrypt(
        nonce, b"session-secret", None
    )
    create_cookie_db(
        cookie_db,
        [
            (
                13312345678900000,
                ".secure.example",
                None,
                "session",
                "",
                encrypted_value,
                "/",
                13322345678900000,
                1,
                1,
                13312345678910000,
                1,
                1,
                1,
                0,
                2,
                443,
                13312345678920000,
                1,
            )
        ],
    )

    result = await chromium_tools.chromium_decrypt_cookies(
        str(chromium_profile_dir),
        master_key_b64=base64.b64encode(master_key).decode("ascii"),
    )

    assert result["status"] == "success"
    assert result["decrypted_count"] == 1
    assert result["records"][0]["decrypt_status"] == "decrypted"
    assert result["records"][0]["decrypted_value"] == "session-secret"


@pytest.mark.asyncio
async def test_chromium_parse_sessions_uses_snss_reader(monkeypatch, chromium_profile_dir):
    """Session parsing should use the SNSS reader and normalize navigation entries."""
    sessions_dir = chromium_profile_dir / "Sessions"
    sessions_dir.mkdir(parents=True)
    (sessions_dir / "Session_123").write_bytes(b"placeholder")
    monkeypatch.setattr(chromium_tools, "ccl_chromium_snss2", FakeSnssModule)

    result = await chromium_tools.chromium_parse_sessions(
        str(chromium_profile_dir),
        url="https://session.example/home",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["source_file"] == "Session_123"
    assert result["records"][0]["transition_core"] == "Typed"
    assert result["records"][0]["transition_qualifiers"] == ["ForwardBack"]


@pytest.mark.asyncio
async def test_chromium_parse_favicons_reads_database(chromium_profile_dir):
    """Favicon parsing should join page URLs with favicon bitmap metadata."""
    favicons_db = chromium_profile_dir / "Favicons"
    create_favicons_db(
        favicons_db,
        [
            {
                "favicon": (1, "https://cdn.example/icon.png", 1),
                "mapping": ("https://app.example", 1),
                "bitmap": (
                    10,
                    1,
                    13312345678900000,
                    13312345678910000,
                    b"\x89PNGdata",
                    32,
                    32,
                ),
            }
        ],
    )

    result = await chromium_tools.chromium_parse_favicons(
        str(chromium_profile_dir),
        page_url="https://app.example",
        include_image=True,
        max_image_bytes=4,
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["icon_url"] == "https://cdn.example/icon.png"
    assert result["records"][0]["image"]["truncated"] is True


@pytest.mark.asyncio
async def test_chromium_parse_web_data_reads_supported_categories(chromium_profile_dir):
    """Web Data parsing should expose supported categories with normalized fields."""
    web_data_db = chromium_profile_dir / "Web Data"
    create_web_data_db(web_data_db)

    result = await chromium_tools.chromium_parse_web_data(
        str(chromium_profile_dir),
        category="autofill",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["category"] == "autofill"
    assert result["records"][0]["name"] == "email"


@pytest.mark.asyncio
async def test_chromium_parse_extensions_reads_manifest_and_preferences(chromium_profile_dir):
    """Extension parsing should merge manifest metadata with preference state."""
    extension_dir = chromium_profile_dir / "Extensions" / "abcdextid" / "1.0.0"
    locale_dir = extension_dir / "_locales" / "en"
    locale_dir.mkdir(parents=True)
    (extension_dir / "manifest.json").write_text(
        json.dumps(
            {
                "name": "__MSG_appName__",
                "description": "__MSG_appDesc__",
                "manifest_version": 3,
                "version": "1.0.0",
                "default_locale": "en",
                "permissions": ["storage"],
                "host_permissions": ["https://*.example.com/*"],
            }
        ),
        encoding="utf-8",
    )
    (locale_dir / "messages.json").write_text(
        json.dumps(
            {
                "appName": {"message": "Example Extension"},
                "appDesc": {"message": "Collects example data"},
            }
        ),
        encoding="utf-8",
    )
    (chromium_profile_dir / "Preferences").write_text(
        json.dumps(
            {
                "extensions": {
                    "settings": {
                        "abcdextid": {
                            "state": 1,
                            "location": 5,
                            "from_webstore": True,
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = await chromium_tools.chromium_parse_extensions(
        str(chromium_profile_dir),
        extension_id="abcdextid",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["name"] == "Example Extension"
    assert result["records"][0]["state"] == 1
    assert result["records"][0]["host_permissions"] == ["https://*.example.com/*"]


@pytest.mark.asyncio
async def test_chromium_parse_preferences_reads_dot_paths(chromium_profile_dir):
    """Preference parsing should read dotted key paths from Preferences files."""
    (chromium_profile_dir / "Preferences").write_text(
        json.dumps(
            {
                "download": {"default_directory": "C:/Downloads"},
                "homepage": "https://start.example",
            }
        ),
        encoding="utf-8",
    )
    (chromium_profile_dir / "Secure Preferences").write_text(
        json.dumps({"signin": {"allowed": False}}),
        encoding="utf-8",
    )

    result = await chromium_tools.chromium_parse_preferences(
        str(chromium_profile_dir),
        key_path="download.default_directory",
    )

    assert result["status"] == "success"
    assert result["record_count"] == 1
    assert result["records"][0]["value"] == "C:/Downloads"
