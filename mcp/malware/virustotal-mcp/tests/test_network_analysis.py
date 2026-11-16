# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Network analysis contracts use synthetic targets and an inert HTTP transport."""

import json
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx
import pytest
from analysis_helpers import ANALYSIS_ID, SHA, TOKEN, analysis_response
from mcp import Client

from vt_mcp.analyses import (
    AnalysisError,
    format_analysis_response,
    format_network_submission_response,
    unknown_network_submission,
)
from vt_mcp.client import AnalysisClient
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

REQUEST_ID = "12345678-1234-4234-8234-123456789abc"
OTHER_ID = "87654321-1234-4234-8234-123456789abc"
TARGETS = {
    "url": "https://example.com/?private=synthetic",
    "domain": "example.com",
    "ip": "192.0.2.1",
}


def receipt(kind="url", *, status="submitted"):
    raw = unknown_network_submission(REQUEST_ID, kind)
    raw["status"] = status
    if status == "submitted":
        raw.update(analysis_id=ANALYSIS_ID, next_poll_after_seconds=5)
    elif status == "rejected":
        raw["error"] = {
            "code": "rate_limited",
            "message": "Provider text is not public output",
            "retryable": False,
            "retry_after_seconds": 17,
        }
    return raw


def network_analysis(kind="url", *, completed=True):
    raw = analysis_response(completed=completed)
    raw.pop("sha256")
    report_id = "a" * 64 if kind == "url" else TARGETS[kind]
    slug = "ip-address" if kind == "ip" else kind
    raw.update(
        request_id=REQUEST_ID,
        indicator_type=kind,
        report_id=report_id,
        report_url=f"https://www.virustotal.com/gui/{slug}/{quote(report_id, safe='')}",
    )
    return raw


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kind,tool", [("url", "submit_url"), ("domain", "reanalyze_domain"), ("ip", "reanalyze_ip")]
)
async def test_sdk_network_flow_sends_json_once_and_recovers_selected_analysis(
    kind, tool, tmp_path, monkeypatch
):
    state = tmp_path / "must-not-create-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        assert request.headers["x-apikey"] == TOKEN
        assert TARGETS[kind] not in str(request.url)
        if request.method == "POST":
            assert request.url.path == f"/api/v3/network-submissions/{REQUEST_ID}"
            assert request.headers["x-vtai-consent"] == "standard-v1"
            assert request.headers["content-type"] == "application/json"
            assert int(request.headers["content-length"]) == len(request.content)
            assert json.loads(request.content) == {
                "indicator_type": kind,
                "indicator": TARGETS[kind],
            }
            return httpx.Response(200, json=receipt(kind))
        if "/analyses/" in request.url.path:
            assert dict(request.url.params) == {"request_id": REQUEST_ID}
            return httpx.Response(200, json=network_analysis(kind))
        return httpx.Response(200, json=receipt(kind))

    async with Client(
        create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    ) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert len(tools) == 11
        assert set(tools[tool].input_schema["required"]) == {kind, "request_id"}
        assert not tools[tool].annotations.read_only_hint
        assert tools[tool].annotations.idempotent_hint
        submitted = await client.call_tool(tool, {kind: TARGETS[kind], "request_id": REQUEST_ID})
        recovered = await client.call_tool("get_submission", {"request_id": REQUEST_ID})
        recovered_with_null = await client.call_tool(
            "get_submission", {"request_id": REQUEST_ID, "sha256": None}
        )
        result = await client.call_tool(
            "get_analysis", {"analysis_id": ANALYSIS_ID, "request_id": REQUEST_ID}
        )
    assert (
        not submitted.is_error
        and not recovered_with_null.is_error
        and submitted.structured_content
        == recovered.structured_content
        == recovered_with_null.structured_content
        == receipt(kind)
    )
    assert not result.is_error and result.structured_content == network_analysis(kind)
    assert [method for method, _ in calls] == ["POST", "GET", "GET", "GET"]
    assert not state.exists()
    assert TOKEN not in submitted.content[0].text and TARGETS[kind] not in submitted.content[0].text


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["lost", "malformed", "credential", "foreign_receipt"])
async def test_uncertain_post_has_safe_recovery_no_replay_or_new_id(mode, caplog):
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json=receipt())
        if mode == "lost":
            raise httpx.ReadTimeout(TOKEN + TARGETS["url"])
        if mode == "malformed":
            return httpx.Response(200, content=TOKEN.encode())
        raw = receipt()
        raw["analysis_id" if mode == "credential" else "request_id"] = (
            TOKEN if mode == "credential" else OTHER_ID
        )
        return httpx.Response(200, json=raw)

    async with Client(
        create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    ) as client:
        failure = await client.call_tool(
            "submit_url", {"url": TARGETS["url"], "request_id": REQUEST_ID}
        )
        recovered = await client.call_tool("get_submission", {"request_id": REQUEST_ID})
    assert failure.is_error and failure.structured_content["error"]["code"] == "submission_unknown"
    assert failure.structured_content["submission"] == unknown_network_submission(REQUEST_ID, "url")
    assert not recovered.is_error and calls == ["POST", "GET"]
    assert TOKEN not in failure.content[0].text + caplog.text
    assert TARGETS["url"] not in failure.content[0].text + caplog.text


@pytest.mark.anyio
async def test_rejected_post_preserves_retry_delay_and_terminal_receipt():
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json=receipt(status="rejected"))
        return httpx.Response(
            429,
            headers={"Retry-After": "17"},
            json={
                "detail": {
                    "code": "rate_limited",
                    "message": TOKEN,
                    "submission": receipt(status="rejected"),
                },
            },
        )

    async with Client(
        create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    ) as client:
        result = await client.call_tool(
            "submit_url", {"url": TARGETS["url"], "request_id": REQUEST_ID}
        )
        recovered = await client.call_tool("get_submission", {"request_id": REQUEST_ID})
    assert result.is_error and result.structured_content["error"]["retry_after_seconds"] == 17
    assert result.structured_content["error"]["retryable"] is False
    assert result.structured_content["submission"] == recovered.structured_content
    assert recovered.structured_content["error"]["retryable"] is False
    assert recovered.structured_content["can_resubmit"] is False
    assert TOKEN not in result.content[0].text and "Provider text" not in result.content[0].text
    assert calls == ["POST", "GET"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool,args",
    [
        ("submit_url", {"url": TARGETS["url"]}),
        ("submit_url", {"url": TARGETS["url"], "request_id": REQUEST_ID.upper()}),
        (
            "submit_url",
            {"url": TARGETS["url"], "request_id": REQUEST_ID.replace("-4234-", "-5234-")},
        ),
        ("submit_url", {"url": [TOKEN], "request_id": REQUEST_ID}),
        ("reanalyze_domain", {"domain": TOKEN, "request_id": REQUEST_ID, "confirm": True}),
        ("reanalyze_ip", {"ip": "192.0.2.1\n" + TOKEN, "request_id": REQUEST_ID}),
        ("get_submission", {"sha256": SHA, "request_id": REQUEST_ID}),
        ("get_submission", {"request_id": None}),
        ("get_analysis", {"analysis_id": ANALYSIS_ID, "request_id": TOKEN}),
    ],
)
async def test_invalid_network_arguments_do_not_bind_or_echo(tool, args):
    @asynccontextmanager
    async def lifespan(_):
        yield None

    def never(_):
        pytest.fail("Malformed input bound a reader")

    server = create_report_server(
        lifespan=lifespan, bind_reports=never, bind_analyses=never, bind_network_submissions=never
    )
    async with Client(server) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error and result.structured_content["error"]["code"] == "invalid_input"
    assert TOKEN not in result.content[0].text and "input_value" not in result.content[0].text


@pytest.mark.parametrize("kind", ["url", "domain", "ip"])
def test_network_analysis_typed_shape_preserves_file_shape(kind):
    raw = network_analysis(kind)
    assert format_analysis_response(raw, ANALYSIS_ID, request_id=REQUEST_ID) == raw
    file_raw = analysis_response()
    assert format_analysis_response(file_raw, ANALYSIS_ID) == file_raw
    pending = network_analysis(kind, completed=False)
    pending.update(report_id=None, report_url=None)
    assert format_analysis_response(pending, ANALYSIS_ID) == pending


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", OTHER_ID),
        ("indicator_type", "file"),
        ("sha256", SHA),
        ("report_url", "https://example.invalid/private"),
        ("report_id", None),
        ("analysis_id", "foreign"),
        ("stats", {"harmless": True}),
    ],
)
def test_network_analysis_rejects_mismatched_or_malformed_selected_evidence(field, value):
    raw = network_analysis()
    raw[field] = value
    with pytest.raises(AnalysisError) as caught:
        format_analysis_response(raw, ANALYSIS_ID, request_id=REQUEST_ID)
    assert caught.value.error["code"] == "invalid_response"


def test_network_receipt_minimizes_unknown_fields_and_rejects_cross_kind():
    raw = receipt()
    raw["indicator"] = TARGETS["url"]
    assert format_network_submission_response(raw, REQUEST_ID) == receipt()
    with pytest.raises(AnalysisError):
        format_network_submission_response(raw, REQUEST_ID, indicator_type="ip")


@pytest.mark.anyio
@pytest.mark.parametrize("status", ["submission_unknown", "rejected"])
async def test_direct_host_receipt_outcome_is_an_error_only_for_the_write(status):
    bound = []

    class Reader:
        async def submit_network(self, indicator_type, indicator, request_id):
            assert (indicator_type, indicator, request_id) == ("url", TARGETS["url"], REQUEST_ID)
            return receipt(status=status)

        async def get_network_submission(self, request_id):
            assert request_id == REQUEST_ID
            return receipt(status=status)

    @asynccontextmanager
    async def lifespan(_):
        yield None

    def bind(ctx):
        bound.append(ctx)
        return Reader()

    server = create_report_server(
        lifespan=lifespan,
        bind_reports=lambda _: None,
        bind_network_submissions=bind,
    )
    async with Client(server) as client:
        await client.list_tools()
        assert bound == []
        write = await client.call_tool(
            "submit_url", {"url": TARGETS["url"], "request_id": REQUEST_ID}
        )
        read = await client.call_tool("get_submission", {"request_id": REQUEST_ID})
    assert write.is_error and not read.is_error
    assert write.structured_content["submission"] == read.structured_content
    assert len(bound) == 2 and bound[0] is not bound[1]


@pytest.mark.anyio
async def test_error_read_cannot_expose_raw_provider_recovery_metadata():
    async with AnalysisClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                403,
                json={
                    "detail": {"submission": {"private": TOKEN}},
                },
            )
        ),
    ) as client:
        with pytest.raises(AnalysisError) as caught:
            await client.get_network_submission(REQUEST_ID)
    assert caught.value.submission is None
    assert TOKEN not in str(caught.value) and caught.value.error["code"] == "access_denied"


@pytest.mark.anyio
async def test_direct_client_rejects_noncanonical_id_before_http():
    async with AnalysisClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("HTTP"))
    ) as client:
        with pytest.raises(AnalysisError):
            await client.submit_network("url", TARGETS["url"], REQUEST_ID.upper())
        with pytest.raises(AnalysisError):
            await client.get_network_submission("../" + TOKEN)
