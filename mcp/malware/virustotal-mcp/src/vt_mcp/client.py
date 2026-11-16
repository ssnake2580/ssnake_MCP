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

"""Bounded analysis reads and a single explicit raw-byte submission to VTAI."""

import json
from collections.abc import AsyncIterator
from typing import BinaryIO
from urllib.parse import quote

import anyio
import httpx

from vt_mcp.analyses import (
    MAX_SUBMISSION_BYTES,
    AnalysisError,
    NetworkKind,
    analysis_http_error,
    format_analysis_response,
    format_network_submission_response,
    format_submission_response,
    unknown_network_submission,
    unknown_submission,
    validate_analysis_id,
    validate_network_submission,
    validate_request_id,
    validate_sha256,
)
from vt_mcp.reports import MAX_RESPONSE_BYTES, parse_retry_after
from vt_mcp.vtai_client import VTAIClient

SUBMIT_TIMEOUT = 130.0
READ_TIMEOUT = 35.0


def _object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite number")


class AnalysisClient(VTAIClient):
    """Shares the existing credential and HTTP lifecycle; POST never retries."""

    async def _analysis_request(
        self,
        method,
        path,
        *,
        content=None,
        size=None,
        timeout=READ_TIMEOUT,
        content_type="application/octet-stream",
    ):
        headers = {}
        if method == "POST":
            headers = {
                "Content-Type": content_type,
                "X-VTAI-Consent": "standard-v1",
                "Content-Length": str(size),
            }
        try:
            with anyio.fail_after(timeout):
                async with self._http.stream(
                    method, path, content=content, headers=headers, timeout=timeout
                ) as response:
                    if response.headers.get("Content-Encoding", "identity").strip().lower() not in {
                        "",
                        "identity",
                    }:
                        raise AnalysisError("invalid_response")
                    payload = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        payload.extend(chunk)
                        if len(payload) > MAX_RESPONSE_BYTES:
                            raise AnalysisError("response_too_large")
                    try:
                        raw = json.loads(
                            payload, object_pairs_hook=_object, parse_constant=_constant
                        )
                    except (ValueError, UnicodeError, TypeError, RecursionError):
                        raw = None
                    if response.status_code not in ({200, 202} if method == "POST" else {200}):
                        detail = raw.get("detail") if isinstance(raw, dict) else None
                        detail = detail if isinstance(detail, dict) else {}
                        retry = parse_retry_after(response.headers.get("Retry-After"))
                        if retry is None:
                            retry = detail.get("retry_after_seconds")
                        raise analysis_http_error(
                            response.status_code,
                            code=detail.get("code"),
                            retry_after_seconds=retry,
                            submission=detail.get("submission")
                            if method == "POST" and path.startswith("network-submissions/")
                            else None,
                        )
                    if raw is None:
                        raise AnalysisError("invalid_response")
                    if response.status_code == 202 and (
                        not isinstance(raw, dict) or raw.get("status") != "submission_unknown"
                    ):
                        raise AnalysisError("invalid_response")
                    return raw
        except (httpx.TimeoutException, TimeoutError):
            raise AnalysisError("timeout") from None
        except httpx.RequestError:
            raise AnalysisError("unavailable") from None

    async def get_analysis(self, analysis_id: str, *, request_id: str | None = None) -> dict:
        validate_analysis_id(analysis_id)
        path = f"analyses/{quote(analysis_id, safe='')}"
        if request_id is not None:
            path += f"?request_id={validate_request_id(request_id)}"
        raw = await self._analysis_request("GET", path)
        return format_analysis_response(
            raw, analysis_id, request_id=request_id, forbidden_values=(self.settings.token,)
        )

    async def get_submission(self, sha256: str) -> dict:
        validate_sha256(sha256)
        raw = await self._analysis_request("GET", f"submissions/{sha256}")
        result = format_submission_response(raw, sha256, forbidden_values=(self.settings.token,))
        if result["status"] == "exists":
            raise AnalysisError("invalid_response")
        return result

    async def get_network_submission(self, request_id: str) -> dict:
        validate_request_id(request_id)
        raw = await self._analysis_request("GET", f"network-submissions/{request_id}")
        return format_network_submission_response(
            raw, request_id, forbidden_values=(self.settings.token,)
        )

    async def submit_network(
        self, indicator_type: NetworkKind, indicator: str, request_id: str
    ) -> dict:
        """One standard-mode POST; the caller must retain request_id before this call."""
        validate_network_submission(indicator_type, indicator, request_id)
        content = json.dumps(
            {"indicator_type": indicator_type, "indicator": indicator},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        try:
            raw = await self._analysis_request(
                "POST",
                f"network-submissions/{request_id}",
                content=content,
                size=len(content),
                content_type="application/json",
                timeout=SUBMIT_TIMEOUT,
            )
            return format_network_submission_response(
                raw,
                request_id,
                indicator_type=indicator_type,
                forbidden_values=(self.settings.token,),
            )
        except AnalysisError as exc:
            if exc.submission is not None:
                try:
                    recovery = format_network_submission_response(
                        exc.submission,
                        request_id,
                        indicator_type=indicator_type,
                        forbidden_values=(self.settings.token,),
                    )
                    expected_code = (
                        "permission_denied"
                        if exc.error["code"] == "access_denied"
                        else exc.error["code"]
                    )
                    if (
                        recovery["status"] != "rejected"
                        or recovery["error"]["code"] != expected_code
                    ):
                        raise AnalysisError("invalid_response")
                except AnalysisError:
                    raise AnalysisError(
                        "submission_unknown",
                        submission=unknown_network_submission(request_id, indicator_type),
                    ) from None
                raise AnalysisError(
                    exc.error["code"],
                    http_status=exc.error["http_status"],
                    retry_after_seconds=exc.error["retry_after_seconds"],
                    submission=recovery,
                ) from None
            if exc.error["code"] in {
                "timeout",
                "unavailable",
                "invalid_response",
                "response_too_large",
                "submission_unknown",
            }:
                raise AnalysisError(
                    "submission_unknown",
                    submission=unknown_network_submission(request_id, indicator_type),
                ) from None
            raise

    async def submit(self, snapshot: BinaryIO, sha256: str, size: int) -> dict:
        """Only call after explicit consent and confirmed durable local recovery state."""
        validate_sha256(sha256)
        if type(size) is not int or not 0 <= size <= MAX_SUBMISSION_BYTES:
            raise AnalysisError("invalid_input")

        async def chunks() -> AsyncIterator[bytes]:
            snapshot.seek(0)
            sent = 0
            while part := snapshot.read(65536):
                sent += len(part)
                if sent > size:
                    raise AnalysisError("submission_unknown")
                yield part
                await anyio.lowlevel.checkpoint()
            if sent != size:
                raise AnalysisError("submission_unknown")

        try:
            raw = await self._analysis_request(
                "POST", f"submissions/{sha256}", content=chunks(), size=size, timeout=SUBMIT_TIMEOUT
            )
            return format_submission_response(
                raw, sha256, size=size, forbidden_values=(self.settings.token,)
            )
        except AnalysisError as exc:
            # A lost/malformed reply can follow durable reservation or external acceptance.
            # Even known HTTP failures retain the local reference; no POST is repeated.
            if exc.error["code"] in {
                "timeout",
                "unavailable",
                "invalid_response",
                "response_too_large",
                "submission_unknown",
            }:
                raise AnalysisError(
                    "submission_unknown", submission=unknown_submission(sha256, size)
                ) from None
            raise
