"""VirusTotal API v3 client implementation."""

import asyncio
import hashlib
from typing import Any, Optional
from urllib.parse import quote

import aiohttp

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.config import VT_API_KEY, VT_BASE_URL
from forensics_utils_mcp_server.exceptions import VirusTotalError, RateLimitError
from forensics_utils_mcp_server.queue import queue


class VirusTotalClient:
    """VirusTotal API v3 client."""

    def __init__(self) -> None:
        self.api_key = VT_API_KEY
        self.base_url = VT_BASE_URL
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    def _get_cache_key(self, endpoint: str, identifier: str) -> str:
        """Generate cache key for VT requests."""
        return f"vt:{endpoint}:{identifier}"

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[bytes] = None,
        json_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make an HTTP request to VirusTotal API."""
        url = f"{self.base_url}/{endpoint}"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    data=data,
                    json=json_data,
                    params=params,
                ) as response:
                    if response.status == 429:
                        raise RateLimitError("Rate limit exceeded")

                    response_data = await response.json()

                    if response.status != 200:
                        error_msg = response_data.get("error", {}).get(
                            "message", "Unknown error"
                        )
                        raise VirusTotalError(
                            error_msg,
                            status_code=response.status,
                            details=response_data,
                        )

                    return response_data
            except aiohttp.ClientError as e:
                raise VirusTotalError(f"Request failed: {str(e)}")

    async def _get_with_cache(self, endpoint: str, identifier: str) -> dict:
        """Get data with caching."""
        cache_key = self._get_cache_key(endpoint, identifier)

        # Try cache first
        cached = await cache.get(cache_key)
        if cached:
            return cached

        # Make request through queue
        result = await queue.submit(
            self._make_request, "GET", f"{endpoint}/{identifier}"
        )

        # Cache the result
        await cache.set(cache_key, result)

        return result

    async def scan_file(self, file_path: str) -> dict:
        """Upload a file to VirusTotal for scanning."""
        # Calculate hash first
        sha256_hash = await self._calculate_sha256(file_path)

        # Check if already analyzed
        try:
            existing = await self.get_file_report(sha256_hash)
            if (
                existing.get("data", {})
                .get("attributes", {})
                .get("last_analysis_results")
            ):
                return {
                    "status": "already_analyzed",
                    "sha256": sha256_hash,
                    "data": existing,
                }
        except VirusTotalError:
            pass  # File not found, proceed with upload

        # Read and upload file
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Upload through queue
        result = await queue.submit(self._upload_file, file_data, file_path)

        # Cache the result
        cache_key = self._get_cache_key("files", sha256_hash)
        await cache.set(cache_key, result)

        return {"status": "uploaded", "sha256": sha256_hash, "data": result}

    async def _upload_file(self, file_data: bytes, filename: str) -> dict:
        """Upload file data to VirusTotal."""
        url = f"{self.base_url}/files"

        data = aiohttp.FormData()
        data.add_field("file", file_data, filename=filename)

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, data=data) as response:
                if response.status == 429:
                    raise RateLimitError("Rate limit exceeded")

                response_data = await response.json()

                if response.status not in [200, 201]:
                    error_msg = response_data.get("error", {}).get(
                        "message", "Unknown error"
                    )
                    raise VirusTotalError(error_msg, status_code=response.status)

                return response_data

    async def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    async def get_file_report(self, file_hash: str) -> dict:
        """Get analysis report for a file by hash."""
        return await self._get_with_cache("files", file_hash)

    async def get_file_behavior(self, file_hash: str) -> dict:
        """Get behavior summary for a file."""
        return await self._get_with_cache(f"files/{file_hash}", "behaviour_summary")

    async def scan_url(self, url: str) -> dict:
        """Submit a URL to VirusTotal for scanning."""
        url_id = quote(url, safe="")

        # Check if already analyzed
        try:
            existing = await self.get_url_report(url)
            if (
                existing.get("data", {})
                .get("attributes", {})
                .get("last_analysis_results")
            ):
                return {"status": "already_analyzed", "url": url, "data": existing}
        except VirusTotalError:
            pass

        # Submit URL through queue
        result = await queue.submit(
            self._make_request, "POST", "urls", json_data={"url": url}
        )

        # Cache the result
        cache_key = self._get_cache_key("urls", url_id)
        await cache.set(cache_key, result)

        return {"status": "submitted", "url": url, "data": result}

    async def get_url_report(self, url: str) -> dict:
        """Get analysis report for a URL."""
        url_id = quote(url, safe="")
        return await self._get_with_cache("urls", url_id)

    async def get_domain_report(self, domain: str) -> dict:
        """Get report for a domain."""
        return await self._get_with_cache("domains", domain)

    async def get_ip_report(self, ip: str) -> dict:
        """Get report for an IP address."""
        return await self._get_with_cache("ip_addresses", ip)

    async def search_files(self, query: str, limit: int = 10) -> dict:
        """Search for files using VirusTotal Intelligence."""
        params = {"query": query, "limit": limit}
        return await queue.submit(
            self._make_request, "GET", "intelligence/search", params=params
        )

    async def get_comments(self, object_id: str, object_type: str = "files") -> dict:
        """Get community comments for an object."""
        return await self._get_with_cache(f"{object_type}/{object_id}", "comments")


# Global client instance
vt_client = VirusTotalClient()
