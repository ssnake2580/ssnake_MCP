import pytest
import aiohttp
import asyncio
from aiohttp import web
import sys
from unittest import mock

from mcp_scheduler.well_known import setup_well_known

# Dummy server for test
class DummyTool:
    def __init__(self, name, description, params=None, required=None):
        self.name = name
        self.description = description
        self.signature = mock.Mock()
        self.signature.parameters = params or {}
        self.signature.__contains__ = lambda self, key: key in (params or {})

class DummyServer:
    def __init__(self):
        self.config = mock.Mock()
        self.config.server_name = "test-server"
        self.config.server_version = "0.0.1"
        self.config.server_address = "127.0.0.1"
        self.config.server_port = 9999
        self.config.transport = "sse"
        self.mcp = mock.Mock()
        self.mcp.tools = [
            DummyTool("foo", "desc foo"),
            DummyTool("bar", "desc bar")
        ]

sys.modules["main"] = mock.Mock(server=DummyServer())

@pytest.mark.asyncio
async def test_well_known_schema():
    app = web.Application()
    setup_well_known(app)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 9998)
    await site.start()
    await asyncio.sleep(0.2)
    session = aiohttp.ClientSession()
    try:
        async with session.get("http://127.0.0.1:9998/.well-known/mcp-schema.json") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert "tools" in data
            assert isinstance(data["tools"], list)
            assert any(tool["name"] == "foo" for tool in data["tools"])
    finally:
        await session.close()
        await runner.cleanup()
