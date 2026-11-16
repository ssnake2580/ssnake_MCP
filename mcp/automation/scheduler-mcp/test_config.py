from mcp_scheduler.config import Config
import os
import tempfile
import json

def test_config_env_vars():
    os.environ["MCP_SCHEDULER_NAME"] = "test-name"
    c = Config()
    assert c.server_name == "test-name"
    del os.environ["MCP_SCHEDULER_NAME"]

def test_config_file_load():
    config_data = {
        "server": {"name": "file-name", "version": "1.2.3", "address": "abc", "port": 1234, "transport": "sse"},
        "database": {"path": "file.db"}
    }
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        json.dump(config_data, f)
        fname = f.name
    os.environ["MCP_SCHEDULER_CONFIG_FILE"] = fname
    c = Config()
    assert c.server_name == "file-name"
    assert c.server_port == 1234
    os.unlink(fname)
    del os.environ["MCP_SCHEDULER_CONFIG_FILE"]
