from __future__ import annotations

import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_wheel_contains_package() -> None:
    """The 0.1.0 scaffold wheel shipped metadata only — no package code.

    Root cause: ``[tool.hatch.build.targets.wheel] packages = ["scapy_mcp"]``
    while the code lived at ``src/scapy_mcp``, so hatchling collected nothing.
    This test is the regression guard for the flat-layout fix.
    """
    result = subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    wheels = sorted((REPO_ROOT / "dist").glob("*.whl"))
    assert wheels, "no wheel produced"
    with zipfile.ZipFile(wheels[-1]) as zf:
        names = zf.namelist()
    assert any(n.endswith("scapy_mcp/__init__.py") for n in names), names
    assert not any(n.startswith("src/") for n in names), names


def test_coverage_floor_is_70() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    addopts = pyproject["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--cov-fail-under=85" in addopts


def test_entry_point_delegates_to_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """``scapy-mcp`` console script resolves to ``__main__.main``, which
    must delegate to ``scapy_mcp.cli.main`` and ultimately call
    ``uvicorn.run`` with the configured port. This is the regression
    guard for the 0.1.0/0.1.1 scaffold stub that printed "not yet
    implemented" instead of starting the server.
    """
    from scapy_mcp import __main__ as entry

    calls: list[dict] = []

    class _FakeASGI:
        pass

    class _FakeRuntime:
        def build_asgi_app(self):
            return _FakeASGI()

    class _FakeSettings:
        http_port = 3056

    monkeypatch.setattr("scapy_mcp.cli.get_settings", lambda: _FakeSettings())
    monkeypatch.setattr(
        "scapy_mcp.cli.build_runtime",
        lambda *, settings: _FakeRuntime(),
    )

    def _fake_uvicorn_run(asgi, host, port, log_level):
        calls.append({"host": host, "port": port, "log_level": log_level})

    monkeypatch.setattr("scapy_mcp.cli.uvicorn.run", _fake_uvicorn_run)

    rc = entry.main()
    assert rc == 0
    assert calls == [{"host": "127.0.0.1", "port": 3056, "log_level": "info"}]
