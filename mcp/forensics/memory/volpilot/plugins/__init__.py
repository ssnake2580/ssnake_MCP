"""Volatility3 Windows plugin wrappers.

Each category module exposes a PLUGIN_MAP dict mapping plugin names to runner
functions. This package aggregates them into a single PLUGIN_MAP.
"""

from plugins._common import BASE_CONFIG_PATH
from plugins.console import PLUGIN_MAP as _console
from plugins.correlation import PLUGIN_MAP as _correlation
from plugins.desktop import PLUGIN_MAP as _desktop
from plugins.file import PLUGIN_MAP as _file
from plugins.kernel import PLUGIN_MAP as _kernel
from plugins.malware import PLUGIN_MAP as _malware
from plugins.memory import PLUGIN_MAP as _memory
from plugins.module import PLUGIN_MAP as _module
from plugins.network import PLUGIN_MAP as _network
from plugins.process import PLUGIN_MAP as _process
from plugins.registry import PLUGIN_MAP as _registry
from plugins.security import PLUGIN_MAP as _security
from plugins.service import PLUGIN_MAP as _service
from plugins.sysinfo import PLUGIN_MAP as _sysinfo

PLUGIN_MAP: dict[str, callable] = {
    **_console,
    **_correlation,
    **_desktop,
    **_file,
    **_kernel,
    **_malware,
    **_memory,
    **_module,
    **_network,
    **_process,
    **_registry,
    **_security,
    **_service,
    **_sysinfo,
}

__all__ = ["BASE_CONFIG_PATH", "PLUGIN_MAP"]
