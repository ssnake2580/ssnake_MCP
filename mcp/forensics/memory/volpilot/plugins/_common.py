"""Shared utilities for Volatility3 plugin wrappers."""

from __future__ import annotations

import re
from typing import Any, TYPE_CHECKING

from volatility3.framework import automagic, renderers
from volatility3.framework.interfaces.renderers import BaseAbsentValue
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces.configuration import path_join

if TYPE_CHECKING:
    from session import Session

BASE_CONFIG_PATH = "plugins"

# Cap on how many raw bytes get hex-encoded into a single field. All known
# callers (LayerData previews, HexBytes secrets, Disassembly blocks) are a
# few hundred bytes at most; this is a defensive bound against a future
# plugin passing something much larger, not a limit anything hits today.
_MAX_BYTES_PREVIEW = 256


def _bytes_to_hex(data: bytes) -> str:
    """Compact hex encoding (no separators/newlines) with a size cap."""
    if len(data) > _MAX_BYTES_PREVIEW:
        return f"{data[:_MAX_BYTES_PREVIEW].hex()}...(truncated, {len(data)} bytes total)"
    return data.hex()


def _serialize_layerdata(val: "renderers.LayerData") -> str | None:
    """Read the bytes a LayerData reference points at and hex-encode them."""
    try:
        data = val.context.layers[val.layer_name].read(val.offset, val.length, True)
    except Exception:
        return None
    return _bytes_to_hex(data)


def _serialize_multitypedata(val: "format_hints.MultiTypeData") -> str:
    """Decode MultiTypeData as text where the plugin expects text, else hex."""
    if val.show_hex:
        return _bytes_to_hex(bytes(val))
    text = val.decode(val.encoding, errors="replace")
    if val.split_nulls:
        return "\n".join(part for part in text.split("\x00") if part)
    return text.split("\x00", 1)[0]


def _serialize_value(val: Any) -> Any:
    """Convert a volatility3 rendered value to a JSON-serializable type."""
    if isinstance(val, BaseAbsentValue):
        return None
    if isinstance(val, format_hints.Hex):
        return hex(val)
    if isinstance(val, format_hints.MultiTypeData):
        return _serialize_multitypedata(val)
    if isinstance(val, renderers.LayerData):
        return _serialize_layerdata(val)
    if isinstance(val, renderers.Disassembly):
        return _bytes_to_hex(val.data)
    if isinstance(val, bytes):
        # Covers format_hints.HexBytes too (a plain bytes subclass).
        return _bytes_to_hex(val)
    if isinstance(val, (int, float, bool, str)):
        return val
    return str(val)


def parse_treegrid(treegrid) -> list[dict[str, Any]]:
    """Parse a Volatility3 TreeGrid into a list of dicts."""
    col_names = [col.name for col in treegrid.columns]
    rows: list[dict[str, Any]] = []

    def visitor(node, accumulator):
        row = {
            name: _serialize_value(node.values[i])
            for i, name in enumerate(col_names)
        }
        accumulator.append(row)
        return accumulator

    treegrid.populate(visitor, rows)
    return rows


def _noop_progress(percent: float, msg: str = "") -> None:
    """No-op progress callback required by some automagics."""


_HIVE_LAYER_NAME_RE = re.compile(r"^hive0x[0-9a-fA-F]+$")


def _purge_stale_hive_layers(ctx) -> None:
    """Remove registry hive layers left behind by a previous plugin run.

    volatility3's ``HiveList.list_hives()`` names each hive layer
    deterministically (``hive<offset>``, tied only to the hive's physical
    offset) and unconditionally calls ``context.layers.add_layer(hive)``
    every time it runs, with no check for an existing layer of that name.
    Kernel and process layers don't have this problem because automagic
    gives each of them a freshly generated, unique name per plugin
    invocation; hive layers don't go through that path.

    volatility3's own CLI never hits this because it builds a brand-new
    Context for every single-plugin invocation. This server deliberately
    reuses one Context across every tool call in a session (to skip
    re-scanning layers and re-downloading PDBs on every call), so any
    second plugin that touches the registry in the same session collides
    with hive layers a previous one left registered, raising
    ``LayerException("Layer already exists: ...")``. At least 15 wrapped
    plugins touch hives, directly or indirectly: everything under
    windows.registry.*, plus windows.consoles, windows.envars,
    windows.getservicesids, windows.getsids, and windows.svcscan.

    Hive layers are cheap views over the physical layer (no PDB download,
    no large scan), so dropping and letting the next plugin reconstruct
    them is safe and matches what a fresh-Context CLI run would do
    anyway.
    """
    for name in [n for n in ctx.layers if _HIVE_LAYER_NAME_RE.match(n)]:
        try:
            ctx.layers.del_layer(name)
        except Exception:
            # Defensive: if something unexpected still depends on this
            # layer, leave it rather than let cleanup itself crash the
            # call. Worst case the upcoming plugin hits the same
            # LayerException this function exists to prevent.
            pass


def run_plugin(
    session: Session,
    plugin_class,
    extra_config: dict | None = None,
    open_method=None,
):
    """Run automagic and construct a plugin, returning a TreeGrid.

    extra_config: optional mapping of plugin-level requirement name -> value
        (e.g. {"pattern": "abc", "maxsize": 256}). Values are injected at the
        plugin's config path before automagic runs so parameterized plugins
        such as vadregexscan can be called from MCP tools with arguments.
    open_method: optional FileHandlerInterface subclass passed to the plugin
        constructor. Dump plugins (``dumpfiles``, ``pedump``, ...) call
        ``self.open(filename)`` which in turn instantiates this class to
        persist bytes. ``Session.file_handler`` binds to ``VOL_DUMP_DIR``.
    """
    ctx = session.ctx
    _purge_stale_hive_layers(ctx)
    plugin_name = plugin_class.__name__
    session.apply_config(plugin_name)
    plugin_config_path = path_join(BASE_CONFIG_PATH, plugin_name)

    if extra_config:
        for key, value in extra_config.items():
            ctx.config[path_join(plugin_config_path, key)] = value

    available = automagic.available(ctx)
    automagics = automagic.choose_automagic(available, plugin_class)
    automagic.run(automagics, ctx, plugin_class, BASE_CONFIG_PATH, progress_callback=_noop_progress)
    constructed = plugin_class(ctx, plugin_config_path, progress_callback=_noop_progress)
    if open_method is not None:
        constructed.set_open_method(open_method)
    treegrid = constructed.run()

    if not session.has_config:
        session.save_config(dict(constructed.build_configuration()))

    return treegrid
