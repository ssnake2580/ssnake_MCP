"""File handler factory for volatility3 dump plugins.

Dump plugins (``windows.dumpfiles``, ``windows.pedump``, ...) extract
binary content from memory by calling ``PluginInterface.open(filename)``
which returns a ``FileHandlerInterface`` instance. The interface's
``close()`` method decides *where* the bytes actually land.

This module provides ``make_file_handler(output_dir)``: a factory that
binds a ``DumpFileHandler`` class to a specific on-disk directory.
Every file opened by a plugin constructed with this handler is buffered
in memory and flushed to ``output_dir`` when the plugin finalises the
file. Filename collisions are resolved by appending ``-1``, ``-2``, ...
before the extension (same behaviour as the vol3 CLI).
"""

from __future__ import annotations

import io
import os

from volatility3.framework.interfaces import plugins


def _long_path_safe(path: str) -> str:
    """Return a path Windows' file APIs will accept regardless of length.

    Windows' classic MAX_PATH (260-character) limit applies unless the
    path is absolute and prefixed with ``\\\\?\\``, which Windows treats
    as an escape into the unrestricted-length API and which is a no-op
    everywhere else. Forensic artifact names routinely exceed this once
    joined with an output directory -- e.g. a Windows Event Log channel
    name like ``Microsoft-Windows-Windows Firewall With Advanced
    Security%4Firewall.evtx`` combined with dumpfiles' own
    ``file.<offset>.<offset>.<type>.`` prefix -- so this is applied to
    every dump write rather than only ones measured as "too long".
    """
    if os.name != "nt":
        return path
    abs_path = os.path.abspath(path)
    if abs_path.startswith("\\\\?\\"):
        return abs_path
    if abs_path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + abs_path.lstrip("\\")
    return "\\\\?\\" + abs_path


def make_file_handler(output_dir: str):
    """Return a FileHandlerInterface subclass that writes into ``output_dir``.

    The directory is created on first use. Every handler instance buffers
    writes in an ``io.BytesIO`` and flushes to
    ``<output_dir>/<preferred_filename>`` in ``close()``. Collisions are
    resolved by inserting ``-N`` before the extension.
    """
    os.makedirs(output_dir, exist_ok=True)

    class DumpFileHandler(io.BytesIO, plugins.FileHandlerInterface):
        def __init__(self, filename: str):
            io.BytesIO.__init__(self)
            plugins.FileHandlerInterface.__init__(self, filename)

        def close(self):
            if self.closed:
                return None
            self.seek(0)

            output_path = os.path.join(output_dir, self.preferred_filename)
            base, ext = os.path.splitext(output_path)
            counter = 1
            while os.path.exists(_long_path_safe(output_path)):
                output_path = f"{base}-{counter}{ext}"
                counter += 1

            with open(_long_path_safe(output_path), "wb") as fp:
                fp.write(self.read())

            super().close()

    return DumpFileHandler
