# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""MIB-specific convenience wrappers.

Each module here exposes one async tool function that walks a known MIB
subtree (or scalars) and returns a normalized payload. The generic
primitives in ``transport.py`` are the building blocks.
"""
