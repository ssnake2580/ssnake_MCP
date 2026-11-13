"""SIFT tool wrappers.

Each tool validates inputs against the guardrails, runs an allow-listed binary
through the runner, emits a hash-chained audit record, and returns structured
output. Grouped by artifact class: memory, timeline, disk, registry, IOC.
"""
