"""Cross-plugin correlation tools.

Each function calls session.run_plugin() for the underlying plugins,
leveraging the result cache so already-executed plugins cost nothing.
The correlation logic itself is deterministic Python — no LLM reasoning
involved — guaranteeing reproducibility.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from session import Session


def run_detect_hidden_processes(session: Session) -> dict:
    """Compare pslist vs psscan to detect hidden processes.

    Processes present in psscan (pool-tag scan) but absent from pslist
    (EPROCESS linked list walk) are strong indicators of DKOM — Direct
    Kernel Object Manipulation — a technique used by rootkits to unlink
    a process from the active process list while keeping it running.
    """
    pslist_data = session.run_plugin("pslist")
    psscan_data = session.run_plugin("psscan")

    pslist_pids = {proc["PID"] for proc in pslist_data["results"]}

    hidden = [
        proc for proc in psscan_data["results"]
        if proc["PID"] not in pslist_pids
    ]

    return {
        "plugin": "detect_hidden_processes",
        "results": {
            "pslist_count": len(pslist_data["results"]),
            "psscan_count": len(psscan_data["results"]),
            "hidden_count": len(hidden),
            "hidden_processes": hidden,
        },
    }


# ---------------------------------------------------------------------------
# Known-good process baseline for anomaly detection
# ---------------------------------------------------------------------------

# Processes that should normally have exactly one instance
_SINGLETON_PROCESSES = {
    "lsass.exe", "services.exe", "smss.exe", "wininit.exe", "lsm.exe",
}

# Expected parent for key system processes (child -> expected parent name)
_EXPECTED_PARENTS = {
    "svchost.exe": "services.exe",
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "wininit.exe": "smss.exe",
    "csrss.exe": "smss.exe",
    "smss.exe": "System",
}

# System processes that must run in Session 0
_SESSION0_PROCESSES = {
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "lsm.exe",
}

# Legitimate names that attackers commonly typosquat
_LEGIT_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "winlogon.exe",
}


def _edit_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def run_detect_process_anomalies(session: Session) -> dict:
    """Flag known-bad process patterns using rule-based detection.

    Checks: parent-child violations, name masquerading (typosquatting),
    singleton violations, and Session 0 violations.
    """
    pslist_data = session.run_plugin("pslist")
    procs = pslist_data["results"]

    pid_to_name = {p["PID"]: p["ImageFileName"] for p in procs}

    # Count instances of each process name
    name_counts: dict[str, int] = {}
    for p in procs:
        name = p["ImageFileName"].lower() if p["ImageFileName"] else ""
        name_counts[name] = name_counts.get(name, 0) + 1

    anomalies: list[dict] = []

    for proc in procs:
        name = proc["ImageFileName"] or ""
        name_lower = name.lower()
        pid = proc["PID"]
        ppid = proc["PPID"]
        session_id = proc.get("SessionId")
        parent_name = pid_to_name.get(ppid, "")

        # Rule 1: expected parent-child relationship
        if name_lower in _EXPECTED_PARENTS:
            expected_parent = _EXPECTED_PARENTS[name_lower]
            if parent_name and parent_name.lower() != expected_parent.lower():
                anomalies.append({
                    "pid": pid,
                    "name": name,
                    "rule": "unexpected_parent",
                    "detail": f"Parent is {parent_name} (PID {ppid}), expected {expected_parent}",
                    "severity": "high",
                })

        # Rule 2: name masquerading (typosquatting)
        if name_lower not in _LEGIT_NAMES:
            for legit in _LEGIT_NAMES:
                dist = _edit_distance(name_lower, legit)
                if 0 < dist <= 2:
                    anomalies.append({
                        "pid": pid,
                        "name": name,
                        "rule": "name_masquerading",
                        "detail": f"Similar to {legit} (edit distance={dist})",
                        "severity": "high",
                    })
                    break

        # Rule 3: singleton violation
        if name_lower in _SINGLETON_PROCESSES and name_counts.get(name_lower, 0) > 1:
            anomalies.append({
                "pid": pid,
                "name": name,
                "rule": "singleton_violation",
                "detail": f"{name} has {name_counts[name_lower]} instances (expected 1)",
                "severity": "medium",
            })

        # Rule 4: Session 0 violation
        if name_lower in _SESSION0_PROCESSES and session_id is not None and session_id != 0:
            anomalies.append({
                "pid": pid,
                "name": name,
                "rule": "session0_violation",
                "detail": f"Running in Session {session_id}, expected Session 0",
                "severity": "high",
            })

    return {
        "plugin": "detect_process_anomalies",
        "results": {
            "total_processes": len(procs),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
        },
    }


def run_triage_process(session: Session, *, pid: int) -> dict:
    """Collect cmdline, dlllist, handles, netscan, and malfind for one PID.

    Returns a consolidated view so the analyst (or LLM) can assess a
    single process without issuing five separate tool calls.
    """
    pslist_data = session.run_plugin("pslist")
    proc_match = next(
        (p for p in pslist_data["results"] if p["PID"] == pid), None,
    )
    if proc_match is None:
        return {
            "plugin": "triage_process",
            "results": {"pid": pid, "error": f"PID {pid} not found in pslist"},
        }

    cmdline_data = session.run_plugin("cmdline")
    dlllist_data = session.run_plugin("dlllist")
    handles_data = session.run_plugin("handles")
    netscan_data = session.run_plugin("netscan")
    malfind_data = session.run_plugin("malware.malfind")

    cmdline_match = next(
        (c for c in cmdline_data["results"] if c["PID"] == pid), None,
    )

    return {
        "plugin": "triage_process",
        "results": {
            "pid": pid,
            "name": proc_match.get("ImageFileName", ""),
            "ppid": proc_match.get("PPID"),
            "create_time": proc_match.get("CreateTime"),
            "cmdline": cmdline_match.get("Args", "") if cmdline_match else "",
            "dlls": [d for d in dlllist_data["results"] if d["PID"] == pid],
            "handles": [h for h in handles_data["results"] if h["PID"] == pid],
            "network_connections": [
                n for n in netscan_data["results"] if n.get("PID") == pid
            ],
            "malfind_hits": [
                m for m in malfind_data["results"] if m["PID"] == pid
            ],
        },
    }


def run_detect_dll_injection(session: Session, *, pid: int) -> dict:
    """Cross-reference ldrmodules + malfind + dlllist to detect DLL injection.

    Checks three signals:
    1. ldrmodules: InLoad/InInit/InMem list discrepancies (unlinked DLLs)
    2. malfind: RWX memory regions in the process (injected code)
    3. dlllist vs ldrmodules module count mismatch
    """
    pslist_data = session.run_plugin("pslist")
    proc_match = next(
        (p for p in pslist_data["results"] if p["PID"] == pid), None,
    )
    if proc_match is None:
        return {
            "plugin": "detect_dll_injection",
            "results": {"pid": pid, "error": f"PID {pid} not found in pslist"},
        }

    ldrmodules_data = session.run_plugin("malware.ldrmodules")
    malfind_data = session.run_plugin("malware.malfind")
    dlllist_data = session.run_plugin("dlllist")

    # ldrmodules uses "Pid" (lowercase id)
    ldr_for_pid = [m for m in ldrmodules_data["results"] if m["Pid"] == pid]
    dll_for_pid = [d for d in dlllist_data["results"] if d["PID"] == pid]
    mal_for_pid = [m for m in malfind_data["results"] if m["PID"] == pid]

    indicators: list[dict] = []

    # Signal 1: unlinked DLLs in ldrmodules
    for mod in ldr_for_pid:
        in_load = mod.get("InLoad", True)
        in_init = mod.get("InInit", True)
        in_mem = mod.get("InMem", True)
        if not (in_load and in_init and in_mem):
            missing = []
            if not in_load:
                missing.append("InLoad")
            if not in_init:
                missing.append("InInit")
            if not in_mem:
                missing.append("InMem")
            indicators.append({
                "type": "unlinked_dll",
                "detail": f"{mod.get('MappedPath', 'unknown')} missing from {', '.join(missing)}",
                "base": mod.get("Base"),
                "source": "ldrmodules",
            })

    # Signal 2: RWX regions from malfind
    for hit in mal_for_pid:
        indicators.append({
            "type": "rwx_region",
            "detail": f"RWX VAD at {hit.get('Start VPN', '?')}-{hit.get('End VPN', '?')} ({hit.get('Protection', '')})",
            "notes": hit.get("Notes", ""),
            "source": "malfind",
        })

    return {
        "plugin": "detect_dll_injection",
        "results": {
            "pid": pid,
            "name": proc_match.get("ImageFileName", ""),
            "injection_indicator_count": len(indicators),
            "injection_indicators": indicators,
            "dlls_in_dlllist": len(dll_for_pid),
            "modules_in_ldrmodules": len(ldr_for_pid),
        },
    }


def run_network_process_correlation(session: Session) -> dict:
    """Join netscan results with pslist and cmdline for attribution.

    Each network connection is enriched with the owning process's name,
    parent PID, creation time, and full command line.
    """
    netscan_data = session.run_plugin("netscan")
    pslist_data = session.run_plugin("pslist")
    cmdline_data = session.run_plugin("cmdline")

    pid_to_proc = {p["PID"]: p for p in pslist_data["results"]}
    pid_to_cmdline = {}
    for c in cmdline_data["results"]:
        pid_to_cmdline[c["PID"]] = c.get("Args", "")

    connections = []
    for conn in netscan_data["results"]:
        pid = conn.get("PID")
        proc = pid_to_proc.get(pid, {})
        enriched = {
            **conn,
            "process_name": proc.get("ImageFileName", conn.get("Owner", "")),
            "ppid": proc.get("PPID"),
            "create_time": proc.get("CreateTime"),
            "cmdline": pid_to_cmdline.get(pid, ""),
        }
        connections.append(enriched)

    return {
        "plugin": "network_process_correlation",
        "results": {
            "total_connections": len(connections),
            "connections": connections,
        },
    }


def run_detect_service_tampering(session: Session) -> dict:
    """Diff svcscan vs svclist to detect hidden or tampered services.

    svclist walks the SCM linked list (available only on Win10 15063+ x64).
    svcscan discovers records by pool-tag scanning. Services present in
    svcscan but absent from svclist were unlinked — a DKOM indicator.
    When svclist is unavailable (older OS), the tool returns svcscan-only
    results with an explicit compatibility note.
    """
    svcscan_data = session.run_plugin("svcscan")
    svcscan_services = svcscan_data["results"]

    # Attempt svclist — may return empty on incompatible OS
    svclist_data = session.run_plugin("svclist")
    svclist_services = svclist_data["results"]

    os_compatible = len(svclist_services) > 0

    hidden_services: list[dict] = []
    if os_compatible:
        svclist_names = {s["Name"] for s in svclist_services if s.get("Name")}
        for svc in svcscan_services:
            name = svc.get("Name", "")
            if name and name not in svclist_names:
                hidden_services.append({**svc, "source": "svcscan_only"})

    # Also include malware.svcdiff results if available on this OS
    svcdiff_results = []
    if os_compatible:
        try:
            svcdiff_data = session.run_plugin("malware.svcdiff")
            svcdiff_results = svcdiff_data["results"]
        except Exception:
            pass  # svcdiff may fail on incompatible OS

    return {
        "plugin": "detect_service_tampering",
        "results": {
            "svcscan_count": len(svcscan_services),
            "svclist_count": len(svclist_services) if os_compatible else None,
            "os_compatible": os_compatible,
            "hidden_count": len(hidden_services),
            "hidden_services": hidden_services,
            "svcdiff_results": svcdiff_results,
        },
    }


def _parse_timestamp(val: str | None) -> str | None:
    """Normalize a Volatility3 timestamp string to ISO 8601, or None."""
    if not val or val == "N/A" or val == "None":
        return None
    val = val.strip()
    # Already ISO-ish: "2026-03-15 14:22:01.000000" → "2026-03-15T14:22:01"
    try:
        from datetime import datetime
        # Handle "YYYY-MM-DD HH:MM:SS.ffffff" (most common vol3 format)
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(val, fmt)
                return dt.isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return None


def run_build_timeline(session: Session) -> dict:
    """Merge timestamps from multiple plugins into a chronological timeline.

    Sources: pslist/psscan (process create/exit), netscan (connection created),
    shimcachemem (execution evidence), registry.userassist (user program launches).
    """
    events: list[dict] = []

    # --- 1. pslist: process created / exited ---
    pslist_data = session.run_plugin("pslist")
    pslist_pids: set[int] = set()
    for proc in pslist_data["results"]:
        pid = proc["PID"]
        pslist_pids.add(pid)
        name = proc.get("ImageFileName", "")

        ts = _parse_timestamp(str(proc.get("CreateTime", "")))
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "process_created",
                "pid": pid,
                "name": name,
                "detail": f"PPID={proc.get('PPID', '?')}",
            })

        ts = _parse_timestamp(str(proc.get("ExitTime", "")))
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "process_exited",
                "pid": pid,
                "name": name,
                "detail": "",
            })

    # --- 2. psscan: add processes not in pslist (hidden/terminated) ---
    psscan_data = session.run_plugin("psscan")
    for proc in psscan_data["results"]:
        pid = proc["PID"]
        if pid in pslist_pids:
            continue
        name = proc.get("ImageFileName", "")

        ts = _parse_timestamp(str(proc.get("CreateTime", "")))
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "process_created",
                "pid": pid,
                "name": f"{name} [psscan-only]",
                "detail": f"PPID={proc.get('PPID', '?')}",
            })

        ts = _parse_timestamp(str(proc.get("ExitTime", "")))
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "process_exited",
                "pid": pid,
                "name": f"{name} [psscan-only]",
                "detail": "",
            })

    # --- 3. netscan: network connections ---
    netscan_data = session.run_plugin("netscan")
    for conn in netscan_data["results"]:
        ts = _parse_timestamp(str(conn.get("Created", "")))
        if ts:
            proto = conn.get("Proto", "")
            local = f"{conn.get('LocalAddr', '?')}:{conn.get('LocalPort', '?')}"
            foreign = f"{conn.get('ForeignAddr', '?')}:{conn.get('ForeignPort', '?')}"
            state = conn.get("State", "")
            events.append({
                "timestamp": ts,
                "event_type": "network_connection",
                "pid": conn.get("PID"),
                "name": conn.get("Owner", ""),
                "detail": f"{proto} {local} -> {foreign} {state}",
            })

    # --- 4. shimcachemem: program execution evidence ---
    shimcache_data = session.run_plugin("shimcachemem")
    for entry in shimcache_data["results"]:
        ts = _parse_timestamp(str(entry.get("Last Update", "")))
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "program_executed",
                "pid": None,
                "name": entry.get("Path", ""),
                "detail": f"Exec={entry.get('Exec Flag', '?')}",
            })

    # --- 5. registry.userassist: user program launches ---
    userassist_data = session.run_plugin("registry.userassist")
    for entry in userassist_data["results"]:
        ts = _parse_timestamp(str(entry.get("Last Updated", "")))
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "userassist_executed",
                "pid": None,
                "name": entry.get("Name", ""),
                "detail": f"Count={entry.get('Count', '?')} Focus={entry.get('Focus Count', '?')}",
            })

    # Sort chronologically
    events.sort(key=lambda e: e["timestamp"])

    # Compute source counts
    sources: dict[str, int] = {}
    for e in events:
        sources[e["event_type"]] = sources.get(e["event_type"], 0) + 1

    return {
        "plugin": "build_timeline",
        "results": {
            "total_events": len(events),
            "sources": sources,
            "timeline": events,
        },
    }


PLUGIN_MAP = {
    "detect_hidden_processes": run_detect_hidden_processes,
    "detect_process_anomalies": run_detect_process_anomalies,
    "triage_process": run_triage_process,
    "detect_dll_injection": run_detect_dll_injection,
    "network_process_correlation": run_network_process_correlation,
    "detect_service_tampering": run_detect_service_tampering,
    "build_timeline": run_build_timeline,
}
