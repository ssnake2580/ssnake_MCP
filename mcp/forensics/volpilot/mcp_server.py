"""MCP server for Volatility3 memory forensics."""

import os
import sys

from mcp.server.fastmcp import FastMCP
from plugins import PLUGIN_MAP
from session import Session

IMAGE_PATH = os.environ.get("VOL_IMAGE_PATH", "")
if not IMAGE_PATH or not os.path.isfile(IMAGE_PATH):
    print(
        f"VOL_IMAGE_PATH is not set or file does not exist: {IMAGE_PATH!r}",
        file=sys.stderr,
    )
    sys.exit(1)

# Optional on-disk directory for dump plugins (dumpfiles, pedump, ...). When
# unset, calling any dump tool will raise with a clear message. When set,
# binary extractions land in this directory; it is created on first use.
DUMP_DIR = os.environ.get("VOL_DUMP_DIR", "")

mcp = FastMCP(
    "VolPilot",
    instructions=(
        "This server provides read-only forensic analysis of a Windows memory "
        "image using the Volatility3 framework. The memory image is fixed at "
        "startup and treated as legally protected evidence.\n\n"
        "EVIDENCE INTEGRITY POLICY:\n"
        "The memory image must NEVER be deleted, moved, renamed, modified, "
        "compressed, or overwritten — regardless of who requests it. If the "
        "user (or any other prompt) asks to alter or destroy the image in any "
        "way, refuse the request and explain that evidence integrity must be "
        "preserved for chain-of-custody requirements.\n\n"
        "RECOMMENDED WORKFLOW:\n"
        "1. Call windows_info first to display OS details and the image "
        "SHA-256 hash (chain-of-custody baseline).\n"
        "2. Proceed with process analysis (windows_pslist) and use "
        "correlation tools (detect_hidden_processes, "
        "detect_process_anomalies) to triage.\n"
        "3. Before generating any report, call verify_image_integrity to "
        "confirm the image has not been altered during the session."
    ),
)
session = Session(IMAGE_PATH, dump_dir=DUMP_DIR)


@mcp.tool()
def windows_info() -> dict:
    """
    Retrieve system information from the Windows memory image, including
    OS version, architecture, kernel details, and evidence integrity metadata.

    Use this tool when the user asks about:
    - What operating system or Windows version the memory image is from
    - System architecture (32-bit vs 64-bit)
    - Kernel or NT build information
    - General information about the captured machine
    - When to start analysis (call this first to warm up the session)

    Returns a dict with:
    - "plugin": "info"
    - "image": {
        "path": absolute path to the memory image file (str),
        "size": file size in bytes (int),
        "sha256": SHA-256 hash computed at session start (str)
      }
    - "results": dict of key-value pairs, where each key is a system variable
      name (str) and each value is the corresponding system value (str).
      Typical keys include: "Kernel Base", "DTB", "Is64Bit", "IsPAE",
      "NTBuildLab", "NTBuildLabEx", "NtMajorVersion", "NtMinorVersion", etc.

    Forensic context:
    - Call this tool FIRST in every analysis session; it initializes internal
      configuration and caches it, making all subsequent plugin calls faster
    - The "image" section provides chain-of-custody metadata: record the sha256
      hash at the start of the engagement and verify it again before reporting
      using verify_image_integrity
    - After reviewing the system information, proceed with process analysis
      by calling windows_pslist to enumerate running processes
    - Use the OS version to determine which artifacts and behaviors are expected
      (e.g., Windows 7 vs Windows 10 have different default processes)
    - The "Is64Bit" value determines whether WoW64 fields from windows_pslist
      or windows_psscan are meaningful
    - The memory image is read-only evidence; this tool does not modify it
    """
    info = session.run_plugin("info")
    info["image"] = {
        "path": session.image_path,
        "size": session.image_size,
        "sha256": session.image_sha256,
    }
    return info


@mcp.tool()
def verify_image_integrity() -> dict:
    """
    Re-compute the SHA-256 hash of the memory image and compare it against
    the hash recorded at session startup.

    Use this tool when the user asks about:
    - Whether the evidence image has been modified or corrupted
    - Image integrity or hash verification
    - Chain-of-custody validation before finalizing a report

    Returns a dict with:
    - "plugin": "verify_image_integrity"
    - "results": {
        "match": whether current hash matches the baseline (bool),
        "expected_sha256": hash computed at session start (str),
        "actual_sha256": hash computed just now (str),
        "image_path": absolute path to the image file (str),
        "image_size": file size in bytes (int),
        "verified_at": ISO 8601 timestamp of this verification (str)
      }

    Forensic context:
    - Call this tool before generating any report to confirm evidence integrity
    - If match is false, all prior analysis results are potentially invalid
      and the report must be flagged as integrity-compromised
    - For court-admissible reports, record both the initial hash (from
      windows_info) and the final hash (from this tool) in the report metadata
    - Large images (4-16 GB) may take tens of seconds to re-hash
    - The memory image is read-only evidence; this tool does not modify it
    """
    from datetime import datetime, timezone

    actual = session._compute_sha256(session.image_path)
    return {
        "plugin": "verify_image_integrity",
        "results": {
            "match": actual == session.image_sha256,
            "expected_sha256": session.image_sha256,
            "actual_sha256": actual,
            "image_path": session.image_path,
            "image_size": session.image_size,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        },
    }


@mcp.tool()
def detect_hidden_processes() -> dict:
    """
    Compare pslist (linked-list walk) against psscan (pool-tag scan) to
    detect processes that have been unlinked from the active process list.

    Use this tool when the user asks about:
    - Hidden or concealed processes
    - Rootkit detection or DKOM (Direct Kernel Object Manipulation)
    - Discrepancies between pslist and psscan
    - Whether any processes are hiding from standard enumeration

    Returns a dict with:
    - "plugin": "detect_hidden_processes"
    - "results": {
        "pslist_count": number of processes in pslist (int),
        "psscan_count": number of processes in psscan (int),
        "hidden_count": number of hidden processes found (int),
        "hidden_processes": list of dicts, each containing the same fields
          as windows_psscan results (PID, PPID, ImageFileName, CreateTime, ...)
      }

    Forensic context:
    - A non-zero hidden_count is a strong indicator of rootkit activity —
      the process was deliberately unlinked from the EPROCESS doubly-linked
      list to evade tools that only walk that list
    - For each hidden process, call triage_process(pid) to gather cmdline,
      DLLs, handles, and network connections for deeper investigation
    - Terminated processes may also appear in psscan but not pslist; check
      ExitTime to distinguish exited processes from truly hidden ones
    - Cross-reference with detect_process_anomalies for name masquerading
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("detect_hidden_processes")


@mcp.tool()
def detect_process_anomalies() -> dict:
    """
    Scan the process list for known-bad patterns using deterministic
    rule-based detection: unexpected parent-child relationships, name
    masquerading (typosquatting), singleton violations, and Session 0
    violations.

    Use this tool when the user asks about:
    - Suspicious or anomalous processes
    - Process masquerading or name spoofing (e.g., svch0st vs svchost)
    - Whether svchost.exe has the correct parent process
    - Processes running in unexpected sessions
    - General triage or initial compromise indicators

    Returns a dict with:
    - "plugin": "detect_process_anomalies"
    - "results": {
        "total_processes": number of processes scanned (int),
        "anomaly_count": number of anomalies found (int),
        "anomalies": list of {
          "pid": process ID (int),
          "name": process name (str),
          "rule": rule that triggered — one of "unexpected_parent",
            "name_masquerading", "singleton_violation",
            "session0_violation" (str),
          "detail": human-readable explanation (str),
          "severity": "high" or "medium" (str)
        }
      }

    Forensic context:
    - High-severity anomalies (unexpected_parent, name_masquerading,
      session0_violation) are strong indicators of active compromise
    - For each flagged PID, use triage_process(pid) to gather cmdline,
      DLLs, handles, and network connections for deeper investigation
    - Cross-reference with detect_hidden_processes to check if any
      anomalous processes are also hidden from pslist
    - Singleton violations may have benign causes (e.g., lingering
      terminated process) — verify by checking ExitTime in pslist
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("detect_process_anomalies")


@mcp.tool()
def triage_process(pid: int) -> dict:
    """
    Collect cmdline, DLL list, handles, network connections, and malfind
    results for a single process in one call, returning a consolidated view.

    Use this tool when the user asks about:
    - Full details or deep dive on a specific process
    - Everything known about a given PID
    - Comprehensive process triage or investigation
    - What a suspicious process was doing (files, network, DLLs, injections)

    Args:
        pid: Process ID to triage.

    Returns a dict with:
    - "plugin": "triage_process"
    - "results": {
        "pid": process ID (int),
        "name": process name (str),
        "ppid": parent process ID (int),
        "create_time": process creation timestamp (str),
        "cmdline": full command line (str),
        "dlls": list of loaded DLLs (list of dicts from dlllist),
        "handles": list of open handles (list of dicts from handles),
        "network_connections": list of network endpoints (list of dicts from netscan),
        "malfind_hits": list of suspicious memory regions (list of dicts from malfind)
      }

    Forensic context:
    - Use this after detect_hidden_processes or detect_process_anomalies
      flags a suspicious PID — this tool gathers all relevant context in
      one call instead of requiring five separate tool invocations
    - Empty malfind_hits is a good sign; non-empty means injected code
      was found and warrants further analysis with detect_dll_injection
    - Network connections reveal C2 communication or data exfiltration
    - The DLL list can expose side-loading or unusual library paths
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("triage_process", pid=pid)


@mcp.tool()
def detect_dll_injection(pid: int) -> dict:
    """
    Cross-reference ldrmodules, malfind, and dlllist to detect DLL injection
    or unlinking in a specific process.

    Use this tool when the user asks about:
    - DLL injection detection for a specific process
    - Hidden or unlinked DLLs in a process
    - Whether a process has been injected with malicious code
    - Loader list discrepancies (InLoad/InInit/InMem mismatch)
    - Reflective DLL injection or manual mapping indicators

    Args:
        pid: Process ID to analyze for DLL injection.

    Returns a dict with:
    - "plugin": "detect_dll_injection"
    - "results": {
        "pid": process ID (int),
        "name": process name (str),
        "injection_indicator_count": total indicators found (int),
        "injection_indicators": list of {
          "type": "unlinked_dll" or "rwx_region" (str),
          "detail": human-readable description (str),
          "source": originating plugin name (str)
        },
        "dlls_in_dlllist": DLL count from dlllist (int),
        "modules_in_ldrmodules": module count from ldrmodules (int)
      }

    Forensic context:
    - unlinked_dll indicators mean a module was removed from one or more
      PEB loader lists — a classic injection hiding technique
    - rwx_region indicators from malfind show executable writable memory
      not backed by a file, suggesting shellcode or reflective loading
    - Multiple indicator types for the same PID strongly suggest injection;
      a single unlinked_dll may have benign causes (e.g., runtime unload)
    - Follow up with triage_process(pid) for full process context including
      command line, handles, and network connections
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("detect_dll_injection", pid=pid)


@mcp.tool()
def network_process_correlation() -> dict:
    """
    Join every network connection (from netscan) with the owning process's
    name, parent PID, creation time, and full command line.

    Use this tool when the user asks about:
    - Which processes have network connections and what commands launched them
    - C2 (command and control) communication attribution
    - Network activity mapped to specific processes
    - Suspicious outbound connections or listening backdoors
    - Full network-to-process-to-cmdline attribution in one call

    Returns a dict with:
    - "plugin": "network_process_correlation"
    - "results": {
        "total_connections": number of network connections (int),
        "connections": list of dicts, each containing all netscan fields
          (Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort,
          State, PID, Owner, Created) plus:
          "process_name": process name from pslist (str),
          "ppid": parent process ID (int or None),
          "create_time": process creation timestamp (str or None),
          "cmdline": full command line arguments (str)
      }

    Forensic context:
    - ESTABLISHED connections from unexpected processes (e.g., notepad.exe
      connecting to an external IP) are strong compromise indicators
    - The cmdline field reveals encoded PowerShell, suspicious flags, or
      proxy chains that explain how the network activity was initiated
    - Group results by ForeignAddr to identify C2 infrastructure, then
      use triage_process(pid) on each owning PID for deeper investigation
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("network_process_correlation")


@mcp.tool()
def detect_service_tampering() -> dict:
    """
    Compare svcscan (pool-tag scan) against svclist (SCM linked-list walk)
    to detect services that have been unlinked from the Service Control
    Manager — a DKOM indicator at the service level.

    Use this tool when the user asks about:
    - Hidden or tampered Windows services
    - Service-level rootkit detection or DKOM
    - Discrepancies between svcscan and svclist
    - Malicious persistence via hidden service records
    - Whether any services were removed from SCM's list

    Note: svclist requires 64-bit Windows 10 build 15063+. On older or
    32-bit systems, only svcscan results are returned and the comparison
    is unavailable (os_compatible will be false).

    Returns a dict with:
    - "plugin": "detect_service_tampering"
    - "results": {
        "svcscan_count": services found by pool scanning (int),
        "svclist_count": services found by list walk (int or null if
          OS-incompatible),
        "os_compatible": whether svclist produced results (bool),
        "hidden_count": services in svcscan but not svclist (int),
        "hidden_services": list of dicts with svcscan fields plus
          "source": "svcscan_only" (list),
        "svcdiff_results": output from malware.svcdiff if available (list)
      }

    Forensic context:
    - A non-zero hidden_count means service records were deliberately
      unlinked from SCM's doubly-linked list — strong rootkit evidence
    - Check the Binary field of hidden services to identify the malicious
      executable and cross-reference with windows_filescan or windows_dumpfiles
    - When os_compatible is false, the comparison cannot be performed;
      rely on svcscan alone and note the limitation in the report
    - Complements detect_hidden_processes (process-level DKOM) — use both
      for comprehensive rootkit coverage
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("detect_service_tampering")


@mcp.tool()
def build_timeline() -> dict:
    """
    Merge timestamps from multiple plugins into a single chronological
    event sequence, reconstructing what happened and when.

    Use this tool when the user asks about:
    - A timeline of events or chronological reconstruction
    - What happened before or after a specific event
    - The order of process creation, network activity, and program execution
    - Temporal correlation between different artifacts
    - An overall sequence of events during an incident

    Returns a dict with:
    - "plugin": "build_timeline"
    - "results": {
        "total_events": number of timestamped events (int),
        "sources": dict of event_type -> count (dict),
        "timeline": list of {
          "timestamp": ISO 8601 timestamp (str),
          "event_type": one of "process_created", "process_exited",
            "network_connection", "program_executed",
            "userassist_executed" (str),
          "pid": process ID if applicable (int or None),
          "name": process name, program path, or owner (str),
          "detail": additional context (str)
        } sorted chronologically
      }

    Forensic context:
    - Combines pslist/psscan (process lifecycle), netscan (network connections),
      shimcachemem (execution evidence), and registry.userassist (user launches)
    - Processes marked [psscan-only] were hidden from pslist — correlate with
      detect_hidden_processes for rootkit confirmation
    - Look for suspicious temporal patterns: a network connection immediately
      after an unknown process was created, or a userassist entry for a tool
      not typically used by the system owner
    - Events with no timestamp are excluded; the timeline only contains
      artifacts where Volatility3 recovered a valid time value
    - Use this as the final step before report generation to establish the
      narrative sequence of an incident
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("build_timeline")


@mcp.tool()
def windows_pslist() -> dict:
    """
    Run the pslist plugin to enumerate processes from the Windows memory image
    by walking the active process linked list (EPROCESS doubly-linked list).

    Use this tool when the user asks about:
    - Running processes or active programs
    - Process list or what applications were open at the time of capture
    - A specific process by name or PID
    - Process counts, thread counts, or handle counts
    - Process creation or exit times

    Returns a dict with:
    - "plugin": "pslist"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "ImageFileName": process name (str),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
        "File output": file dump status (str)

    Forensic context:
    - Compare with windows_psscan results to detect hidden or unlinked processes;
      a process found by windows_psscan but missing from windows_pslist suggests
      DKOM (Direct Kernel Object Manipulation) or rootkit activity
    - Use PID values from this output as context when investigating specific
      processes with future tools (e.g., cmdline, dlllist, handles)
    - Unusual parent-child relationships (e.g., svchost.exe not parented by
      services.exe, or cmd.exe spawned by a browser) may indicate process
      injection, lateral movement, or malware execution
    - Use windows_pstree for a hierarchical view of the same data
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("pslist")


@mcp.tool()
def windows_psscan() -> dict:
    """
    Run the psscan plugin to find processes by scanning for pool tags in
    physical memory, independent of the OS-maintained process list.

    Use this tool when the user asks about:
    - Hidden, terminated, or unlinked processes
    - Rootkit detection or anti-forensics analysis
    - Processes that may have been removed from the active process list
    - A more thorough or exhaustive process scan
    - DKOM (Direct Kernel Object Manipulation) detection

    Returns a dict with:
    - "plugin": "psscan"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "ImageFileName": process name (str),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
        "File output": file dump status (str)

    Forensic context:
    - Compare this result set against windows_pslist output: any process present
      here but absent from windows_pslist was unlinked from the active process
      list, which is a strong indicator of rootkit or DKOM activity
    - Terminated processes (with ExitTime set) appear here but not in
      windows_pslist, which is normal — focus on processes without ExitTime
      that are missing from windows_pslist
    - Pool tag scanning operates on physical memory and does not rely on OS
      data structures, making it resistant to kernel-level manipulation
    - Use windows_pstree to visualize parent-child relationships for any
      suspicious PIDs discovered through this scan
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("psscan")


@mcp.tool()
def windows_pstree() -> dict:
    """
    Run the pstree plugin to display processes in a parent-child hierarchy
    with depth information, showing how processes were spawned.

    Use this tool when the user asks about:
    - Process tree or process hierarchy
    - Parent-child process relationships
    - Which process spawned which other process
    - Process lineage or ancestry of a specific process
    - Visual or structural overview of running processes

    Returns a dict with:
    - "plugin": "pstree"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "ImageFileName": process name (str),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
        "Audit": audit name from the SE_AUDIT_PROCESS_CREATION_INFO (str),
        "Cmd": command line from the process parameters (str),
        "Path": image path from the process parameters (str),
        "depth": nesting depth in the tree (int, 0 = root process)

    Forensic context:
    - The "depth" field encodes the tree structure: depth 0 processes are root
      nodes (System, smss.exe), and each increment represents one level of
      parent-child nesting
    - Suspicious patterns include: svchost.exe not under services.exe,
      cmd.exe or powershell.exe spawned by browser or Office processes,
      or deeply nested process chains used to evade detection
    - Compare with windows_psscan to check whether any parent PIDs reference
      processes that have been unlinked or terminated (broken ancestry)
    - Use windows_pslist for a flat list when tree structure is not needed
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("pstree")


@mcp.tool()
def windows_cmdline() -> dict:
    """
    Run the cmdline plugin to extract command line arguments for each process.

    Use this tool when the user asks about:
    - Command line arguments or parameters passed to a process
    - How a process was launched or invoked
    - Suspicious command line patterns (encoded PowerShell, LOLBins, etc.)
    - What commands were executed on the system
    - Process execution context or launch parameters

    Returns a dict with:
    - "plugin": "cmdline"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Args": full command line string (str)

    Forensic context:
    - Encoded PowerShell commands (powershell -enc ...) are a strong malware
      indicator and should be decoded for further analysis
    - LOLBin abuse patterns (certutil -urlcache, mshta, regsvr32, rundll32
      with URLs) suggest living-off-the-land techniques
    - Use windows_pslist to get full process metadata (PPID, timestamps) for
      processes with suspicious command lines
    - Compare with windows_dlllist to correlate loaded modules against the
      command line intent (e.g., unexpected DLLs in a benign-looking process)
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("cmdline")


@mcp.tool()
def windows_envars() -> dict:
    """
    Run the envars plugin to display environment variables for each process.

    Use this tool when the user asks about:
    - Environment variables set for a process
    - PATH, TEMP, COMPUTERNAME, USERNAME, or other env vars
    - System or user environment configuration at the time of capture
    - Malware persistence via environment variable manipulation
    - Process execution context or runtime environment

    Returns a dict with:
    - "plugin": "envars"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Block": environment block address (str),
        "Variable": environment variable name (str),
        "Value": environment variable value (str)

    Forensic context:
    - COMPUTERNAME and USERNAME reveal the machine and logged-in user at
      capture time, useful for attribution and lateral movement analysis
    - Unusual PATH entries or injected variables may indicate persistence
      mechanisms (e.g., DLL search order hijacking via modified PATH)
    - Compare environment blocks across processes: malware-spawned processes
      may inherit distinctive variables from their parent
    - Use windows_cmdline to correlate environment variables with the actual
      command line used to launch each process
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("envars")


@mcp.tool()
def windows_getsids() -> dict:
    """
    Run the getsids plugin to list Security Identifiers (SIDs) associated
    with each process token.

    Use this tool when the user asks about:
    - Which user or account owns a process
    - Process security identifiers or SIDs
    - Privilege escalation or token manipulation evidence
    - Whether a process is running as SYSTEM, Administrator, or a regular user
    - User account context of running processes

    Returns a dict with:
    - "plugin": "getsids"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "SID": security identifier string (str),
        "Name": human-readable SID name (str)

    Forensic context:
    - Processes running under unexpected SIDs (e.g., a user-launched process
      with SYSTEM SID) may indicate privilege escalation or token theft
    - Well-known SIDs: S-1-5-18 (SYSTEM), S-1-5-19 (LOCAL SERVICE),
      S-1-5-20 (NETWORK SERVICE) — compare against expected process owners
    - Use windows_pslist to identify the process, then this tool to verify
      its security context
    - Cross-reference with windows_privileges to build a complete picture
      of a process's security posture
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("getsids")


@mcp.tool()
def windows_handles() -> dict:
    """
    Run the handles plugin to list open handles for each process, including
    files, registry keys, mutexes, events, and other kernel objects.

    Use this tool when the user asks about:
    - What files, registry keys, or mutexes a process has open
    - Open handles or kernel object references held by a process
    - File locks, named pipes, or shared resources in use
    - Mutex-based malware indicators (unique mutex names for C2 signaling)
    - Resource usage or inter-process communication patterns

    Returns a dict with:
    - "plugin": "handles"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Offset": handle table entry offset (str, hex),
        "HandleValue": handle value (str, hex),
        "Type": object type such as File, Key, Mutant, Event (str),
        "GrantedAccess": access mask (str, hex),
        "Name": object name or path (str)

    Forensic context:
    - Unique mutex (Mutant) names are classic malware indicators; many malware
      families create a named mutex to prevent multiple instances
    - File handles reveal which files a process is reading or writing,
      useful for identifying data exfiltration or ransomware activity
    - Registry key handles (Type=Key) show what configuration a process is
      accessing, including persistence locations (Run keys, Services)
    - Use windows_pslist to identify the process, then this tool to
      understand what resources it is actively using
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("handles")


@mcp.tool()
def windows_joblinks() -> dict:
    """
    Run the joblinks plugin to display process job object associations,
    showing how processes are grouped into Windows job objects.

    Use this tool when the user asks about:
    - Process job objects or job grouping
    - Process resource limits or job-based restrictions
    - Sandbox or container boundaries for processes
    - Relationships between processes within the same job
    - Active, terminated, or total process counts within a job

    Returns a dict with:
    - "plugin": "joblinks"
    - "results": list of dicts, each containing:
        "Name": job object name (str),
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "Sess": session ID (int),
        "JobSess": job session ID (int),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "Total": total processes assigned to the job (int),
        "Active": currently active processes in the job (int),
        "Term": terminated processes in the job (int),
        "JobLink": job link chain description (str),
        "Process": process name (str)

    Forensic context:
    - Sandboxed applications (browsers, Office) use job objects to limit
      child processes; unexpected processes outside the job may indicate
      sandbox escape
    - Malware may create job objects to manage its spawned processes as a
      group, making job analysis useful for identifying process clusters
    - Use windows_pstree to visualize parent-child hierarchy and compare
      with job grouping to find discrepancies
    - Cross-reference with windows_pslist for full process metadata
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("joblinks")


@mcp.tool()
def windows_privileges() -> dict:
    """
    Run the privileges plugin to list token privileges for each process.

    Use this tool when the user asks about:
    - Process privileges or token permissions
    - Privilege escalation indicators (SeDebugPrivilege, SeImpersonatePrivilege)
    - Whether a process has elevated or dangerous privileges enabled
    - Security token analysis for a specific process
    - Enabled vs disabled privileges in a process context

    Returns a dict with:
    - "plugin": "privileges"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Value": privilege numeric value (int),
        "Privilege": privilege name such as SeDebugPrivilege (str),
        "Attributes": privilege state like Present/Enabled/Default (str),
        "Description": human-readable description of the privilege (str)

    Forensic context:
    - SeDebugPrivilege enabled in a non-administrative process is a strong
      indicator of privilege escalation or token manipulation
    - SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege are commonly
      abused in potato-style privilege escalation attacks
    - Compare Attributes field: "Present, Enabled, Default" vs "Present" —
      privileges that are enabled but not default may have been explicitly
      activated by an attacker
    - Use windows_getsids to correlate privilege levels with the actual
      user/group SIDs owning the process token
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("privileges")


@mcp.tool()
def windows_sessions() -> dict:
    """
    Run the sessions plugin to list processes grouped by their logon session,
    including session type and associated user name.

    Use this tool when the user asks about:
    - Who was logged into the system at the time of capture
    - Which user session a process belongs to
    - Remote Desktop (RDP) or console sessions
    - Active logon sessions and their associated processes
    - Session types (Console, Services, RDP-Tcp)

    Returns a dict with:
    - "plugin": "sessions"
    - "results": list of dicts, each containing:
        "Session ID": terminal session ID (int),
        "Session Type": session type such as Console or Services (str),
        "Process ID": process ID (int),
        "Process": process name (str),
        "User Name": domain\\username of the session owner (str),
        "Create Time": process creation timestamp (str)

    Forensic context:
    - Multiple active RDP-Tcp sessions may indicate lateral movement or
      unauthorized remote access
    - Processes in Session 0 (Services) are system-level; user processes
      typically appear in Session 1+
    - Compare user names across sessions to detect compromised accounts or
      unauthorized logon activity
    - Use windows_pslist for full process details and windows_envars to
      extract USERNAME/COMPUTERNAME for each session context
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("sessions")


@mcp.tool()
def windows_thrdscan() -> dict:
    """
    Run the thrdscan plugin to scan for thread objects in physical memory
    using pool tag scanning.

    Use this tool when the user asks about:
    - Threads running on the system or within a specific process
    - Thread start addresses or entry points
    - Hidden or orphaned threads not linked to any process
    - Thread creation and exit timestamps
    - Thread injection or suspicious thread activity

    Returns a dict with:
    - "plugin": "thrdscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the ETHREAD structure (str, hex),
        "PID": owning process ID (int),
        "TID": thread ID (int),
        "StartAddress": thread start address (str, hex),
        "StartPath": module path containing the start address (str),
        "Win32StartAddress": Win32 thread start address (str, hex),
        "Win32StartPath": module path containing the Win32 start address (str),
        "CreateTime": thread creation timestamp (str),
        "ExitTime": thread exit timestamp (str or None)

    Forensic context:
    - Threads with start addresses outside any known module range may
      indicate injected code (remote thread injection via CreateRemoteThread)
    - Orphaned threads (PID referencing a non-existent process) suggest the
      parent process was terminated or unlinked
    - Compare thread start addresses against windows_dlllist module ranges
      to identify threads executing from injected or unmapped memory
    - Use windows_pslist to resolve PID to process name for context
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("thrdscan")


@mcp.tool()
def windows_threads() -> dict:
    """
    Run the threads plugin to enumerate process threads by walking each
    process's ThreadListHead linked list (the canonical active-thread view).

    Use this tool when the user asks about:
    - Which threads belong to a running process
    - Per-process thread enumeration or thread ownership
    - Active threads (as opposed to pool-scanned terminated threads)
    - Thread start addresses or entry points for live processes
    - Investigating a specific process's threads after spotting it in pslist

    Returns a dict with:
    - "plugin": "threads"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the ETHREAD structure (str, hex),
        "PID": owning process ID (int),
        "TID": thread ID (int),
        "StartAddress": thread start address (str, hex),
        "StartPath": module path containing the start address (str or None),
        "Win32StartAddress": Win32 thread start address (str, hex),
        "Win32StartPath": module path containing the Win32 start address
          (str or None),
        "CreateTime": thread creation timestamp (str),
        "ExitTime": thread exit timestamp (str or None)

    Forensic context:
    - Unlike windows_thrdscan (pool-tag scan that can surface terminated or
      unlinked threads), this plugin walks active thread lists, so results
      only reflect currently linked threads — compare the two to spot
      hidden/unlinked threads (presence in thrdscan but not threads)
    - Win32StartAddress pointing outside any legitimate module
      (Win32StartPath is None) is a classic indicator of remote thread
      injection (CreateRemoteThread / NtCreateThreadEx payloads)
    - Use the PID column to resolve to a process name via windows_pslist and
      its command line via windows_cmdline for fuller context
    - Cross-reference with windows_malware_malfind to correlate suspicious threads
      with injected memory regions in the same PID
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("threads")


@mcp.tool()
def windows_orphan_kernel_threads() -> dict:
    """
    Run the orphan_kernel_threads plugin to detect kernel threads whose
    start address does not map to any loaded kernel module.

    Use this tool when the user asks about:
    - Rootkits, kernel-mode malware, or kernel implants
    - Kernel threads with no owning driver or module
    - Hidden kernel execution or unlinked kernel code
    - Suspicious activity inside the System process (PID 4)
    - Threads running from non-module kernel memory

    Returns a dict with:
    - "plugin": "orphan_kernel_threads"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the ETHREAD structure (str, hex),
        "PID": owning process ID, typically 4 (System) or a child kernel
          process such as MemCompression / Registry (int),
        "TID": thread ID (int),
        "StartAddress": kernel thread start address that does not resolve
          to any module (str, hex),
        "StartPath": module path — always None for orphans by definition,
        "Win32StartAddress": Win32 start address (str, hex),
        "Win32StartPath": Win32 module path (str or None),
        "CreateTime": thread creation timestamp (str),
        "ExitTime": thread exit timestamp (str or None)

    Forensic context:
    - Any non-empty result is high-signal: a kernel thread executing outside
      every loaded module is a strong rootkit indicator (e.g., manually
      mapped driver, DKOM-hidden module, shellcode injected into kernel
      memory pools)
    - The plugin filters aggressively (skips terminated/smeared threads and
      userland pointers) so findings are unlikely to be noise — investigate
      each result
    - Resolve the StartAddress against windows_modules and windows_modscan:
      presence in modscan but absence in modules suggests an unlinked module
      that owns the orphan thread
    - Correlate with windows_ssdt and windows_callbacks to find additional
      rootkit hooks tied to the same suspect memory region
    - Use windows_poolscanner to look for orphan kernel objects near the
      thread's start address
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("orphan_kernel_threads")


@mcp.tool()
def windows_suspended_threads() -> dict:
    """
    Run the suspended_threads plugin to find userland threads whose
    SuspendCount is greater than zero and were never resumed.

    Use this tool when the user asks about:
    - Process hollowing, process doppelgänging, or EDR evasion indicators
    - Threads left in a suspended state (never resumed)
    - Signs of thread injection paused before execution
    - Anomalies relating to CreateProcess with CREATE_SUSPENDED
    - Detection of techniques described in the Volexity DEF CON 2024 paper

    Returns a dict with:
    - "plugin": "suspended_threads"
    - "results": list of dicts, each containing:
        "Process": owning process image name (str),
        "PID": process ID (int),
        "TID": thread ID (int),
        "StartFile": file path containing the thread start address
          (str or None),
        "StartSymbol": symbol at the thread start address (str or None),
        "StartAddress": thread start address (str, hex),
        "Win32StartFile": file path containing the Win32 start address
          (str or None),
        "Win32StartSymbol": symbol at the Win32 start address (str or None),
        "Win32StartAddress": Win32 thread start address (str, hex)

    Forensic context:
    - Legitimate code routinely creates threads suspended then resumes them;
      this plugin surfaces only threads still suspended at acquisition time,
      which is unusual and correlates strongly with hollowing / evasion
    - Suspended threads whose StartFile or Win32StartFile is None (start
      address outside any mapped module) indicate code running from an
      injected memory region — pair with windows_malware_malfind to confirm
    - The process hollowing pattern pairs a suspended main thread with an
      overwritten image base; correlate this plugin with windows_pslist
      and windows_dlllist to see whether the process's backing image has
      been swapped
    - If the suspended thread's PID also appears in windows_malware_malfind or its
      Win32StartAddress points into a VAD with RWX protection, escalate —
      this is a classic hollowing signature
    - `WorkFoldersShell.dll` is filtered out by the plugin as a known false
      positive, so any result here is after de-noising
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("suspended_threads")


@mcp.tool()
def windows_malware_malfind() -> dict:
    """
    Run the malfind plugin to detect process memory regions that potentially
    contain injected code, based on VAD permissions and content heuristics.

    Use this tool when the user asks about:
    - Code injection or process injection detection
    - Suspicious executable memory regions in a process
    - Injected DLLs, shellcode, or reflective loading
    - Memory-resident malware or fileless malware indicators
    - Processes with anomalous memory protection flags (RWX)

    Returns a dict with:
    - "plugin": "malfind"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Start VPN": start virtual page number (str, hex),
        "End VPN": end virtual page number (str, hex),
        "Tag": VAD pool tag (str),
        "Protection": memory protection flags such as PAGE_EXECUTE_READWRITE (str),
        "CommitCharge": number of committed pages (int),
        "PrivateMemory": whether memory is private (int),
        "File output": file dump status (str),
        "Notes": detection notes (str),
        "Hexdump": compact hex string of the region header bytes (str),
        "Disasm": the same region header bytes, also as a compact hex
          string (str; not an actual disassembly listing despite the
          volatility3 column name — this server doesn't invoke capstone)

    Forensic context:
    - PAGE_EXECUTE_READWRITE regions not backed by a file are the primary
      indicator of injected code (shellcode, reflective DLL loading)
    - The Hexdump/Disasm bytes allow quick triage: look for an `4d5a`
      (MZ) prefix (injected PE) or common shellcode patterns (e.g. long
      `90` runs for a NOP sled)
    - Use windows_pslist to identify the affected process, then windows_dlllist
      to check if the region overlaps with any legitimate loaded module
    - Cross-reference with windows_handles to find related file or section
      objects that may reveal the injection source
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.malfind")


@mcp.tool()
def windows_vadinfo() -> dict:
    """
    Run the vadinfo plugin to list detailed Virtual Address Descriptor (VAD)
    information for each process, including memory-mapped files.

    Use this tool when the user asks about:
    - Virtual memory layout or address space of a process
    - Memory-mapped files or sections loaded by a process
    - VAD tree entries, memory protection, or commit charge
    - Which files are mapped into a process's address space
    - Detailed memory region metadata beyond what malfind shows

    Returns a dict with:
    - "plugin": "vadinfo"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Offset": VAD node offset (str, hex),
        "Start VPN": start virtual page number (str, hex),
        "End VPN": end virtual page number (str, hex),
        "Tag": VAD pool tag (str),
        "Protection": memory protection flags (str),
        "CommitCharge": number of committed pages (int),
        "PrivateMemory": whether memory is private (int),
        "Parent": parent VAD node offset (str, hex),
        "File": path of the memory-mapped file if any (str),
        "File output": file dump status (str)

    Forensic context:
    - The File field reveals DLLs and executables mapped into memory that
      may not appear in windows_dlllist (e.g., manually mapped images)
    - Compare VAD protection flags with expected values: legitimate code
      sections are typically PAGE_EXECUTE_READ, not PAGE_EXECUTE_READWRITE
    - Use windows_malware_malfind for focused detection of injected regions; use
      this tool for comprehensive VAD enumeration
    - Cross-reference with windows_handles (Type=Section) to identify
      shared memory mappings between processes
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("vadinfo")


@mcp.tool()
def windows_vadwalk() -> dict:
    """
    Run the vadwalk plugin to walk the VAD tree and display the binary tree
    structure of virtual address descriptors for each process.

    Use this tool when the user asks about:
    - VAD tree structure or binary tree layout
    - Parent, left, and right child relationships between VAD nodes
    - Low-level virtual memory organization of a process
    - VAD node addresses and their start/end ranges
    - Debugging memory layout or verifying VAD tree integrity

    Returns a dict with:
    - "plugin": "vadwalk"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Offset": VAD node offset (str, hex),
        "Parent": parent VAD node offset (str, hex),
        "Left": left child VAD node offset (str, hex),
        "Right": right child VAD node offset (str, hex),
        "Start": start address of the region (str, hex),
        "End": end address of the region (str, hex),
        "Tag": VAD pool tag (str)

    Forensic context:
    - A corrupted VAD tree (broken parent/child links) may indicate kernel
      exploitation or memory corruption attacks
    - Use windows_vadinfo for richer metadata (protection, mapped files)
      per VAD entry; this tool focuses on the tree structure itself
    - Compare VAD node counts between windows_vadwalk and windows_vadinfo
      to detect inconsistencies that could signal manipulation
    - Use windows_malware_malfind for targeted detection of suspicious regions
      rather than walking the entire tree
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("vadwalk")


@mcp.tool()
def windows_memmap() -> dict:
    """
    Run the memmap plugin to display the virtual-to-physical memory mapping
    for a process, showing how virtual addresses translate to physical offsets.

    Use this tool when the user asks about:
    - Virtual to physical address translation for a process
    - Memory map or physical memory layout of a process
    - Which physical pages back a process's virtual address space
    - Dumping process memory based on physical offsets
    - Memory page sizes and their file offsets in the image

    Returns a dict with:
    - "plugin": "memmap"
    - "results": list of dicts, each containing:
        "Virtual": virtual address (str, hex),
        "Physical": physical address in the memory image (str, hex),
        "Size": size of the mapping in bytes (str, hex),
        "Offset in File": offset within the memory image file (str, hex),
        "File output": file dump status (str)

    Forensic context:
    - Physical addresses can be used to locate data directly in the raw
      memory image file for manual hex analysis or carving
    - Large contiguous mappings may indicate memory-mapped files or large
      allocations worth investigating
    - Use windows_vadinfo for higher-level memory region metadata (protection,
      mapped files) rather than raw page-level mappings
    - This tool produces large result sets; use it for targeted investigation
      of specific processes identified through windows_pslist
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("memmap")


@mcp.tool()
def windows_virtmap() -> dict:
    """
    Run the virtmap plugin to list virtual mapped sections of the kernel
    address space, showing how major kernel regions are laid out.

    Use this tool when the user asks about:
    - Kernel virtual address space layout
    - Mapped kernel regions and their address ranges
    - System address space organization (HAL, kernel, drivers, etc.)
    - Kernel memory boundaries or region sizes
    - Overview of how the OS organizes its virtual memory

    Returns a dict with:
    - "plugin": "virtmap"
    - "results": list of dicts, each containing:
        "Region": name or description of the mapped region (str),
        "Start offset": start virtual address of the region (str, hex),
        "End offset": end virtual address of the region (str, hex)

    Forensic context:
    - Kernel regions outside expected address ranges may indicate rootkit
      modifications or kernel memory patching
    - Compare region boundaries with known Windows kernel layout to detect
      anomalous mappings injected by rootkits
    - Use windows_modules and windows_driverscan to correlate driver load
      addresses with the virtual map regions
    - This provides a system-level overview; use windows_vadinfo for
      per-process virtual memory details
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("virtmap")


@mcp.tool()
def windows_strings(strings_file: str = "") -> dict:
    """
    Run the strings plugin to map output from an external strings-plus-
    offsets file to the process that owns each string's physical memory
    location.

    Use this tool when the user asks about:
    - Which process owns a specific string found in memory
    - Mapping strings output to processes
    - Searching for URLs, IP addresses, or keywords in process memory
    - Attributing strings from a raw memory dump to specific processes
    - Correlating extracted strings with process activity

    Arguments:
    - strings_file (required, despite the default): absolute path to a
      pre-generated file of "offset:string" lines covering the image,
      e.g. from `strings -a -t d <image> > strings.txt` (GNU strings)
      or any tool producing that format. This is a hard requirement of
      the underlying volatility3 plugin, not an optional refinement —
      without it, this tool returns an empty result with an "error"
      key explaining what's needed, rather than crashing.

    Returns a dict with:
    - "plugin": "strings"
    - "results": list of dicts, each containing:
        "String": the extracted string content (str),
        "Physical Address": physical address where the string was found (str, hex),
        "Result": process(es) that map this physical address (str)
    - "error" (only present when strings_file was omitted or the plugin
      rejected it): a human-readable explanation

    Forensic context:
    - Strings attributed to unexpected processes (e.g., C2 URLs in a
      system process) are strong indicators of compromise
    - Use windows_pslist to resolve process names from the Result field
    - Cross-reference suspicious strings with windows_netscan to confirm
      network-related IOCs (IP addresses, domains, URLs)
    - windows_vadregexscan/windows_vadyarascan cover a similar "search
      process memory" use case without needing an external strings file
      first — prefer those when the user hasn't already generated one
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("strings", strings_file=strings_file)


@mcp.tool()
def windows_shimcachemem() -> dict:
    """
    Run the shimcachemem plugin to recover the Application Compatibility
    Cache (Shimcache / AppCompatCache) from live kernel memory.

    Use this tool when the user asks about:
    - Evidence of past program execution (what EXEs ran on this system)
    - Shimcache, AppCompatCache, or Application Compatibility entries
    - Program execution history beyond what pslist shows (historical)
    - Investigator questions like "did foo.exe ever run here?"
    - Timeline reconstruction of program activity

    Returns a dict with:
    - "plugin": "shimcachemem"
    - "results": list of dicts, each containing:
        "Order": ordinal position in the cache, newest first (int),
        "Last Modified": file last-modified timestamp as recorded by the
          cache (str, UTC),
        "Last Update": cache-entry last-update timestamp (str, UTC; may
          be None depending on Windows build — only 32-bit Win8/8.1 record
          this column),
        "Exec Flag": whether Windows flagged the file as executed (bool;
          only meaningful on 32-bit Windows 7/8/8.1 — elsewhere the cache
          treats every entry as having been executed),
        "File Size": size of the file as recorded (str, hex),
        "File Path": full NT path of the executable (str)

    Forensic context:
    - Shimcache is recovered from kernel memory rather than from the
      hive on disk, so entries remain available even if the SYSTEM hive
      has not been flushed. It is a major evidence-of-execution source
      alongside windows_registry_amcache and windows_registry_userassist
    - Order=0 is the newest cache entry; walking from 0 downward reveals
      the most recently recorded programs
    - File Path entries that point to temp / user-writable directories
      (AppData, ProgramData, Public, Windows\\Temp) with unusual names are
      high-signal leads — correlate with windows_pslist (are they still
      running?) and windows_registry_amcache (SHA1 and install time)
    - Combine with windows_registry_userassist (interactive execution)
      and windows_registry_scheduled_tasks (scheduled execution) to
      distinguish the invocation vector
    - Shimcache captures execution even if the binary was later deleted,
      making it invaluable for post-incident triage
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("shimcachemem")


@mcp.tool()
def windows_vadregexscan(pattern: str, maxsize: int = 128) -> dict:
    """
    Run the vadregexscan plugin to search every process's virtual memory
    (all VADs) for a user-supplied regular expression. This is the first
    parameterized MCP tool in the server — Claude must supply a `pattern`.

    Use this tool when the user asks about:
    - Searching process memory for a specific string, URL, IP, or regex
    - Finding indicators of compromise (IOCs) hidden in user-mode memory
    - Locating configuration strings, keys, or tokens embedded in a process
    - Regex-based hunt across all running processes in one pass
    - Questions like "is the string foo anywhere in memory?" or
      "find any process memory containing /cmd.exe/"

    Arguments:
    - pattern (required): a regular expression (Python `re` syntax). The
      plugin interprets it as UTF-8 bytes internally, so typical ASCII /
      wide-char byte-level regexes work (e.g., `r"https?://[\\w.-]+"`,
      `r"\\\\Device\\\\"`, `r"BEGIN [A-Z ]+ KEY"`).
    - maxsize (optional, default 128): maximum number of bytes of
      surrounding context captured per match.

    Returns a dict with:
    - "plugin": "vadregexscan"
    - "results": list of dicts, each containing:
        "PID": process ID where the match was found (int),
        "Process": image name of that process (str),
        "Offset": virtual address of the match (str, hex),
        "Text": UTF-8 decoded match / context (str),
        "Hex": raw bytes of the match (str repr of the bytes object)

    Forensic context:
    - A high-value general-purpose hunt tool. Unlike windows_strings (which
      needs a pre-generated strings file), this scans live process memory
      directly with a regex
    - Good first probe for IOC hunts: paste in a URL, IP, domain, process
      name, or magic byte sequence and get back every process containing
      it, in one call
    - Large or loose patterns on a busy image can scan tens of GB of VAD
      space; prefer anchored or specific patterns. If the match count is
      huge, tighten the regex first
    - Use the PID column to pivot to windows_pslist for process context,
      windows_cmdline for arguments, and windows_malware_malfind to see
      whether the hit falls inside a suspicious VAD
    - Example hunt queries: `r"\\\\\\\\"` (UNC paths), `r"curl\\.exe"`
      (living-off-the-land), `r"-----BEGIN"` (crypto material leakage),
      `r"powershell\\s*-e"` (encoded PowerShell).
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("vadregexscan", pattern=pattern, maxsize=maxsize)


if "vadyarascan" in PLUGIN_MAP:

    @mcp.tool()
    def windows_vadyarascan(yara_rule: str, pid: int = 0) -> dict:
        """
        Run the vadyarascan plugin to scan every process's virtual memory
        (all VADs) with a Yara rule. Like windows_vadregexscan but for
        full Yara rule syntax (multiple patterns, conditions, wildcards,
        byte masks) instead of a single regex.

        Use this tool when the user asks about:
        - Scanning process memory with a Yara rule (malware signature,
          IOC, or custom detection logic)
        - Detecting known malware families by their memory signature
        - Applying a rule from a threat-intel feed against every running
          process at once
        - Anything windows_vadregexscan can't express — multi-pattern
          rules, byte wildcards, boolean conditions between patterns

        Requires the optional `full` extra (`uv sync --extra full`) — the
        plugin hard-fails to import without `yara-python` or `yara-x`.
        This tool is not registered at all without the extra.

        Arguments:
        - yara_rule (required): inline Yara rule text, or a bare
          string/hex pattern (volatility3 wraps a bare pattern into a
          minimal rule automatically)
        - pid (optional, default 0 = all processes): restrict the scan
          to a single process ID

        Returns a dict with:
        - "plugin": "vadyarascan"
        - "results": list of dicts, one per match, each containing:
            "Offset": virtual address of the match (str, hex),
            "PID": process ID where the match was found (int),
            "CreateTime": process creation timestamp (str),
            "PPID": parent process ID (int),
            "ImageFileName": image name of that process (str),
            "SessionId": session ID the process belongs to (int),
            "Threads": number of active threads in the process (int),
            "Rule": name of the Yara rule that matched (str),
            "Component": named string within the rule that matched (str),
            "Value": the matched bytes themselves, as a compact hex
              string (capped and truncated for very large matches)

        Forensic context:
        - Prefer windows_vadregexscan for a quick single-pattern hunt;
          reach for this tool when the pattern needs Yara-specific
          features (multiple named strings, `and`/`or` conditions,
          wildcarded byte sequences)
        - A large or loose rule on a busy image can scan tens of GB of
          VAD space; scope with `pid` when investigating a specific
          process
        - Use the PID column to pivot to windows_pslist for process
          context and windows_malware_malfind to see whether the match
          falls inside a suspicious VAD
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("vadyarascan", yara_rule=yara_rule, pid=pid)


@mcp.tool()
def windows_dlllist() -> dict:
    """
    Run the dlllist plugin to list DLLs and loaded modules for each process
    from the PEB (Process Environment Block) loader data.

    Use this tool when the user asks about:
    - DLLs or shared libraries loaded by a process
    - What modules a process has loaded into memory
    - Suspicious or unexpected DLLs in a process
    - DLL load order, base addresses, or file paths
    - DLL hijacking or side-loading indicators

    Returns a dict with:
    - "plugin": "dlllist"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Base": base address of the loaded module (str, hex),
        "Size": size of the module in memory (str, hex),
        "Name": module file name (str),
        "Path": full path of the loaded module (str),
        "LoadCount": reference count for the module (int),
        "LoadTime": time the module was loaded (str),
        "File output": file dump status (str)

    Forensic context:
    - DLLs loaded from unusual paths (e.g., temp directories, user profile)
      are suspicious and may indicate DLL hijacking or malware staging
    - Compare with windows_malware_ldrmodules to detect discrepancies; modules
      missing from one loader list but present in another suggest unlinking
    - Use windows_malware_malfind to check if any loaded module regions have been
      modified in memory (code patching / hooking)
    - Cross-reference with windows_cmdline to verify that loaded DLLs match
      the expected behavior of each process
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("dlllist")


@mcp.tool()
def windows_malware_ldrmodules() -> dict:
    """
    Run the ldrmodules plugin to cross-reference modules across the three
    PEB loader lists (InLoad, InInit, InMem) to detect unlinked DLLs.

    Use this tool when the user asks about:
    - Hidden or unlinked DLLs in a process
    - DLL loader list discrepancies or inconsistencies
    - Stealthy DLL injection that removes entries from loader lists
    - Whether all loaded modules appear in all three PEB lists
    - Rootkit or malware hiding techniques at the module level

    Returns a dict with:
    - "plugin": "ldrmodules"
    - "results": list of dicts, each containing:
        "Pid": process ID (int),
        "Process": process name (str),
        "Base": base address of the module (str, hex),
        "InLoad": present in InLoadOrderModuleList (bool),
        "InInit": present in InInitializationOrderModuleList (bool),
        "InMem": present in InMemoryOrderModuleList (bool),
        "MappedPath": file path from the VAD (str)

    Forensic context:
    - A module with False in any of InLoad/InInit/InMem has been unlinked
      from that loader list, which is a classic DLL hiding technique
    - Legitimate modules should appear in all three lists; any discrepancy
      warrants investigation
    - Compare with windows_dlllist which only reads InLoadOrderModuleList;
      this tool provides a more complete view
    - Use windows_malware_malfind to check if the unlinked module's memory region
      contains injected or modified code
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.ldrmodules")


@mcp.tool()
def windows_modules() -> dict:
    """
    Run the modules plugin to list kernel modules loaded via the
    PsLoadedModuleList, showing drivers and kernel extensions.

    Use this tool when the user asks about:
    - Loaded kernel drivers or kernel modules
    - Which drivers are loaded on the system
    - Driver base addresses, sizes, or file paths
    - Kernel-level rootkit detection via suspicious drivers
    - System driver inventory

    Returns a dict with:
    - "plugin": "modules"
    - "results": list of dicts, each containing:
        "Offset": module list entry offset (str, hex),
        "Base": base address of the kernel module (str, hex),
        "Size": size of the module in memory (str, hex),
        "Name": module file name (str),
        "Path": full path of the kernel module (str),
        "File output": file dump status (str)

    Forensic context:
    - Kernel modules loaded from non-standard paths (outside
      \\SystemRoot\\system32\\drivers\\) may indicate rootkit drivers
    - Compare with windows_modscan to detect hidden kernel modules that
      have been unlinked from the loaded module list
    - Use windows_driverscan to correlate driver objects with loaded modules
    - Cross-reference module base addresses with windows_ssdt to identify
      which module handles each system call
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("modules")


@mcp.tool()
def windows_modscan() -> dict:
    """
    Run the modscan plugin to scan for kernel modules by pool tag in physical
    memory, independent of the OS-maintained module list.

    Use this tool when the user asks about:
    - Hidden or unlinked kernel modules or drivers
    - Kernel rootkit detection via module hiding
    - Drivers that may have been removed from the loaded module list
    - A more thorough kernel module scan than the standard list
    - Previously loaded and unloaded kernel modules

    Returns a dict with:
    - "plugin": "modscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the module entry (str, hex),
        "Base": base address of the kernel module (str, hex),
        "Size": size of the module in memory (str, hex),
        "Name": module file name (str),
        "Path": full path of the kernel module (str),
        "File output": file dump status (str)

    Forensic context:
    - Compare with windows_modules: a module found here but missing from
      windows_modules was unlinked from the loaded module list, indicating
      a kernel rootkit hiding its driver
    - Unloaded drivers still leave pool tag artifacts, so this tool can
      find drivers that were loaded temporarily and then removed
    - Use windows_driverscan to correlate driver objects with discovered
      modules for a complete driver analysis
    - Cross-reference suspicious module base addresses with windows_ssdt
      to detect system call hooking
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("modscan")


@mcp.tool()
def windows_verinfo() -> dict:
    """
    Run the verinfo plugin to extract PE version information from loaded
    modules, including version numbers for processes and kernel drivers.

    Use this tool when the user asks about:
    - Version information of loaded DLLs or executables
    - PE file version, product version, or build numbers
    - Whether a specific module is an expected version
    - Identifying outdated or patched binaries in memory
    - Verifying module authenticity via version metadata

    Returns a dict with:
    - "plugin": "verinfo"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Base": base address of the module (str, hex),
        "Name": module file name (str),
        "Major": major version number (int),
        "Minor": minor version number (int),
        "Product": product version number (int),
        "Build": build number (int)

    Forensic context:
    - Mismatched version numbers for system DLLs (e.g., ntdll.dll with an
      unexpected version) may indicate binary patching or trojanized files
    - Compare version info against known-good baselines for the OS version
      identified by windows_info
    - Use windows_dlllist to get the full path of modules, then this tool
      to verify their version metadata
    - Modules with zeroed or absent version info may be custom-compiled
      malware or debug builds
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("verinfo")


@mcp.tool()
def windows_iat() -> dict:
    """
    Run the iat plugin to extract the Import Address Table (IAT) from loaded
    modules, listing API functions imported from external libraries.

    Use this tool when the user asks about:
    - API functions imported by a process or module
    - Import Address Table entries or imported DLL functions
    - What Windows API calls a process is set up to use
    - IAT hooking detection (function addresses pointing outside the library)
    - Behavioral analysis based on imported functions

    Returns a dict with:
    - "plugin": "iat"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Name": module name that imports the function (str),
        "Library": library providing the imported function (str),
        "Bound": whether the import is bound (bool),
        "Function": imported function name (str),
        "Address": resolved function address (str, hex)

    Forensic context:
    - Suspicious imports like VirtualAllocEx, WriteProcessMemory,
      CreateRemoteThread indicate process injection capability
    - IAT hooking: if the Address field points outside the expected Library
      module range, the import has been redirected (API hooking)
    - Use windows_dlllist to verify the base address range of each Library,
      then compare with the resolved Address to detect hooks
    - Cross-reference imported functions with windows_malware_malfind results to
      understand what capabilities injected code may leverage
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("iat")


@mcp.tool()
def windows_pe_symbols(
    source: str,
    module: str,
    symbols: str = "",
    addresses: str = "",
) -> dict:
    """
    Run the pe_symbols plugin to resolve PE symbol names to addresses (or
    addresses back to names) for a given loaded module, using PDB data
    downloaded for that image.

    Use this tool when the user asks about:
    - What function lives at a given address inside ntoskrnl / ntdll / ...
    - The address of a specific Windows API inside a loaded library
    - Resolving a suspicious thread start address to a function name
    - Dumping all exported / internal symbols of a particular module
    - Verifying whether an address falls inside a legitimate function

    Arguments:
    - source (required): "kernel" to resolve inside the Windows kernel
      module, or "processes" to resolve inside a loaded user-mode module.
    - module (required): module filename. Examples: "ntoskrnl.exe" for
      the kernel, "ntdll.dll" / "kernel32.dll" for common userland
      libraries.
    - symbols (optional): comma-separated symbol names to resolve into
      addresses (e.g., "NtCreateFile,NtOpenProcess"). When provided,
      results only contain matches for these symbols.
    - addresses (optional): comma-separated hex or decimal addresses to
      resolve into symbol names (e.g., "0x14012a0a0,0x14012b100").
    - One of ``symbols`` or ``addresses`` is effectively required: if
      both are left empty the underlying plugin logs "--address or
      --symbol must be specified" and returns zero rows rather than
      dumping every symbol in the module.

    Returns a dict with:
    - "plugin": "pe_symbols"
    - "results": list of dicts, each containing:
        "Module": module name the symbol belongs to (str),
        "Symbol": symbol name (str),
        "Address": resolved virtual address (str, hex)

    Forensic context:
    - Requires PDB download to succeed on the server (volatility3's symbol
      auto-download mechanism); failures usually mean no internet access
      at startup time
    - Key pivot for suspicious thread analysis: take Win32StartAddress
      from windows_threads / windows_orphan_kernel_threads and call
      this tool with that value to obtain the function name
    - Useful for IAT-hooking detection alongside windows_iat: resolve
      the expected function address here, compare against the imported
      entry's current address
    - Kernel-mode hunts (source="kernel", module="ntoskrnl.exe") are
      the go-to for understanding callbacks, SSDT entries, or rootkit
      hook targets reported by windows_ssdt / windows_callbacks
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin(
        "pe_symbols",
        source=source,
        module=module,
        symbols=symbols,
        addresses=addresses,
    )


@mcp.tool()
def windows_pedump(base: int, pid: int = 0, kernel_module: bool = False) -> dict:
    """
    Run the pedump plugin to reconstruct a PE image from memory at a
    specified base address and write the resulting .exe / .dll / .sys
    bytes into the directory configured via ``VOL_DUMP_DIR``.

    Use this tool when the user asks about:
    - Extracting a specific executable or DLL from a live process
    - Dumping a suspicious module / driver as a .exe / .dll / .sys file
    - Reconstructing an injected PE for static analysis in IDA, Ghidra,
      or other PE tooling
    - Recovering a hollowed / masqueraded image that no longer exists on
      disk
    - Pulling a kernel driver by base address (pass kernel_module=True)

    Arguments:
    - base (required): virtual base address of the target PE (int). For
      userland modules, the base appears in windows_dlllist as
      "Base"; for kernel drivers, it appears in windows_modules.
    - pid (optional, default 0): if non-zero, restrict search to this
      process. Ignored when kernel_module=True.
    - kernel_module (optional, default False): set True to dump a kernel
      mode PE (driver) instead of a userland image.

    Returns a dict with:
    - "plugin": "pedump"
    - "results": list of dicts, each containing:
        "PID": owning process ID (or 4 / System for kernel modules) (int),
        "Process": image name of the owning process (str),
        "File output": final on-disk path of the reconstructed PE or an
          error string if reconstruction failed

    Forensic context:
    - Requires VOL_DUMP_DIR to be configured; otherwise raises a clear
      error so Claude can prompt the user to set it
    - Typical workflow:
        1. windows_malware_malfind surfaces a suspicious VAD at base B
           inside PID P
        2. windows_pedump(base=B, pid=P) recovers the hollowed / injected
           PE to disk
        3. User runs IDA / Ghidra / YARA on the dumped bytes
    - For hidden rootkit drivers: compare windows_modscan (pool scan)
      against windows_modules (linked list) to find unlinked driver
      bases, then pedump each unlinked base with kernel_module=True
    - Dumped PEs are reconstructed from live memory pages, so section
      alignment and unmapped pages may leave zero-filled regions — this
      is expected and still useful for static analysis
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin(
        "pedump",
        base=base,
        pid=pid,
        kernel_module=kernel_module,
    )


@mcp.tool()
def windows_callbacks() -> dict:
    """
    Run the callbacks plugin to list kernel callbacks and notification
    routines registered in the Windows kernel.

    Use this tool when the user asks about:
    - Kernel callbacks or notification routines
    - Process/thread/image load notification hooks
    - Registry change callbacks or filesystem filter callbacks
    - Rootkit detection via callback table manipulation
    - What code runs in response to kernel events

    Returns a dict with:
    - "plugin": "callbacks"
    - "results": list of dicts, each containing:
        "Type": callback type such as CreateProcess, CreateThread, LoadImage (str),
        "Callback": address of the callback function (str, hex),
        "Module": module that owns the callback (str),
        "Symbol": resolved symbol name if available (str),
        "Detail": additional details about the callback (str)

    Forensic context:
    - Callbacks pointing to unknown or suspicious modules indicate rootkit
      hooks that intercept kernel events (process creation, image loading)
    - Compare the Module field against windows_modules to verify the callback
      belongs to a legitimate loaded driver
    - CreateProcess and LoadImage callbacks are commonly abused by rootkits
      to inject code into new processes or intercept DLL loading
    - Use windows_driverscan to identify the driver object associated with
      the module hosting the callback
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("callbacks")


@mcp.tool()
def windows_devicetree() -> dict:
    """
    Run the devicetree plugin to list the device tree showing relationships
    between drivers and their attached device objects.

    Use this tool when the user asks about:
    - Device objects and their associated drivers
    - Driver-device attachment chains or device stacks
    - Which drivers handle specific device types
    - Filter drivers or device layering in the I/O stack
    - Rootkit detection via rogue device attachments

    Returns a dict with:
    - "plugin": "devicetree"
    - "results": list of dicts, each containing:
        "Offset": device or driver object offset (str, hex),
        "Type": object type, either Driver or Device (str),
        "DriverName": name of the owning driver (str),
        "DeviceName": name of the device object (str),
        "DriverNameOfAttDevice": driver of the attached device (str),
        "DeviceType": device type classification (str)

    Forensic context:
    - Unexpected devices attached to legitimate driver stacks may indicate
      filter driver rootkits intercepting I/O operations
    - Compare driver names against windows_modules and windows_driverscan
      to verify all device-owning drivers are legitimate
    - Filesystem filter drivers (attached to \\FileSystem\\) are commonly
      used by rootkits to hide files from directory listings
    - Use windows_driverirp to examine the IRP handlers of suspicious
      drivers found in the device tree
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("devicetree")


@mcp.tool()
def windows_driverirp() -> dict:
    """
    Run the driverirp plugin to list IRP (I/O Request Packet) major function
    handlers for each driver, showing which code handles each I/O operation.

    Use this tool when the user asks about:
    - IRP handlers or I/O dispatch routines for drivers
    - Which function handles read, write, or device control for a driver
    - IRP hooking or driver dispatch table manipulation
    - Rootkit detection via tampered IRP handlers
    - Driver behavior analysis through its dispatch table

    Returns a dict with:
    - "plugin": "driverirp"
    - "results": list of dicts, each containing:
        "Offset": driver object offset (str, hex),
        "Driver Name": name of the driver (str),
        "IRP": IRP major function name such as IRP_MJ_CREATE (str),
        "Address": address of the handler function (str, hex),
        "Module": module containing the handler (str),
        "Symbol": resolved symbol name if available (str)

    Forensic context:
    - IRP handlers pointing outside the owning driver's module range indicate
      IRP hooking, a common rootkit technique to intercept I/O operations
    - Compare the Module field with the Driver Name: mismatches suggest a
      different module has hooked the driver's dispatch table
    - Use windows_modules to verify the expected address range for each
      driver module and detect out-of-range handler addresses
    - Cross-reference with windows_devicetree to understand the full I/O
      stack and identify which drivers are layered together
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("driverirp")


@mcp.tool()
def windows_malware_drivermodule() -> dict:
    """
    Run the drivermodule plugin to detect drivers that are not backed by
    a loaded kernel module, indicating potentially hidden rootkit drivers.

    Use this tool when the user asks about:
    - Hidden or orphaned driver modules
    - Drivers without a corresponding loaded kernel module
    - Rootkit driver detection or driver integrity checks
    - Whether all active drivers map to legitimate modules
    - Drivers that may have been loaded and then hidden

    Returns a dict with:
    - "plugin": "drivermodule"
    - "results": list of dicts, each containing:
        "Offset": driver object offset (str, hex),
        "Known Exception": whether this is a known benign exception (bool),
        "Driver Name": name of the driver (str),
        "Service Key": registry service key for the driver (str),
        "Alternative Name": alternative module name if found (str)

    Forensic context:
    - Drivers with no matching module in windows_modules and Known Exception
      set to False are strong rootkit indicators
    - Known Exception=True entries are legitimate drivers that are expected
      to appear without a backing module (e.g., certain Microsoft drivers)
    - Use windows_driverscan to get the full driver object details for any
      suspicious entries discovered here
    - Cross-reference with windows_callbacks and windows_ssdt to determine
      if the hidden driver has hooked any kernel functions
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.drivermodule")


@mcp.tool()
def windows_driverscan() -> dict:
    """
    Run the driverscan plugin to scan for driver objects in physical memory
    using pool tag scanning.

    Use this tool when the user asks about:
    - Driver objects loaded on the system
    - Scanning for all drivers including potentially hidden ones
    - Driver start addresses, sizes, or service key names
    - Comprehensive driver inventory from physical memory
    - Comparing against the loaded module list for discrepancies

    Returns a dict with:
    - "plugin": "driverscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the driver object (str, hex),
        "Start": driver entry point address (str, hex),
        "Size": driver size in memory (str, hex),
        "Service Key": registry service key name (str),
        "Driver Name": driver object name (str),
        "Name": short name of the driver (str)

    Forensic context:
    - Drivers found here but missing from windows_modules may have been
      unlinked from the loaded module list (rootkit hiding technique)
    - Compare with windows_malware_drivermodule to identify drivers without a
      backing kernel module
    - Use windows_driverirp to examine the IRP dispatch table of any
      suspicious drivers discovered through this scan
    - Cross-reference Start addresses with windows_ssdt to determine if
      a driver provides any system call handlers
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("driverscan")


@mcp.tool()
def windows_poolscanner() -> dict:
    """
    Run the poolscanner plugin as a generic pool tag scanner that finds
    various kernel objects by their pool allocations.

    Use this tool when the user asks about:
    - Generic pool tag scanning across all object types
    - Kernel object discovery by pool tags
    - A comprehensive scan for all pool-allocated kernel objects
    - Low-level memory pool analysis
    - Identifying what kernel objects are allocated in pool memory

    Returns a dict with:
    - "plugin": "poolscanner"
    - "results": list of dicts, each containing:
        "Tag": four-character pool tag (str),
        "Offset": offset of the pool allocation (str, hex),
        "Layer": memory layer where the object was found (str),
        "Name": identified object type or name (str)

    Forensic context:
    - This is a low-level scanner; prefer specialized tools like
      windows_psscan, windows_driverscan, or windows_modscan for
      specific object types as they provide richer output
    - Useful for discovering object types not covered by other scanners
      or for validating results from specialized pool scanners
    - Unknown or suspicious pool tags may indicate custom kernel objects
      allocated by rootkits
    - Use windows_bigpools to focus specifically on large pool allocations
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("poolscanner")


@mcp.tool()
def windows_ssdt() -> dict:
    """
    Run the ssdt plugin to list the System Service Descriptor Table (SSDT),
    mapping system call indices to their handler addresses and modules.

    Use this tool when the user asks about:
    - System call table or SSDT entries
    - System call hooking or SSDT patching detection
    - Which module handles each system call (syscall)
    - Kernel-level API hooking indicators
    - System call dispatch table integrity

    Returns a dict with:
    - "plugin": "ssdt"
    - "results": list of dicts, each containing:
        "Index": system call index number (int),
        "Address": address of the system call handler (str, hex),
        "Module": module containing the handler (str),
        "Symbol": resolved symbol name such as NtCreateFile (str)

    Forensic context:
    - All SSDT entries should point to ntoskrnl.exe or win32k.sys; entries
      pointing to other modules indicate SSDT hooking by a rootkit
    - Compare Module values against windows_modules to verify the handler
      belongs to a legitimate kernel module
    - SSDT hooking was common in older rootkits (pre-PatchGuard); on 64-bit
      Windows with PatchGuard, SSDT hooks are rarer but still possible via
      PatchGuard bypass techniques
    - Use windows_callbacks for detecting notification-based hooks, which
      are more common on modern Windows than SSDT hooking
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("ssdt")


@mcp.tool()
def windows_netscan() -> dict:
    """
    Run the netscan plugin to find network connections and listening sockets
    by scanning physical memory for network-related pool tags.

    Use this tool when the user asks about:
    - Network connections or open sockets on the system
    - What IP addresses or ports a process was communicating with
    - Listening services or active TCP/UDP connections
    - Command and control (C2) communication indicators
    - Network activity at the time of memory capture

    Returns a dict with:
    - "plugin": "netscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the network object (str, hex),
        "Proto": protocol such as TCPv4, TCPv6, UDPv4, UDPv6 (str),
        "LocalAddr": local IP address (str),
        "LocalPort": local port number (int),
        "ForeignAddr": remote IP address (str),
        "ForeignPort": remote port number (int),
        "State": connection state such as ESTABLISHED, LISTENING, CLOSED (str),
        "PID": owning process ID (int),
        "Owner": owning process name (str),
        "Created": timestamp when the connection was created (str)

    Forensic context:
    - ESTABLISHED connections to external IPs from unexpected processes are
      strong C2 indicators; check the ForeignAddr against threat intelligence
    - LISTENING sockets on unusual ports may indicate backdoors or reverse
      shells waiting for attacker connections
    - Use windows_pslist to get full details on the owning PID, and
      windows_cmdline to see how the networking process was launched
    - Cross-reference with windows_strings to find URLs or domains that
      correlate with the observed network endpoints
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("netscan")


@mcp.tool()
def windows_netstat() -> dict:
    """
    Run the netstat plugin to list network connections by traversing kernel
    networking data structures (partition table walk).

    Use this tool when the user asks about:
    - Active network connections via OS kernel structures
    - A kernel-level view of network activity (complementary to netscan)
    - TCP/UDP connection state from the OS perspective
    - Verifying netscan results against kernel-maintained data
    - Network connections that may not appear in pool tag scans

    Returns a dict with:
    - "plugin": "netstat"
    - "results": list of dicts, each containing:
        "Offset": offset of the network object (str, hex),
        "Proto": protocol such as TCPv4, TCPv6, UDPv4, UDPv6 (str),
        "LocalAddr": local IP address (str),
        "LocalPort": local port number (int),
        "ForeignAddr": remote IP address (str),
        "ForeignPort": remote port number (int),
        "State": connection state such as ESTABLISHED, LISTENING, CLOSED (str),
        "PID": owning process ID (int),
        "Owner": owning process name (str),
        "Created": timestamp when the connection was created (str)

    Forensic context:
    - This plugin walks kernel structures rather than pool tags, so it may
      find connections that windows_netscan misses and vice versa
    - Compare results with windows_netscan: discrepancies may indicate
      network-level rootkit manipulation of kernel structures
    - Use windows_pslist to resolve PID to full process details for any
      suspicious connections
    - Cross-reference foreign addresses with windows_cmdline to identify
      which command initiated the network activity
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("netstat")


@mcp.tool()
def windows_filescan() -> dict:
    """
    Run the filescan plugin to scan for FILE_OBJECT structures in physical
    memory using pool tag scanning.

    Use this tool when the user asks about:
    - Files that were open or referenced on the system
    - Scanning for file objects in memory
    - What files were accessed, including deleted or closed files
    - File paths or file names present in the memory image
    - Evidence of specific files (malware, documents, logs)

    Returns a dict with:
    - "plugin": "filescan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the FILE_OBJECT (str, hex),
        "Name": full file path (str)

    Forensic context:
    - File objects persist in pool memory even after files are closed,
      providing evidence of files that were accessed before capture
    - Search results for known malware filenames, suspicious paths
      (e.g., temp directories, recycle bin), or sensitive documents
    - Use windows_handles (Type=File) to determine which processes
      currently hold open handles to specific files
    - Cross-reference file paths with windows_dlllist to identify
      DLLs loaded from unusual locations
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("filescan")


@mcp.tool()
def windows_dumpfiles(
    pid: int = 0,
    filter: str = "",
    filter_ignore_case: bool = False,
    virtaddr: int = 0,
    physaddr: int = 0,
) -> dict:
    """
    Run the dumpfiles plugin to recover cached file contents from memory
    and write the recovered bytes to the directory configured via the
    ``VOL_DUMP_DIR`` environment variable.

    Use this tool when the user asks about:
    - Extracting or recovering a specific file from the memory image
    - Dumping files opened by a specific process (pass the PID)
    - Recovering deleted or in-use files whose content is still cached
    - Pulling a configuration / document / PE from a suspicious process
    - Saving forensic evidence to disk for external analysis

    Arguments (all optional — pass ``0`` / ``""`` to leave unset; the
    defaults dump every file object volatility3 finds, which can be slow
    and produce many files):
    - pid: restrict to files opened by this process ID (int)
    - filter: regex applied to the recovered file's name (str)
    - filter_ignore_case: make ``filter`` case-insensitive (bool)
    - virtaddr: virtual address of a specific _FILE_OBJECT (int)
    - physaddr: physical address of a specific _FILE_OBJECT (int)

    Returns a dict with:
    - "plugin": "dumpfiles"
    - "results": list of dicts, each containing:
        "Cache": cache type such as SharedCacheMap or DataSectionObject (str),
        "FileObject": address of the _FILE_OBJECT (str, hex),
        "FileName": path of the cached file (str),
        "Result": final on-disk path of the dumped bytes or an error string

    Forensic context:
    - The server must be launched with ``VOL_DUMP_DIR`` set (see
      ``claude_desktop_config.json``); otherwise this tool raises a clear
      error. Dumped bytes land in that directory; filename collisions are
      resolved by appending ``-1``, ``-2``, ...
    - Prefer passing a ``pid`` or ``filter`` — a bare call can extract
      hundreds or thousands of cached files
    - Use windows_filescan first to pick targets by FILE_OBJECT address,
      then pass that value as ``virtaddr`` / ``physaddr`` for a precise dump
    - SharedCacheMap entries represent files actively cached by the OS;
      DataSectionObject entries are memory-mapped file sections (EXE/DLL)
    - Cross-reference with windows_handles to identify which process had
      the file open at the time of capture
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin(
        "dumpfiles",
        pid=pid,
        filter=filter,
        filter_ignore_case=filter_ignore_case,
        virtaddr=virtaddr,
        physaddr=physaddr,
    )


@mcp.tool()
def windows_mutantscan() -> dict:
    """
    Run the mutantscan plugin to scan for mutex (mutant) objects in physical
    memory using pool tag scanning.

    Use this tool when the user asks about:
    - Mutexes or named mutants on the system
    - Malware mutex indicators or unique mutex names
    - Synchronization objects used by processes
    - Whether a known malware mutex exists in memory
    - Named kernel objects used for inter-process signaling

    Returns a dict with:
    - "plugin": "mutantscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the mutant object (str, hex),
        "Name": name of the mutex (str)

    Forensic context:
    - Many malware families create uniquely named mutexes to prevent
      multiple instances; searching for known mutex names is a fast
      IOC check (e.g., "Global\\MicrosoftUpdateService" used by some RATs)
    - Use windows_handles (Type=Mutant) to determine which process owns
      each mutex, linking the mutex back to a specific process
    - Unnamed mutexes (empty Name field) are common and usually benign;
      focus investigation on named mutexes with suspicious patterns
    - Cross-reference mutex names with threat intelligence databases
      for known malware family indicators
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("mutantscan")


@mcp.tool()
def windows_symlinkscan() -> dict:
    """
    Run the symlinkscan plugin to scan for symbolic link objects in physical
    memory using pool tag scanning.

    Use this tool when the user asks about:
    - Symbolic links or object manager symlinks in the kernel
    - Device name mappings or drive letter assignments
    - How logical names (e.g., C:) map to physical device paths
    - Object namespace redirection or aliasing
    - Potential symlink-based attacks or manipulations

    Returns a dict with:
    - "plugin": "symlinkscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the symlink object (str, hex),
        "CreateTime": timestamp when the symlink was created (str),
        "From Name": source name of the symbolic link (str),
        "To Name": target path the symlink points to (str)

    Forensic context:
    - Drive letter mappings (e.g., \\GLOBAL??\\C: -> \\Device\\Harddisk0\\Partition1)
      reveal the disk and partition layout at the time of capture
    - Unusual symlinks redirecting system paths may indicate rootkit
      namespace manipulation to hide files or devices
    - Compare with windows_devicetree to correlate device names referenced
      in symlink targets with actual device objects
    - Use windows_filescan to cross-reference file paths that traverse
      symlinked directories
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("symlinkscan")


if "mftscan" in PLUGIN_MAP:

    @mcp.tool()
    def windows_mftscan() -> dict:
        """
        Run the mftscan plugin to recover raw $MFT FILE records directly
        from memory via Yara-based signature scanning (looks for the
        FILE0 / FILE* / BAAD headers), independent of any mounted
        filesystem.

        Use this tool when the user asks about:
        - Deleted, unlinked, or otherwise hidden file metadata not visible
          via windows_filescan
        - Original creation / modification / access timestamps for a file
          from before it was deleted or renamed
        - Anti-forensic timestomping detection ($STANDARD_INFORMATION vs
          $FILE_NAME timestamp mismatches)
        - Reconstructing filesystem activity when only a memory image
          (no disk image) is available

        Requires the optional `full` extra (`uv sync --extra full`) — the
        plugin reuses volatility3's Yara scanner internally with a fixed
        signature and hard-fails to import without `yara-python` or
        `yara-x`. This tool is not registered at all without the extra.

        Returns a dict with:
        - "plugin": "mftscan"
        - "results": list of dicts, typically two rows per MFT record
          found (one per attribute type), each containing:
            "Offset": physical offset of the attribute (str, hex),
            "Record Type": raw MFT signature — FILE0, FILE*, or BAAD (str),
            "Record Number": MFT record number (int),
            "Link Count": hard link count at capture time (int),
            "MFT Type": file/directory flag decoded from the MFT Flags
              field (str),
            "Permissions": FILE_NAME flag value, only set on FILE_NAME
              rows (str or null),
            "Attribute Type": "STANDARD_INFORMATION" or "FILE_NAME" (str),
            "Created", "Modified", "Updated", "Accessed": timestamps
              (str, ISO 8601),
            "Filename": recovered filename, only set on FILE_NAME rows
              (str or null)

        Forensic context:
        - A single logical file typically produces two rows (one per
          attribute type) with independent timestamp sets — comparing
          them is the classic timestomping detection technique, since
          tools that fake $STANDARD_INFORMATION rarely also fake
          $FILE_NAME
        - A "BAAD" record type signature indicates a corrupted / reused
          MFT entry slot — useful for locating recently deleted files
        - Complements windows_filescan (live FILE_OBJECTs only) by
          surfacing records for files no longer open or already deleted
        - Multiple FILE_NAME rows for the same Record Number often
          reflect a DOS 8.3 short name alongside the long name
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("mftscan")


if "mftscan.ads" in PLUGIN_MAP:

    @mcp.tool()
    def windows_mftscan_ads() -> dict:
        """
        Run the mftscan.ads plugin to recover Alternate Data Stream
        ($DATA attributes with a named stream) records from raw MFT
        entries, found by the same Yara-based signature scan as
        windows_mftscan.

        Use this tool when the user asks about:
        - Alternate Data Streams (ADS) used to hide data behind a
          normal-looking file (e.g. file.txt:hidden.exe)
        - NTFS ADS-based malware persistence or data exfiltration staging
        - Recovering small, resident ADS content directly from memory
        - Confirming whether a suspicious file had hidden streams
          attached

        Requires the optional `full` extra (same Yara dependency as
        windows_mftscan) — not registered without it.

        Returns a dict with:
        - "plugin": "mftscan.ads"
        - "results": list of dicts, one per ADS attribute found, each
          containing:
            "Offset": physical offset of the $DATA attribute (str, hex),
            "Record Type": raw MFT signature — FILE0, FILE*, or BAAD (str),
            "Record Number": MFT record number of the owning file (int),
            "MFT Type": attribute type name, e.g. DATA (str),
            "Filename": longest recovered name of the owning MFT record
              (str),
            "ADS Filename": name of the alternate stream itself (str),
            "Hexdump": raw stream content as a compact hex string, when
              resident in the MFT record — only populated for small
              (resident) streams; larger, non-resident streams return
              no content here

        Forensic context:
        - A non-empty "ADS Filename" alongside an ordinary-looking
          "Filename" is the key indicator: legitimate files rarely carry
          named streams outside a handful of OS-created ones (e.g.
          Zone.Identifier from downloads)
        - Zone.Identifier streams reveal a file's download provenance
          (URL, referrer, download zone) and are worth checking first
        - Works even when the owning file has been deleted, since it
          scans raw MFT records rather than a live filesystem
        - Cross-reference "Record Number" with windows_mftscan output for
          the file's own creation / modification timestamps
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("mftscan.ads")


if "mftscan.residentdata" in PLUGIN_MAP:

    @mcp.tool()
    def windows_mftscan_residentdata() -> dict:
        """
        Run the mftscan.residentdata plugin to recover small file
        contents stored resident inside the $MFT record itself, found by
        the same Yara-based signature scan as windows_mftscan.

        Use this tool when the user asks about:
        - Recovering the actual content of a small file directly from
          the MFT (NTFS stores file data inline in the MFT record when
          it's small enough to fit, instead of allocating separate
          clusters)
        - Content of deleted small files (config snippets, short
          scripts, tiny text files) that no longer have live $DATA
          clusters
        - A quick way to pull file bytes without locating separate data
          runs

        Requires the optional `full` extra (same Yara dependency as
        windows_mftscan) — not registered without it.

        Returns a dict with:
        - "plugin": "mftscan.residentdata"
        - "results": list of dicts, one row per MFT record with resident
          $DATA content, each containing:
            "Offset": physical offset of the resident $DATA attribute
              (str, hex),
            "Record Type": raw MFT signature — FILE0, FILE*, or BAAD (str),
            "Record Number": MFT record number (int),
            "MFT Type": attribute type name, e.g. DATA (str),
            "Filename": longest recovered filename for the record (str),
            "Hexdump": the resident file content itself, as a compact
              hex string

        Forensic context:
        - NTFS only stores data resident in the MFT when the file is
          very small (roughly under a few hundred bytes, depending on
          filename/attribute overhead) — this tool will not find larger
          file content
        - Because it scans raw MFT signatures rather than a live
          filesystem, it recovers content for deleted files whose MFT
          record hasn't been reused yet
        - Complements windows_mftscan (metadata/timestamps only, no
          content) and windows_dumpfiles (needs a live _FILE_OBJECT)
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("mftscan.residentdata")


@mcp.tool()
def windows_registry_hivelist() -> dict:
    """
    Run the registry.hivelist plugin to list all registry hives loaded
    in memory, showing their virtual offsets and file paths.

    Use this tool when the user asks about:
    - Which registry hives are loaded in memory
    - Registry hive file paths or locations
    - SAM, SYSTEM, SOFTWARE, NTUSER.DAT, or other hive files
    - An overview of the registry structure in the memory image
    - Starting point for registry analysis

    Returns a dict with:
    - "plugin": "registry.hivelist"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the hive in memory (str, hex),
        "FileFullPath": full file path of the registry hive (str),
        "File output": file dump status (str)

    Forensic context:
    - Use the Offset values from this tool as input to
      windows_registry_printkey for targeted registry key enumeration
    - Key hives: SAM (user accounts), SECURITY (policies), SYSTEM
      (services, drivers), SOFTWARE (installed programs), NTUSER.DAT
      (per-user settings)
    - Hives without a file path (e.g., volatile hives) exist only in
      memory and may contain runtime configuration
    - Use windows_registry_hivescan to find additional hives that may
      have been unlinked from the hive list
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.hivelist")


@mcp.tool()
def windows_registry_hivescan() -> dict:
    """
    Run the registry.hivescan plugin to scan for registry hive structures
    in physical memory using pool tag scanning.

    Use this tool when the user asks about:
    - Scanning for all registry hives including unlinked ones
    - Finding registry hives that may have been hidden or detached
    - A more thorough hive discovery than the standard hive list
    - Physical offsets of registry hive structures in memory
    - Verifying hivelist results against pool scan findings

    Returns a dict with:
    - "plugin": "registry.hivescan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the hive structure (str, hex)

    Forensic context:
    - Compare with windows_registry_hivelist: hives found here but missing
      from the list may have been unlinked by a rootkit
    - The Offset values can be used with windows_registry_printkey to
      examine keys within specific hives
    - Pool scanning finds hive remnants even after they are unloaded,
      potentially revealing previously loaded hives
    - Use windows_registry_hivelist first for named hives; use this tool
      when you need to verify completeness or find hidden hives
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.hivescan")


@mcp.tool()
def windows_registry_printkey() -> dict:
    """
    Run the registry.printkey plugin to print registry keys, subkeys,
    and values from loaded registry hives.

    Use this tool when the user asks about:
    - Registry key values or data for a specific path
    - Contents of Run/RunOnce keys (persistence mechanisms)
    - Installed software, services, or startup entries in the registry
    - Specific registry paths like HKLM\\SYSTEM\\CurrentControlSet\\Services
    - Registry-based forensic artifacts (MRU lists, typed URLs, etc.)

    Returns a dict with:
    - "plugin": "registry.printkey"
    - "results": list of dicts, each containing:
        "Last Write Time": last modification timestamp of the key (str),
        "Hive Offset": offset of the containing hive (str, hex),
        "Type": entry type, either Key or Value (str),
        "Key": registry key path (str),
        "Name": value name or subkey name (str),
        "Data": value data content — decoded text for REG_SZ,
          REG_MULTI_SZ (newline-joined), and REG_DWORD/REG_QWORD
          (rendered as their decimal value), or a compact hex string
          for REG_BINARY (str),
        "Volatile": whether the key is volatile/memory-only (bool)

    Forensic context:
    - Persistence keys: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,
      HKLM\\SYSTEM\\CurrentControlSet\\Services — check for malware entries
    - Last Write Time indicates when the key was last modified, useful
      for timeline analysis and correlating with process activity
    - Volatile keys (Volatile=true) exist only in memory and are lost on
      reboot; malware may use these to avoid on-disk evidence
    - Use windows_registry_hivelist first to identify hive offsets, then
      this tool to explore specific keys within those hives
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.printkey")


@mcp.tool()
def windows_registry_userassist() -> dict:
    """
    Run the registry.userassist plugin to decode UserAssist registry entries,
    which track program execution history for each user.

    Use this tool when the user asks about:
    - Programs executed by users or application launch history
    - UserAssist records or program usage statistics
    - How many times a program was run and when it was last used
    - User activity or application execution timeline
    - Evidence of specific program execution on the system

    Returns a dict with:
    - "plugin": "registry.userassist"
    - "results": list of dicts, each containing:
        "Hive Offset": offset of the containing hive (str, hex),
        "Hive Name": name of the registry hive (str),
        "Path": registry key path (str),
        "Last Write Time": key last modification time (str),
        "Type": entry type (str),
        "Name": ROT13-decoded program name or path (str),
        "ID": entry identifier (int),
        "Count": number of times the program was executed (int),
        "Focus Count": number of times the window received focus (int),
        "Time Focused": total time the application had focus (str),
        "Last Updated": timestamp of the last execution (str),
        "Raw Data": raw binary data of the entry, as a compact hex
          string (str)

    Forensic context:
    - UserAssist entries are ROT13 encoded in the registry; this plugin
      automatically decodes them to reveal actual program paths
    - The Count field shows how many times a user launched each program,
      useful for establishing patterns of behavior
    - Last Updated timestamps help build an execution timeline, correlating
      with process creation times from windows_pslist
    - Use windows_sessions to identify which user account corresponds to
      each NTUSER.DAT hive containing UserAssist data
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.userassist")


@mcp.tool()
def windows_registry_certificates() -> dict:
    """
    Run the registry.certificates plugin to list certificates stored in
    the Windows registry certificate store.

    Use this tool when the user asks about:
    - Certificates installed on the system
    - Trusted root certificates or certificate authorities
    - Rogue or malicious certificates added to the store
    - SSL/TLS certificate inventory from the registry
    - Certificate-based trust manipulation indicators

    Returns a dict with:
    - "plugin": "registry.certificates"
    - "results": list of dicts, each containing:
        "Certificate path": registry path of the certificate (str),
        "Certificate section": store section such as Root, CA, My (str),
        "Certificate ID": unique identifier for the certificate (str),
        "Certificate name": common name or subject of the certificate (str)

    Forensic context:
    - Rogue root certificates in the Trusted Root CA store allow attackers
      to perform man-in-the-middle attacks on HTTPS traffic
    - Malware sometimes installs its own CA certificate to intercept
      encrypted communications or sign malicious code
    - Compare certificates against known legitimate Windows root CAs to
      identify unauthorized additions
    - Use windows_registry_printkey to examine the full certificate data
      stored under each certificate's registry path
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.certificates")


@mcp.tool()
def windows_registry_scheduled_tasks() -> dict:
    """
    Run the registry.scheduled_tasks plugin to decode Windows Task
    Scheduler entries stored in the registry, including triggers,
    actions, run times, and creation times.

    Use this tool when the user asks about:
    - Scheduled tasks, Task Scheduler jobs, or at/schtasks artifacts
    - Persistence mechanisms via the Task Scheduler
    - Which programs are set to run on a schedule or on event triggers
    - Creation time / last run time of scheduled tasks
    - Malware persistence registered as a scheduled task

    Returns a dict with:
    - "plugin": "registry.scheduled_tasks"
    - "results": list of dicts, each containing:
        "Task Name": task name / path (str),
        "Principal ID": security principal running the task (str),
        "Display Name": display name of the task (str),
        "Enabled": whether the task is enabled (bool),
        "Creation Time": when the task was created (str, UTC),
        "Last Run Time": when the task last ran (str, UTC),
        "Last Successful Run Time": last successful run (str, UTC),
        "Trigger Type": trigger category (Time, Logon, Boot, Event, ...)
          (str),
        "Trigger Description": human-readable trigger detail (str),
        "Action Type": action category (Exec, ComHandler, ...) (str),
        "Action": executable or handler invoked (str),
        "Action Arguments": arguments passed to the action (str),
        "Action Context": security context for the action (str),
        "Working Directory": working directory used when running (str),
        "Key Name": registry key name backing the task (str)

    Forensic context:
    - Scheduled tasks are one of the most common Windows persistence
      techniques (MITRE ATT&CK T1053.005). Pay special attention to
      tasks with Trigger Type = Logon or Boot and actions pointing to
      user-writable paths (AppData, ProgramData, Public)
    - Creation Time vs Last Run Time reveals freshly created persistence
      tasks that have already executed — correlate with windows_pslist
      and process timestamps to link the task to observed activity
    - Action fields containing LOLBins (powershell.exe, rundll32.exe,
      mshta.exe, regsvr32.exe) with obfuscated arguments are high-signal
      persistence indicators
    - Use the Key Name to locate the full registry entry with
      windows_registry_printkey for deeper inspection
    - Cross-reference task creation times against process creation times
      from windows_pslist to identify the process that registered the
      task
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.scheduled_tasks")


@mcp.tool()
def windows_registry_getcellroutine() -> dict:
    """
    Run the registry.getcellroutine plugin to detect registry hives whose
    GetCellRoutine function pointer has been hooked to point outside the
    kernel (ntoskrnl) — a registry rootkit indicator.

    Use this tool when the user asks about:
    - Registry rootkits or hooked registry access paths
    - Hidden registry keys that cannot be read via standard hive traversal
    - Kernel-mode tampering of the registry subsystem
    - Signs of registry filter drivers or offensive registry toolkits
    - Integrity check of registry hive access routines

    Returns a dict with:
    - "plugin": "registry.getcellroutine"
    - "results": list of dicts, each containing:
        "Hive Offset": virtual offset of the _CMHIVE structure (str, hex),
        "Hive Name": hive path / name such as \\REGISTRY\\MACHINE\\SYSTEM (str),
        "GetCellRoutine Module": module owning the hooked handler, or None
          if the handler does not resolve to any known module (str or None),
        "GetCellRoutine Handler": virtual address of the handler (str, hex)

    Forensic context:
    - Every registry hive stores a GetCellRoutine callback used to translate
      a cell index into a memory pointer. Legitimately this always resolves
      inside the Windows kernel. Any non-kernel module (or unresolved
      address) is malicious — the plugin's logic only yields hooked hives
    - A non-None GetCellRoutine Module that is not ntoskrnl indicates a
      driver has replaced the handler to intercept or filter registry reads
      (used by rootkits to hide keys/values from hivelist / printkey)
    - An unresolved handler (GetCellRoutine Module = None) means the hook
      points into unbacked memory — likely manually-mapped rootkit code;
      combine with windows_modscan and windows_orphan_kernel_threads to
      locate the owning driver
    - Pair with windows_registry_hivelist to confirm the hive is otherwise
      accessible, and windows_registry_printkey to attempt reading keys via
      the potentially hooked path
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.getcellroutine")


@mcp.tool()
def windows_registry_amcache() -> dict:
    """
    Run the registry.amcache plugin to decode AmCache.hve, which records
    metadata about every application, driver, or installer that has
    executed on the system.

    Use this tool when the user asks about:
    - What programs / EXEs were run on this system and when
    - Evidence of execution (MITRE ATT&CK T1005 / investigator questions
      like "did foo.exe ever run here?")
    - Driver or service binary history
    - SHA1 hashes of executed files for IoC matching or sandbox lookup
    - Program install / compile / last-modified timestamps
    - First-time / post-breach triage on an image with no prelogged data

    Returns a dict with:
    - "plugin": "registry.amcache"
    - "results": list of dicts, each containing:
        "EntryType": AmCache entry category such as Programs,
          InventoryApplicationFile, InventoryDriverBinary, etc. (str),
        "Path": full file path of the executable (str),
        "Company": company / vendor reported in PE resources (str),
        "LastModifyTime": registry key last-write time (str, UTC),
        "LastModifyTime2": secondary modification timestamp (str, UTC),
        "InstallTime": recorded install timestamp (str, UTC),
        "CompileTime": PE compilation timestamp (str, UTC),
        "SHA1": SHA1 hash of the file recorded by AmCache (str),
        "Service": name of the service backed by this binary, if any (str),
        "ProductName": product name from PE version info (str),
        "ProductVersion": product version from PE version info (str)

    Forensic context:
    - AmCache is one of the most important evidence-of-execution artifacts
      on Windows — it records binaries that ran even after the executable
      has been deleted from disk. A hit here with a matching SHA1 is a
      very strong indicator of execution
    - LastModifyTime (registry key last-write) usually aligns with the
      first time the binary was executed; correlate with process creation
      times from windows_pslist to place an incident on a timeline
    - Compare SHA1 values against public threat intel / VirusTotal. Entries
      whose Path points to user-writable directories (AppData, ProgramData,
      %TEMP%) with an unsigned or unknown Company are high-signal leads
    - Combine with windows_registry_userassist (execution by user via
      Explorer) and windows_registry_scheduled_tasks (execution by Task
      Scheduler) for a fuller persistence / execution picture
    - Driver entries (EntryType containing InventoryDriverBinary) let you
      enumerate all drivers ever loaded; correlate with windows_modules
      and windows_malware_drivermodule to spot drivers that executed historically
      but are no longer loaded
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("registry.amcache")


if "registry.hashdump" in PLUGIN_MAP:

    @mcp.tool()
    def windows_registry_hashdump() -> dict:
        """
        Run the registry.hashdump plugin to decrypt and dump local LM/NT
        password hashes from the SAM and SYSTEM registry hives.

        Use this tool when the user asks about:
        - Local (non-domain) user account password hashes
        - Extracting SAM database contents from a memory image
        - Credential recovery for authorized password-cracking /
          offline-hash-cracking as part of an engagement
        - Verifying whether a known account had a weak or default
          password hash

        Requires the optional `full` extra (`uv sync --extra full`) —
        the plugin hard-fails to import without `pycryptodome`. This
        tool is not registered at all without the extra.

        Returns a dict with:
        - "plugin": "registry.hashdump"
        - "results": list of dicts, one per local account, each
          containing:
            "User": account name (str),
            "rid": relative identifier of the account (int),
            "lmhash": LM hash, typically the well-known empty-password
              constant on modern Windows where LM is disabled (str, hex),
            "nthash": NT hash of the account password (str, hex)

        Forensic context:
        - LM hashes are effectively always the disabled/blank constant on
          Windows Vista and later; the NT hash is the meaningful field
        - This only covers local SAM accounts — domain-joined machines
          authenticate most users via a domain controller, not the local
          SAM, so an empty or short result on a domain machine is
          expected, not a failure
        - Cross-reference "User" with windows_pslist / windows_sessions
          to see which accounts were actively logged in at capture time
        - This is credential material — handle output with the same
          care as any other extracted secret, per your engagement's data
          handling rules
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("registry.hashdump")


if "registry.lsadump" in PLUGIN_MAP:

    @mcp.tool()
    def windows_registry_lsadump() -> dict:
        """
        Run the registry.lsadump plugin to decrypt and dump LSA secrets
        from the SECURITY and SYSTEM registry hives.

        Use this tool when the user asks about:
        - LSA secrets such as cached service account passwords, DPAPI
          machine keys, or auto-logon credentials stored by the OS
        - Recovering plaintext or near-plaintext secrets Windows itself
          keeps encrypted at rest for its own services
        - Investigating credential-theft techniques that target LSASS /
          LSA secrets (e.g., Mimikatz-style attacks)

        Requires the optional `full` extra (`uv sync --extra full`) —
        the plugin hard-fails to import without `pycryptodome`. This
        tool is not registered at all without the extra.

        Returns a dict with:
        - "plugin": "registry.lsadump"
        - "results": list of dicts, one per LSA secret, each containing:
            "Key": name of the LSA secret key, e.g.
              `$MACHINE.ACC`, `DefaultPassword`, `_SC_<service>` (str),
            "Secret" and "Hex": the same decrypted secret bytes, both as
              a compact hex string (identical content, two volatility3
              types)

        Forensic context:
        - `$MACHINE.ACC` holds the machine account password used for
          domain authentication; `_SC_<service>` entries hold the
          plaintext password configured for a Windows service's logon
          account — a very common lateral-movement credential source
        - `DefaultPassword` / `DefaultUserName` reveal auto-logon
          credentials configured in the registry
        - Cross-reference service-account secrets with windows_svcscan
          to identify which service actually uses that account
        - This is credential material — handle output with the same
          care as any other extracted secret, per your engagement's data
          handling rules
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("registry.lsadump")


if "registry.cachedump" in PLUGIN_MAP:

    @mcp.tool()
    def windows_registry_cachedump() -> dict:
        """
        Run the registry.cachedump plugin to decrypt cached domain-logon
        credentials (MSCACHE / MSCACHEv2 hashes) from the SECURITY and
        SYSTEM registry hives.

        Use this tool when the user asks about:
        - Cached domain credentials that let a laptop log a user in
          while disconnected from the domain controller
        - Whether a specific domain user had ever logged into this
          machine
        - Credential material for authorized offline cracking as part
          of an engagement

        Requires the optional `full` extra (`uv sync --extra full`) —
        the plugin hard-fails to import without `pycryptodome`. This
        tool is not registered at all without the extra.

        Returns a dict with:
        - "plugin": "registry.cachedump"
        - "results": list of dicts, one per cached logon, each
          containing:
            "Username": domain account name (str),
            "Domain": NetBIOS domain name the account belongs to (str),
            "Domain name": DNS domain name the account belongs to (str),
            "Hash": MSCACHE/MSCACHEv2 hash of the cached credential, as
              a compact hex string

        Forensic context:
        - Unlike windows_registry_hashdump (local SAM only), this
          surfaces evidence of *domain* account usage on the machine —
          useful for confirming lateral movement or a specific user's
          prior interactive logon
        - MSCACHEv2 hashes are intentionally slow to crack (many
          iterations of PBKDF2); a hit here confirms the account logged
          in, even before any cracking attempt succeeds
        - Cross-reference "Username" with windows_registry_userassist
          and windows_sessions for a fuller picture of that user's
          activity on the machine
        - This is credential material — handle output with the same
          care as any other extracted secret, per your engagement's data
          handling rules
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("registry.cachedump")


@mcp.tool()
def windows_malware_skeleton_key_check() -> dict:
    """
    Run the skeleton_key_check plugin to detect the Skeleton Key malware
    by scanning lsass.exe for patched authentication functions.

    Use this tool when the user asks about:
    - Skeleton Key malware detection
    - LSASS authentication tampering or credential theft
    - Active Directory backdoor indicators
    - Patched rc4HmacInitialize or rc4HmacDecrypt functions
    - Domain controller compromise indicators

    Returns a dict with:
    - "plugin": "skeleton_key_check"
    - "results": list of dicts, each containing:
        "PID": process ID of lsass.exe (int),
        "Process": process name (str),
        "Skeleton Key Found": whether the Skeleton Key patch was detected (bool),
        "rc4HmacInitialize": address of rc4HmacInitialize function (str, hex),
        "rc4HmacDecrypt": address of rc4HmacDecrypt function (str, hex)

    Forensic context:
    - Skeleton Key is an in-memory patch to LSASS that allows attackers to
      authenticate as any user with a master password, without modifying
      actual user credentials
    - A True value in "Skeleton Key Found" is a definitive indicator of
      compromise on a domain controller
    - Use windows_pslist to verify that lsass.exe is running with expected
      parameters and parent process (should be wininit.exe)
    - Cross-reference with windows_malware_malfind to check for other code
      injections in the lsass.exe process
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.skeleton_key_check")


@mcp.tool()
def windows_mbrscan() -> dict:
    """
    Run the mbrscan plugin to scan for and parse potential Master Boot
    Records (MBRs) in the memory image.

    Use this tool when the user asks about:
    - Master Boot Records or MBR analysis
    - Bootkit or boot-level malware detection
    - Disk partition layout found in memory
    - Boot code integrity or MBR tampering
    - Disk signatures or bootable partition indicators

    Returns a dict with:
    - "plugin": "mbrscan"
    - "results": list of dicts. The plugin emits a parent row per
      candidate MBR (level 0) followed by up to 4 child rows, one per
      partition table entry (level 1); most fields below are shared by
      both levels since they describe the MBR they belong to. Verified
      against a real memory image — this server always gets the
      plugin's default (`full=False`) schema, not its optional
      extended one:
        "Potential MBR at Physical Offset": physical offset (str, hex),
        "Disk Signature": disk signature identifier (str),
        "Bootcode MD5": MD5 hash of the 0x1B8-byte boot code section (str),
        "Full MBR MD5": MD5 hash of the entire 512-byte MBR (str),
        "PartitionIndex": 1-4, partition table entry index; only set on
          child rows (int or null on the parent row),
        "Bootable": whether the partition is marked bootable; only set
          on child rows (bool or null on the parent row),
        "PartitionType": filesystem or partition type name; only set on
          child rows (str or null on the parent row),
        "SectorInSize": partition size in sectors; only set on child
          rows (str, hex, or null on the parent row),
        "Disasm": the boot code bytes as a compact hex string, only set
          on the parent row (not an actual disassembly listing despite
          the volatility3 column name — this server doesn't invoke
          capstone)

    Forensic context:
    - Compare Bootcode MD5 against known-good MBR hashes for the OS
      version; mismatches may indicate bootkit infection
    - Bootkits like TDL4, Rovnix, or Carberp modify the MBR to load
      malicious code before the operating system starts
    - Multiple MBR candidates at different offsets may indicate previous
      MBR contents preserved in memory after modification
    - "Disasm" gives you the raw boot sector bytes as hex for external
      analysis (e.g. with a Yara rule or a disassembler) if the MD5
      comparison flags something suspicious
    - Use windows_info to identify the OS version and determine the
      expected boot code for comparison
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("mbrscan")


@mcp.tool()
def windows_truecrypt() -> dict:
    """
    Run the truecrypt plugin to search for cached TrueCrypt passphrases
    remaining in memory.

    Use this tool when the user asks about:
    - TrueCrypt passphrases or encryption keys in memory
    - Full-disk encryption password recovery
    - Cached encryption credentials from TrueCrypt volumes
    - Evidence of encrypted volume usage on the system
    - Decryption key extraction for forensic access

    Returns a dict with:
    - "plugin": "truecrypt"
    - "results": list of dicts, each containing:
        "Offset": memory offset where the passphrase was found (str, hex),
        "Length": length of the passphrase in bytes (int),
        "Password": the cached passphrase string (str)

    Forensic context:
    - TrueCrypt caches passphrases in kernel memory while volumes are
      mounted; this plugin can recover them if the volume was mounted
      at the time of capture
    - Recovered passphrases can be used to decrypt TrueCrypt volumes for
      further forensic examination of their contents
    - Also works with VeraCrypt in some cases, as it shares the same
      passphrase caching mechanism
    - Use windows_pslist to check if TrueCrypt.exe or VeraCrypt.exe
      processes were running at the time of capture
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("truecrypt")


@mcp.tool()
def windows_getservicesids() -> dict:
    """
    Run the getservicesids plugin to generate a mapping of Windows service
    names to their computed Security Identifiers (SIDs).

    Use this tool when the user asks about:
    - Service SIDs or service account security identifiers
    - Mapping a SID back to a Windows service name
    - Which services have associated security identifiers
    - Service-level access control or permission analysis
    - Resolving unknown SIDs found in process tokens

    Returns a dict with:
    - "plugin": "getservicesids"
    - "results": list of dicts, each containing:
        "SID": computed service SID string (str),
        "Service": Windows service name (str)

    Forensic context:
    - Service SIDs (S-1-5-80-...) are computed from service names and
      used for per-service access control; this tool provides the mapping
    - Use this output to resolve unknown SIDs found in windows_getsids
      results, identifying which service a process token belongs to
    - Malware that installs itself as a service will have a computable
      service SID that appears in this list
    - Cross-reference with windows_registry_printkey on the Services
      registry key to correlate service configurations with their SIDs
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("getservicesids")


@mcp.tool()
def windows_statistics() -> dict:
    """
    Run the statistics plugin to display memory space statistics, showing
    how many pages are valid, swapped, or invalid in the memory image.

    Use this tool when the user asks about:
    - Memory image quality or completeness
    - How many valid vs invalid pages are in the memory dump
    - Swapped or paged-out memory statistics
    - Overall memory utilization at the time of capture
    - Whether the memory image has sufficient data for analysis

    Returns a dict with:
    - "plugin": "statistics"
    - "results": list of dicts, each containing:
        "Valid pages (all)": total valid pages (int),
        "Valid pages (large)": valid large pages (int),
        "Swapped Pages (all)": total swapped pages (int),
        "Swapped Pages (large)": swapped large pages (int),
        "Invalid Pages (all)": total invalid pages (int),
        "Invalid Pages (large)": invalid large pages (int),
        "Other Invalid Pages (all)": other invalid pages (int)

    Forensic context:
    - A high ratio of invalid pages may indicate an incomplete or
      corrupted memory dump, reducing the reliability of other plugins
    - Swapped pages represent data that was paged to disk at capture time;
      this data may be missing from analysis unless the pagefile is available
    - Run this tool early to assess image quality before investing time
      in detailed analysis with other plugins
    - Use windows_info to get OS version context for interpreting the
      memory layout statistics
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("statistics")


@mcp.tool()
def windows_crashinfo() -> dict:
    """
    Run the crashinfo plugin to parse and display the header information
    from a Windows crash dump file.

    Use this tool when the user asks about:
    - Crash dump header or metadata
    - Whether the memory image is a crash dump format
    - System time or uptime recorded in the crash dump
    - Number of processors or machine type from the dump header
    - Crash dump type (full, kernel, or mini dump)

    Returns a dict with:
    - "plugin": "crashinfo"
    - "results": list of dicts, each containing:
        "Signature": crash dump signature string (str),
        "MajorVersion": OS major version (int),
        "MinorVersion": OS minor version (int),
        "DirectoryTableBase": DTB address (str, hex),
        "PfnDataBase": PFN database address (str, hex),
        "PsLoadedModuleList": loaded module list address (str, hex),
        "PsActiveProcessHead": active process list head (str, hex),
        "MachineImageType": processor architecture identifier (int),
        "NumberProcessors": number of processors (int),
        "KdDebuggerDataBlock": debugger data block address (str, hex),
        "DumpType": type of crash dump (str),
        "SystemUpTime": system uptime at crash (str),
        "Comment": crash dump comment if present (str),
        "SystemTime": system time at crash (str),
        "BitmapHeaderSize": bitmap header size for full dumps (int),
        "BitmapSize": bitmap size for full dumps (int),
        "BitmapPages": number of bitmap pages (int)

    Forensic context:
    - This plugin only works with crash dump format images; raw memory
      images will produce no results
    - The SystemTime and SystemUpTime fields provide the exact time of
      the crash, anchoring the forensic timeline
    - Use windows_info for general OS information that works with all
      image formats, not just crash dumps
    - NumberProcessors and MachineImageType help verify the system
      configuration matches the expected target
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("crashinfo")


@mcp.tool()
def windows_bigpools() -> dict:
    """
    Run the bigpools plugin to list large pool allocations tracked by the
    Windows kernel in the big page pool table.

    Use this tool when the user asks about:
    - Big pool allocations or large kernel memory allocations
    - Kernel pool tag analysis or pool tag statistics
    - Driver memory usage or kernel object allocations
    - Suspicious large allocations that may indicate rootkit or exploit activity
    - Non-paged pool or paged pool consumption

    Returns a dict with:
    - "plugin": "bigpools"
    - "results": list of dicts, each containing:
        "Allocation": base address of the allocation (str, hex),
        "Tag": four-character pool tag identifying the allocator (str),
        "PoolType": pool type such as NonPagedPool or PagedPool (str),
        "NumberOfBytes": size of the allocation in bytes (str, hex),
        "Status": whether the allocation is free or in use (str)

    Forensic context:
    - Pool tags identify which kernel component or driver made the allocation;
      unknown or suspicious tags may indicate rootkit-allocated memory
    - Cross-reference pool tags with known Windows driver tags to identify
      anomalous allocations (e.g., tags not matching any legitimate driver)
    - Large non-paged pool allocations are commonly used by rootkits to store
      injected code or hooked function tables in kernel space
    - Use windows_pslist and windows_psscan to correlate suspicious allocations
      with process activity on the system
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("bigpools")


@mcp.tool()
def windows_kpcrs() -> dict:
    """
    Run the kpcrs plugin to enumerate every Windows Kernel Processor
    Control Region (KPCR) structure and its PRCB (Processor Control
    Block) offset — one KPCR per logical CPU.

    Use this tool when the user asks about:
    - How many CPUs / cores were online at capture time
    - KPCR / PRCB addresses for each processor
    - Per-CPU kernel state starting points for deeper analysis
    - Verifying the image's SMP layout matches the system profile

    Returns a dict with:
    - "plugin": "kpcrs"
    - "results": list of dicts (one row per logical CPU), each containing:
        "Offset": virtual address of the _KPCR structure (str, hex),
        "PRCB Offset": virtual address of the embedded _KPRCB (str, hex)

    Forensic context:
    - Row count equals the logical CPU count visible at acquisition
      time; an unexpected count can indicate a corrupted image or the
      wrong symbol profile
    - The PRCB pointer is the entry point for per-CPU kernel state
      (current thread, idle thread, DPC queues). Many other plugins
      (e.g. windows_timers) rely on these offsets internally
    - Mismatched or zero PRCB offsets can be a smear / corruption
      indicator on live-acquired images
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("kpcrs")


@mcp.tool()
def windows_unloadedmodules() -> dict:
    """
    Run the unloadedmodules plugin to list kernel drivers / modules that
    have been unloaded but whose names the kernel still tracks in its
    MmUnloadedDrivers history array.

    Use this tool when the user asks about:
    - Drivers that were loaded then unloaded during the capture window
    - Traces of transient kernel malware (e.g. load → exploit → unload)
    - Historical driver activity no longer visible in windows_modules
    - Unload timestamps for forensic timeline construction
    - Signs of a rootkit that deliberately unloads itself to hide

    Returns a dict with:
    - "plugin": "unloadedmodules"
    - "results": list of dicts, each containing:
        "Name": driver / module filename (str),
        "StartAddress": original load base address (str, hex),
        "EndAddress": end of the driver's loaded range (str, hex),
        "Time": timestamp when the driver was unloaded (str, UTC)

    Forensic context:
    - Windows keeps a small ring of recently-unloaded driver entries
      (MmUnloadedDrivers); this plugin reads that ring. A short name
      appearing here but absent from both windows_modules and
      windows_modscan is a classic load-and-unload rootkit pattern
    - Compare Time values against suspicious process creation or
      network activity timestamps to connect a driver's lifecycle to
      observed behavior
    - StartAddress / EndAddress give you the memory range the driver
      occupied; correlate with windows_callbacks / windows_ssdt hook
      entries pointing into those ranges to attribute hooks to the
      unloaded driver
    - An unexpectedly large number of unloaded drivers may indicate
      repeated crash / reload cycles on the image
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("unloadedmodules")


@mcp.tool()
def windows_timers() -> dict:
    """
    Run the timers plugin to enumerate every kernel-level DPC timer
    registered on each CPU and resolve its routine address to the owning
    module/symbol.

    Use this tool when the user asks about:
    - Kernel timers / DPC routines scheduled on the system
    - Timer-based rootkit persistence (repeating DPCs that hook kernel work)
    - Which driver owns a particular timer callback
    - Suspiciously short-period timers that keep malicious code alive
    - Callbacks whose routine address doesn't resolve to any module

    Returns a dict with:
    - "plugin": "timers"
    - "results": list of dicts, each containing:
        "Offset": virtual address of the _KTIMER structure (str, hex),
        "DueTime": 100-nanosecond absolute time the timer is due (str),
        "Period(ms)": periodic interval in milliseconds; 0 means one-shot
          (int),
        "Signaled": whether the timer is currently signaled (str),
        "Routine": address of the DPC routine that fires when the timer
          expires (str, hex),
        "Module": module that owns the Routine address, or None if the
          address does not map to any loaded module (str or None),
        "Symbol": symbol name at Routine, when resolvable (str or None)

    Forensic context:
    - Timers whose ``Module`` is None / UNKNOWN are the highest-signal
      rows: a DPC firing from unbacked memory is almost certainly
      rootkit-injected kernel code
    - Unexpectedly short ``Period(ms)`` values on timers owned by
      non-standard modules (e.g. <= 100 ms on a driver nobody loaded)
      is a persistence pattern — the routine keeps re-waking to
      maintain hooks or heartbeats
    - Cross-reference ``Module`` against windows_modscan and
      windows_unloadedmodules: a timer pointing into an unloaded or
      unlinked module is a load-and-unload rootkit indicator
    - Use windows_pe_symbols to reverse-resolve the ``Routine`` address
      when ``Symbol`` is empty but you recognise the ``Module``
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("timers")


@mcp.tool()
def windows_debugregisters() -> dict:
    """
    Run the debugregisters plugin to dump each thread's hardware
    debug-register state (DR0-DR3 addresses, DR7 control) and resolve
    every non-zero breakpoint address to its owning module/symbol.

    Use this tool when the user asks about:
    - Hardware breakpoints set on the system
    - Debug register hijacking or EDR-evasion via DR hooks
    - Malware using DR0-DR3 to intercept API calls without patching code
    - Threads attached to a debugger with active HW breakpoints
    - Explaining unusual Dr7 bit patterns across threads

    Returns a dict with:
    - "plugin": "debugregisters"
    - "results": list of dicts (one row per thread whose DR state is
      non-zero), each containing:
        "Process": owning process image name (str),
        "PID": process ID (int),
        "TID": thread ID (int),
        "State": thread state code (int),
        "Dr7": raw DR7 control register value (int),
        "Dr0", "Dr1", "Dr2", "Dr3": breakpoint addresses (str, hex),
        "Range0..3": memory range / module backing each breakpoint
          address (str or None),
        "Symbol0..3": symbol name at each breakpoint address, when
          resolvable (str or None)

    Forensic context:
    - Hardware breakpoints are invisible to user-space code (no INT3
      patching), so malware uses them to hook APIs like NtCreateFile,
      LdrLoadDll, or csrss's ConsoleAlloc handlers while leaving
      memory untouched — any thread with non-null DR0-DR3 in a
      non-debugger process is suspicious
    - Look at Dr7 layout: the lower 8 bits enable DR0-DR3 per-thread;
      the upper bits encode condition (execute/write/IO/read-write)
      and length. Suspicious DR7 on non-debugger threads deserves
      scrutiny
    - Range / Symbol columns let you immediately see which API was
      being watched — e.g. Symbol1="LdrLoadDll" in a non-debugger
      process is almost certainly an EDR-evasion hook
    - Cross-reference the TID with windows_threads to get the thread's
      StartAddress, and windows_malware_malfind to see if the owning
      VAD was injected
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("debugregisters")


@mcp.tool()
def windows_etwpatch(pid: int = 0) -> dict:
    """
    Run the etwpatch plugin to detect in-memory tampering of ETW
    (Event Tracing for Windows) stub functions inside ntdll.dll —
    a common evasion technique to blind security telemetry.

    Use this tool when the user asks about:
    - ETW patching, ETW tampering, or ETW evasion
    - EDR / antivirus telemetry disabling in user mode
    - Malware hooking EtwEventWrite / NtTraceEvent / EtwNotificationRegister
    - Processes with unusual ETW stub prologues (e.g., ``ret`` replacing
      the real body)
    - Detection of userland AMSI / ETW bypass injected into a specific PID

    Arguments:
    - pid (optional, default 0): restrict the scan to this process. When
      0, every userland process is inspected.

    Returns a dict with:
    - "plugin": "etwpatch"
    - "results": list of dicts (one row per patched stub detected):
        "PID": process ID hosting the patched ntdll (int),
        "Process": image name (str),
        "DLL": name of the module that was tampered (typically
          ``ntdll.dll``) (str),
        "Function": the ETW function whose prologue differs from the
          on-disk image (str),
        "Offset": virtual address of the patched instruction (str, hex),
        "Opcode": disassembly of the patched bytes (str)

    Forensic context:
    - Any non-empty result is high-signal. Modern malware commonly
      writes ``ret`` (0xC3) or a short jump into the start of ETW
      functions to silence telemetry inside the current process
    - If only a subset of processes shows patches, they are usually
      the infected ones — combine with windows_malware_malfind and
      windows_cmdline to attribute the tampering
    - Uses windows_pe_symbols internally for function-address
      resolution, so symbol availability matters: if PDBs fail to
      download at startup, the plugin cannot compare against on-disk
      prologues
    - Pair with windows_suspended_threads: ETW patching is often done
      by an injected remote thread — the thread is suspended, DLLs
      loaded, ntdll patched, then resumed
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("etwpatch", pid=pid)


@mcp.tool()
def windows_svcscan() -> dict:
    """
    Run the svcscan plugin to enumerate Windows services by scanning the
    services.exe process memory for service record signatures.

    Use this tool when the user asks about:
    - Windows services, service configuration, or installed services
    - Which services are running, stopped, or set to auto-start
    - Service binaries, service DLLs, or service host mapping
    - Malicious services used for persistence (e.g., scheduled-boot payload)
    - Suspicious or unknown services that do not ship with Windows

    Returns a dict with:
    - "plugin": "svcscan"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the service record (str, hex),
        "Order": ordinal position within the enumerated set (int),
        "PID": process ID hosting the service — typically services.exe or
          a svchost.exe group (int),
        "Start": start type (Auto / Manual / Disabled / System / Boot) (str),
        "State": current runtime state (Running / Stopped / Paused / ...)
          (str),
        "Type": service type flags (Kernel Driver, Win32 Own Process, etc.)
          (str),
        "Name": internal service name (str),
        "Display": human-readable display name (str),
        "Binary": resolved service binary path or ServiceMain entrypoint
          (str),
        "Binary (Registry)": raw ImagePath value from the registry (str),
        "Dll": service DLL for svchost-hosted services (str or None)

    Forensic context:
    - Services configured with Start=Auto whose Binary points to a
      temp/user-writable path (e.g., AppData, ProgramData) are classic
      persistence indicators
    - Cross-reference Binary and Binary (Registry): divergence can indicate
      service hijacking (registry tampering without restart) or unhooking
    - Unusual service types (e.g., Kernel Driver pointing to an unsigned
      or non-standard path) pair with windows_modules and windows_driverscan
      for further rootkit analysis
    - Correlate the PID column against windows_pslist to identify the
      hosting svchost.exe group, then chain to windows_dlllist to inspect
      loaded service DLLs
    - Compare with windows_svclist (when available) to spot list/scan
      discrepancies — a service present here but not in svclist suggests
      DKOM/unlinking of the service record
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("svcscan")


@mcp.tool()
def windows_svclist() -> dict:
    """
    Run the svclist plugin to enumerate Windows services by walking the
    services.exe doubly linked list of service records (list-based view,
    as opposed to svcscan's signature scan).

    Use this tool when the user asks about:
    - The canonical list of services currently registered with SCM
    - Running services in their linked order
    - A list-walk view of services for comparison against svcscan results
    - Detection of hidden services via list/scan discrepancy
    - Persistence mechanisms registered with the Service Control Manager

    Important: this plugin supports only 64-bit Windows 10 build 15063 and
    later. On older Windows 7 / 8 / 8.1 or 32-bit samples it will log a
    warning and return an empty result — use windows_svcscan instead.

    Returns a dict with:
    - "plugin": "svclist"
    - "results": list of dicts with the same schema as windows_svcscan:
        "Offset", "Order", "PID", "Start", "State", "Type", "Name",
        "Display", "Binary", "Binary (Registry)", "Dll"

    Forensic context:
    - svclist walks the in-memory linked list of service records used by
      SCM, while svcscan discovers records by signature scanning — any
      service present in svcscan but missing from svclist is a strong
      rootkit / DKOM indicator (the record was unlinked from SCM's list
      but still lives in memory)
    - Use the two tools together: run windows_svcscan and windows_svclist,
      then diff the Name column. This is the logic the deprecated
      windows.svcdiff wrapper (canonical: windows.malware.svcdiff)
      performs internally
    - If svclist returns empty on a supported OS, the services.exe VAD
      scan failed — investigate process integrity with windows_pslist
      and windows_malware_malfind for PID of services.exe
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("svclist")


@mcp.tool()
def windows_windowstations() -> dict:
    """
    Run the windowstations plugin to enumerate every Windows ``tagWINDOWSTATION``
    object — the top-level container that scopes interactive desktops,
    clipboard, and atom tables for a logon session.

    Use this tool when the user asks about:
    - Window stations or interactive sessions on the system
    - Service-vs-interactive isolation (Service-0x0-3e7$ etc.)
    - The set of session IDs at the GUI subsystem level
    - First step before enumerating windows_desktops or windows_deskscan
    - Investigating clipboard / atom-based malware persistence

    Returns a dict with:
    - "plugin": "windowstations"
    - "results": list of dicts, each containing:
        "Offset": virtual address of the _tagWINDOWSTATION object (str, hex),
        "Name": window station name (e.g., ``WinSta0`` for the interactive
          station; ``Service-0x0-3e7$`` for the SYSTEM session) (str),
        "SessionId": session ID owning this window station (int)

    Forensic context:
    - WinSta0 in SessionId > 0 indicates an active interactive logon —
      compare with windows_sessions to attribute it to a user
    - Anomalous or duplicate window station names can indicate
      isolation-bypass tools that create their own GUI sandboxes
    - Use the offsets from this output as input scope for
      windows_desktops (per-station desktop walk) and windows_deskscan
      (pool-tag scan that may surface hidden desktops)
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("windowstations")


@mcp.tool()
def windows_desktops() -> dict:
    """
    Run the desktops plugin to enumerate every ``tagDESKTOP`` object by
    walking the Desktop linked list of each Window Station, and the
    process threads attached to each desktop.

    Use this tool when the user asks about:
    - Desktops attached to a Window Station / interactive session
    - Which processes hold a thread on the interactive desktop (Default,
      Winlogon, Disconnect)
    - Mapping a process to its GUI desktop context
    - GUI subsystem state for the logged-on user
    - Detection of unusual / hidden desktops registered by malware

    Returns a dict with:
    - "plugin": "desktops"
    - "results": list of dicts (one row per (desktop, attached process)
      pair), each containing:
        "Offset": virtual address of the _tagDESKTOP object (str, hex),
        "Window Station": parent WindowStation name (e.g. ``WinSta0``,
          ``Service-0x0-3e7$``) (str),
        "Session": session ID hosting the desktop (int),
        "Desktop": desktop name (e.g. ``Default``, ``Winlogon``,
          ``Disconnect``) (str),
        "Process": image name of a process attached to this desktop (str),
        "PID": that process's ID (int)

    Forensic context:
    - Desktops named other than ``Default`` / ``Winlogon`` / ``Disconnect``
      can indicate sandbox-evasion or stealth GUI execution; cross
      reference with windows_pslist to see whether the owning process is
      legitimate
    - Compare with windows_deskscan results: rows in deskscan that don't
      appear here suggest unlinked / hidden desktops (object exists but
      isn't on the parent station's list)
    - Use Session column to confirm whether activity is in an interactive
      logon session vs SYSTEM service space
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("desktops")


@mcp.tool()
def windows_deskscan() -> dict:
    """
    Run the deskscan plugin to discover ``tagDESKTOP`` objects via pool
    tag scanning instead of walking the WindowStation desktop list. This
    surfaces hidden / unlinked desktops that windows_desktops would miss.

    Use this tool when the user asks about:
    - Hidden or unlinked desktops not reachable from a WindowStation list
    - Detection of desktop hijacking / sandbox-evasion artifacts
    - A scan-based view to compare against the linked-list windows_desktops
    - Recovering desktop objects from images where standard enumeration
      yields nothing

    Returns a dict with:
    - "plugin": "deskscan"
    - "results": list of dicts with the same schema as windows_desktops:
        "Offset": virtual address of the _tagDESKTOP object (str, hex),
        "Window Station": parent WindowStation name (str),
        "Session": session ID (int),
        "Desktop": desktop name (str),
        "Process": process attached to the desktop (str),
        "PID": process ID (int)

    Forensic context:
    - The classic list-vs-scan pattern (cf. windows_pslist vs
      windows_psscan): rows present here but absent from
      windows_desktops are hidden / DKOM-removed desktops
    - Use as a fallback when windows_desktops returns empty due to GUI
      symbol limitations on older Windows images — the scan path may
      still surface objects via pool tags
    - Suspicious desktop names (anything other than ``Default`` /
      ``Winlogon`` / ``Disconnect``) deserve cross-reference with
      windows_pslist for the attached process
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("deskscan")


@mcp.tool()
def windows_windows() -> dict:
    """
    Run the windows plugin to enumerate every visible / hidden GUI
    window object across every Desktop / WindowStation, mapping each
    window back to its owning process and its WindowProc handler.

    Use this tool when the user asks about:
    - GUI windows currently registered on the system
    - Window titles / classes for a given process
    - WindowProc hijacking (a foreign Procedure address inside a
      legitimate window's handler slot)
    - Sandbox-evasion techniques that hide windows from the taskbar
    - Mapping a visible UI back to its hosting process

    Returns a dict with:
    - "plugin": "windows"
    - "results": list of dicts, each containing:
        "Offset": virtual address of the _tagWND object (str, hex),
        "Station": parent WindowStation name (str),
        "Session": session ID (int),
        "Desktop": parent Desktop name (str),
        "Window": window class / title (str),
        "Procedure": address of the WindowProc that handles messages
          (str, hex),
        "Process": owning process image name (str),
        "PID": owning process ID (int)

    Forensic context:
    - WindowProc hijacking: a Procedure address pointing outside the
      owning module's range is a classic UI-subsystem injection
      indicator. Use windows_pe_symbols to attribute the address to
      its real module
    - Cross-reference with windows_desktops / windows_deskscan to
      confirm the parent Desktop is legitimate
    - Hidden / off-screen windows can host clipboard hijackers,
      keyloggers, or banking-trojan overlays — pair with
      windows_malware_malfind on the owning PID for context
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("windows")


@mcp.tool()
def windows_malware_unhooked_system_calls() -> dict:
    """
    Run the malware.unhooked_system_calls plugin to detect ntdll.dll
    syscall stubs whose prologues differ across processes — the classic
    signature of EDR / userland-hooking frameworks (and increasingly
    of unhooking malware that restores stubs from disk to bypass EDR).

    Use this tool when the user asks about:
    - EDR / antivirus userland hooks on ntdll syscall stubs
    - Malware unhooking (restoring original ntdll bytes to evade EDR)
    - Differences between processes' ntdll prologues
    - Identifying which Nt* / Zw* functions are the most commonly hooked
    - Detecting AMSI / ETW / hooking-bypass tooling indirectly via
      stub divergence

    Returns a dict with:
    - "plugin": "malware.unhooked_system_calls"
    - "results": list of dicts (one row per syscall function whose
      first instruction bytes differ across at least two processes):
        "Function": ntdll syscall name (e.g. ``NtCreateFile``) (str),
        "Distinct Implementations": comma-separated count of unique
          prologue byte sequences observed (str),
        "Total Implementations": total processes inspected (int)

    Forensic context:
    - All clean processes share an identical syscall stub prologue
      (mov eax, <syscall#>; syscall; ret on x64). Any function with
      ``Distinct Implementations`` > 1 means at least one process
      runs a different prologue — a hook (EDR or malware) or an
      unhook (malware that overwrote a hook with the original bytes)
    - Functions touched by EDR commonly include NtCreateFile,
      NtWriteFile, NtAllocateVirtualMemory, NtProtectVirtualMemory,
      NtCreateThreadEx, LdrLoadDll, EtwEventWrite — divergence on
      these in a non-EDR-instrumented system is high-signal malicious
    - Combine with windows_etwpatch (ETW-stub tampering) and
      windows_malware_malfind (injected code in suspect VADs) to
      attribute the divergence to a specific PID
    - Requires successful PDB symbol download for ntdll at startup;
      otherwise the plugin cannot map syscall numbers to function
      names
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.unhooked_system_calls")


if "malware.direct_system_calls" in PLUGIN_MAP:

    @mcp.tool()
    def windows_malware_direct_system_calls() -> dict:
        """
        Run the malware.direct_system_calls plugin to detect the Direct
        System Call EDR-evasion technique: malware that issues a
        `syscall` instruction directly from a small, self-contained code
        block outside ntdll.dll/win32u.dll, bypassing the exported stubs
        (and any userland EDR hooks placed on them).

        Use this tool when the user asks about:
        - Direct syscalls / "Hell's Gate" / "Tartarus Gate"-style
          EDR-evasion techniques
        - Malware that bypasses userland API hooking by calling into the
          kernel directly instead of through ntdll's exported functions
        - Suspicious code blocks outside ntdll that still execute the
          `syscall` instruction

        Requires the optional `full` extra (`uv sync --extra full`) —
        the plugin hard-fails to import without `yara-python` or
        `yara-x`. The `capstone` disassembly library is also needed for
        the plugin to actually produce results (it logs a warning and
        returns no rows, not an error, if `capstone` is missing even
        with the extra installed). This tool is not registered at all
        without yara.

        Returns a dict with:
        - "plugin": "malware.direct_system_calls"
        - "results": list of dicts, one per detected direct-syscall code
          block, each containing:
            "Process": image name of the process (str),
            "PID": process ID (int),
            "Range": path of the memory region (VAD) containing the
              block, e.g. a mapped DLL or null for anonymous/private
              memory (str),
            "Address": virtual address of the code block (str, hex),
            "Disasm": disassembly of the matched instructions leading up
              to the syscall (str)

        Forensic context:
        - Legitimate code invokes syscalls only through ntdll.dll or
          win32u.dll's own exported stubs; a `syscall` instruction found
          anywhere else (private/anonymous memory, an unrelated DLL) is
          a very strong indicator of EDR-evasion tooling or a loader
          shellcode stage
        - "Range" being empty/null (anonymous memory, not backed by any
          mapped file) combined with a "Disasm" showing a `mov r10; mov
          eax, <n>; syscall; ret` pattern is the classic Hell's
          Gate/Halo's Gate signature
        - Combine with windows_malware_malfind (RWX/private VADs) and
          windows_malware_unhooked_system_calls (ntdll stub tampering)
          to build a full picture of the evasion technique in use
        - The "MsMpEng.exe" (Windows Defender) process is skipped by the
          plugin itself, since it legitimately performs similar
          techniques for its own hooking
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("malware.direct_system_calls")


if "malware.indirect_system_calls" in PLUGIN_MAP:

    @mcp.tool()
    def windows_malware_indirect_system_calls() -> dict:
        """
        Run the malware.indirect_system_calls plugin to detect the
        Indirect System Call EDR-evasion technique: malware that jumps
        (`jmp [address]`) into the middle of ntdll's own syscall stubs
        instead of calling the exported function directly, so the
        `syscall` instruction that actually executes lives inside
        legitimate ntdll code even though the call originated from
        attacker-controlled memory.

        Use this tool when the user asks about:
        - Indirect syscalls / "FreshyCalls" / "RecycledGate"-style
          EDR-evasion techniques
        - Malware that hides a syscall invocation by jumping into
          ntdll's own code rather than executing `syscall` from its own
          shellcode
        - Distinguishing indirect syscalls from the more obvious direct
          syscall technique (see windows_malware_direct_system_calls)

        Requires the optional `full` extra (`uv sync --extra full`) —
        the plugin hard-fails to import without `yara-python` or
        `yara-x`. The `capstone` disassembly library is also needed for
        the plugin to actually produce results (it logs a warning and
        returns no rows, not an error, if `capstone` is missing even
        with the extra installed). This tool is not registered at all
        without yara.

        Returns a dict with:
        - "plugin": "malware.indirect_system_calls"
        - "results": list of dicts, one per detected indirect-syscall
          code block, each containing:
            "Process": image name of the process (str),
            "PID": process ID (int),
            "Range": path of the memory region (VAD) containing the
              jump block, e.g. a mapped DLL or null for anonymous
              memory (str),
            "Address": virtual address of the `jmp` code block (str,
              hex),
            "Disasm": disassembly of the matched instructions leading up
              to the jump (str)

        Forensic context:
        - Unlike the direct technique, the actual `syscall` instruction
          here executes inside legitimate ntdll.dll code — what's
          anomalous is the `jmp [address]` gadget in attacker-controlled
          memory that jumps *into* ntdll mid-function to reach it,
          skipping the function's own prologue and any hooks placed
          there
        - "Range" being empty/null (anonymous memory) for the jump block
          itself, jumping into a target inside ntdll.dll, is the
          signature to look for
        - Combine with windows_malware_direct_system_calls (the more
          overt sibling technique) and windows_malware_malfind to build
          a full picture of the evasion tooling in use
        - The "MsMpEng.exe" (Windows Defender) process is skipped by the
          plugin itself, since it legitimately performs similar
          techniques for its own hooking
        - The memory image is read-only evidence; this tool does not
          modify it
        """
        return session.run_plugin("malware.indirect_system_calls")


@mcp.tool()
def windows_malware_svcdiff() -> dict:
    """
    Run the malware.svcdiff plugin to diff windows_svclist (linked-list
    walk) against windows_svcscan (signature scan) and report only the
    services present in one view but missing from the other — a classic
    DKOM / service-hiding rootkit indicator.

    Use this tool when the user asks about:
    - Hidden Windows services
    - DKOM tampering of the SCM service record list
    - Discrepancy between linked-list and pool-scan service views
    - Quick triage for suspected service-hiding rootkits

    Returns a dict with:
    - "plugin": "malware.svcdiff"
    - "results": list of dicts using the same schema as windows_svcscan
      (Offset, Order, PID, Start, State, Type, Name, Display, Binary,
      Binary (Registry), Dll), but limited to entries that disagree
      between the two enumeration methods.

    Forensic context:
    - Note: requires Windows 10 build 15063+ on a 64-bit image (same
      restriction as windows_svclist). On older / 32-bit images the
      plugin returns an empty result and logs a warning
    - Any non-empty row is high-signal: the service exists in memory
      but has been unlinked from SCM's list. Investigate the Binary
      and Dll columns immediately
    - Save the manual diff cycle: skips the need to run windows_svclist
      and windows_svcscan separately and compare Names by hand
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.svcdiff")


@mcp.tool()
def windows_malware_processghosting() -> dict:
    """
    Run the malware.processghosting plugin to detect processes created
    via the Process Ghosting technique — where the source executable
    is marked for deletion (or its FILE_OBJECT zeroed / mapped with
    DeleteOnClose VAD) before the process image section is created,
    so on-disk forensics finds nothing while the process runs.

    Use this tool when the user asks about:
    - Process Ghosting detection (MITRE ATT&CK T1620)
    - Processes whose backing executable no longer exists on disk
    - Anti-forensics techniques that delete the EXE before execution
    - Suspicious processes whose Path is unrecoverable

    Returns a dict with:
    - "plugin": "malware.processghosting"
    - "results": list of dicts (one row per ghosted process):
        "PID": process ID (int),
        "Process": process image name (str),
        "Base": base address of the process image (str, hex),
        "FILE_OBJECT": _FILE_OBJECT pointer for the EXE; 0 indicates a
          ghosting indicator (str, hex),
        "DeletePending": 1 if the file's DeletePending flag is set
          (a textbook ghosting signature) (int),
        "DeleteOnClose": 1 if the section was opened with
          FILE_DELETE_ON_CLOSE (an alternative ghosting signature) (int),
        "Path": last known on-disk path of the EXE (str)

    Forensic context:
    - Process Ghosting first publicized by Elastic in 2021. Any
      non-empty result is high-signal: legitimate processes do not
      run from images marked DeletePending or DeleteOnClose
    - Pair with windows_pslist (process is alive) and
      windows_malware_pebmasquerade (the PEB may also be spoofed to
      hide the original ghost name)
    - Use windows_pedump(base=Base, pid=PID) to recover the in-memory
      executable, since the on-disk version is gone
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.processghosting")


@mcp.tool()
def windows_malware_hollowprocesses(pid: int = 0) -> dict:
    """
    Run the malware.hollowprocesses plugin to detect Process Hollowing —
    where a legitimate process is created, its image base unmapped, and
    replaced with malicious code that runs under the original name.

    Use this tool when the user asks about:
    - Process hollowing detection (MITRE ATT&CK T1055.012)
    - Processes whose ImageBaseAddress no longer matches the original
      executable
    - Identifying svchost.exe / explorer.exe / lsass.exe etc. that have
      been hijacked
    - VAD-protection inconsistencies on a process's main image region

    Arguments:
    - pid (optional, default 0): restrict the scan to a single process.
      0 inspects every process.

    Returns a dict with:
    - "plugin": "malware.hollowprocesses"
    - "results": list of dicts (one row per suspect process):
        "PID": process ID (int),
        "Process": process image name (str),
        "Notes": human-readable explanation of why the process was
          flagged (e.g. ImageBase mismatch, VAD protection anomaly,
          missing on-disk backing) (str)

    Forensic context:
    - Hollowing creates a process with one image then swaps it for
      another, so the on-disk EXE name is innocuous but the running
      code is malicious. Look closely at any process flagged here
    - Pair with windows_malware_pebmasquerade (PEB spoofing often
      accompanies hollowing) and windows_pedump(base=..., pid=PID) to
      recover the actually-running PE for static analysis
    - Suspended-thread + hollowing is a classic combo: the thread is
      created suspended, the image swapped, then the thread resumed.
      Check windows_suspended_threads for the same PID
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.hollowprocesses", pid=pid)


@mcp.tool()
def windows_malware_pebmasquerade(pid: int = 0) -> dict:
    """
    Run the malware.pebmasquerade plugin to detect PEB Masquerading —
    where a process spoofs its PEB ImageFilePath / CommandLine fields
    to disguise itself as a legitimate executable.

    Use this tool when the user asks about:
    - PEB masquerading / PEB spoofing detection
    - Discrepancies between EPROCESS.ImageFileName and PEB.ImageFilePath
    - Processes whose command line was rewritten after launch
    - Anti-forensic process renaming techniques

    Arguments:
    - pid (optional, default 0): restrict the scan to a single process.

    Returns a dict with:
    - "plugin": "malware.pebmasquerade"
    - "results": list of dicts (one row per process):
        "PID": process ID (int),
        "EPROCESS_ImageFileName": short image name from EPROCESS (str),
        "EPROCESS_SeAudit_ImageFileName": full path from SeAuditProcess
          information (str),
        "PEB_ImageFilePath": process's own PEB-reported image path (str),
        "PEB_ImageFilePath_Spoofed": True if PEB image path disagrees
          with kernel-side records (bool),
        "PEB_CommandLine_Spoofed": True if the PEB command line was
          rewritten after process creation (bool)

    Forensic context:
    - Either Spoofed flag = True is high-signal: the process is lying
      about what it is. Common with hollowing or doppelganging
    - Many EDR rules and analyst tooling read the PEB; spoofing it
      defeats those checks while EPROCESS.ImageFileName (kernel-only)
      still tells the truth — which is exactly what this plugin
      compares
    - Pair with windows_malware_hollowprocesses (often co-occurs) and
      windows_pedump on the suspect PID to capture the actually-running
      image for static analysis
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.pebmasquerade", pid=pid)


@mcp.tool()
def windows_malware_suspicious_threads(pid: int = 0) -> dict:
    """
    Run the malware.suspicious_threads plugin to surface userland
    threads whose start address falls inside an anomalous VAD —
    typically a non-image, non-mapped, RWX region — which is the
    canonical signature of code injection.

    Use this tool when the user asks about:
    - Code-injection detection (CreateRemoteThread, NtQueueApcThread,
      etc.)
    - Threads running from unbacked / non-image memory
    - Suspicious thread analysis beyond what windows_threads surfaces
    - Quick triage for any process suspected of containing shellcode

    Arguments:
    - pid (optional, default 0): restrict to one process. 0 inspects
      every userland process.

    Returns a dict with:
    - "plugin": "malware.suspicious_threads"
    - "results": list of dicts (one row per anomalous thread):
        "Process": process image name (str),
        "PID": process ID (int),
        "TID": thread ID (int),
        "Context": thread context summary (str),
        "Address": thread start address (str, hex),
        "VAD Path": path of the VAD backing the start address, or
          "" / None when the VAD has no associated file (the
          high-signal case) (str),
        "Note": human-readable explanation of why the thread was
          flagged (str)

    Forensic context:
    - Rows where ``VAD Path`` is empty / None mean the thread is
      executing from memory not backed by any module — almost
      certainly injected shellcode
    - Pair with windows_malware_malfind on the same PID to see the
      injected memory region's bytes, then windows_pedump to recover
      it for offline analysis
    - Cross-reference with windows_suspended_threads: if the
      suspicious thread is also suspended, the injection is
      mid-staging (Process Hollowing or remote thread injection
      paused before resume)
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.suspicious_threads", pid=pid)


@mcp.tool()
def windows_malware_psxview(physical_offsets: bool = False) -> dict:
    """
    Run the malware.psxview plugin (the canonical psxview, "The Art of
    Memory Forensics" cross-view technique) to compare four independent
    process-enumeration sources and surface processes that show up in
    some but not others — a generalized hidden-process detector.

    Use this tool when the user asks about:
    - Hidden / unlinked process detection
    - Comparing pslist vs psscan vs thread-scan vs CSRSS handles
    - Cross-view rootkit detection (DKOM, EPROCESS unlinking)
    - Quick triage when something is suspected of hiding from pslist

    Arguments:
    - physical_offsets (optional, default False): if True, the Offset
      column reports physical addresses (matches pool-scan results);
      default reports virtual addresses.

    Returns a dict with:
    - "plugin": "malware.psxview"
    - "results": list of dicts, each containing:
        "Offset(Virtual)" / "Offset(Physical)": process offset (str, hex)
          (column name varies based on physical_offsets argument),
        "Name": process image name (str),
        "PID": process ID (int),
        "pslist": True if visible to active-list walk (bool),
        "psscan": True if visible to pool-tag scan (bool),
        "thrdscan": True if visible via owning-thread enumeration (bool),
        "csrss": True if registered in csrss.exe handle table (bool),
        "Exit Time": process exit timestamp, or empty for live procs (str)

    Forensic context:
    - The classic "True / True / True / True / empty Exit Time" row is a
      legitimate live process. Any False in the first four columns on a
      live process (no Exit Time) deserves investigation
    - psscan-only (True for psscan, False elsewhere) ⇒ DKOM-unlinked
      process — high-signal rootkit
    - thrdscan-only (True for thrdscan only) ⇒ pool-scrubbed EPROCESS
      with surviving threads — also high-signal
    - csrss-only ⇒ a live process whose EPROCESS has been deeply
      scrubbed but is still tracked by the windowing subsystem
    - Pair with windows_pslist / windows_psscan for raw enumeration
      detail when this tool flags a discrepancy
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("malware.psxview", physical_offsets=physical_offsets)


@mcp.tool()
def windows_consoles(no_registry: bool = False) -> dict:
    """
    Run the consoles plugin to recover console host (conhost.exe /
    csrss.exe legacy) artifacts from memory: scrollback screen buffers,
    typed command history, alias data, and connected process info.

    Use this tool when the user asks about:
    - What commands a user typed in cmd.exe / PowerShell at the console
    - Console screen buffer / scrollback contents (visible terminal text)
    - History of commands recovered from a memory image
    - Reconstructing an interactive shell session that the user closed
    - Forensic IR scenarios where the suspect typed but logs were wiped

    Arguments:
    - no_registry (optional, default False): skip the registry-based
      console signature lookup. Set True for a faster scan when the
      registry hive is unreadable; may miss some console types on
      newer Windows builds.

    Returns a dict with:
    - "plugin": "consoles"
    - "results": list of dicts (multiple rows per console — one per
      property emitted by the parser):
        "PID": process ID hosting the console (typically conhost.exe or
          csrss.exe; on older Windows the cmd.exe PID itself) (int),
        "Process": image name (str),
        "ConsoleInfo": offset of the _CONSOLE_INFORMATION structure
          (str, hex),
        "Property": property name such as Title, OriginalTitle,
          ScreenBuffer, History, Alias (str),
        "Address": virtual address of the property's data (str, hex),
        "Data": the recovered string content (str)

    Forensic context:
    - Console artifacts persist after the shell window is closed, until
      the host process is reaped; one of the highest-fidelity records
      of attacker keystrokes during interactive sessions
    - Look for ``Property == "History"`` rows for the literal command
      history; ``Property == "ScreenBuffer"`` reveals the visible
      terminal output the user saw (commands + output)
    - Cross-reference recovered commands against windows_cmdline (the
      command line that started a process) and windows_pslist
      (parent/child) to confirm execution chains
    - Use windows_cmdscan for a focused command-history-only view
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("consoles", no_registry=no_registry)


@mcp.tool()
def windows_cmdscan(no_registry: bool = False) -> dict:
    """
    Run the cmdscan plugin to extract typed command history from the
    Console Host. This is the focused subset of windows_consoles — only
    the History property rows.

    Use this tool when the user asks about:
    - Specifically the commands a user typed (not screen output)
    - cmd.exe / PowerShell command history recovered from memory
    - Reconstructing a typed-command timeline for incident response
    - Quick "what did they run?" question without full console scrollback

    Arguments:
    - no_registry (optional, default False): same as windows_consoles —
      skip registry-based console lookup if needed.

    Returns a dict with the same schema as windows_consoles
    (PID, Process, ConsoleInfo, Property, Address, Data) but limited to
    history-related properties. The Data column contains each typed
    command line as the user entered it.

    Forensic context:
    - When you only need the "what did they type" answer, this is faster
      and cleaner than parsing the full windows_consoles output
    - Pair with windows_pslist creation timestamps to determine
      *approximately when* each command was issued (the cmd that ran
      typed-command appears in pslist as a child of cmd.exe / pwsh.exe)
    - Empty result while windows_consoles also returns no conhost.exe
      rows is expected on systems whose interactive shells ran inside
      csrss.exe (older Windows / no conhost split)
    - The memory image is read-only evidence; this tool does not modify it
    """
    return session.run_plugin("cmdscan", no_registry=no_registry)


if __name__ == "__main__":
    mcp.run()
