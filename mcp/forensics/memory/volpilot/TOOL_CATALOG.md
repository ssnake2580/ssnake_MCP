# Volatility3 Windows Plugin Catalog

Volatility3 v2.28.0 ships exactly **105** Windows plugin classes — confirmed
by running `uvx --from 'volatility3[full]==2.28.0' vol -h` and counting
every `windows.*` entry in the plugin list (a prior version of this
document undercounted this as 91, then as 98; see the note at the end of
the [Deprecated Alias Audit](#deprecated-alias-audit) section for how those
earlier passes missed entries). Of these 105:

- **88 are canonical plugins this server wraps** with a dedicated MCP tool.
- **17 are deprecated `PluginRenameClass` wrappers** that redirect to one
  of those 88 canonical paths and are intentionally not wrapped again
  (see the audit table below).
- **0 have no MCP tool** — every canonical `windows.*` plugin class is now
  wrapped, including the `mftscan.py` trio (`MFTScan`, `ADS`,
  `ResidentData`) that was the last gap.

These figures (88 + 17 + 0 = 105) were verified directly from code by
importing `plugins.PLUGIN_MAP` (with the `full` extra installed) and
diffing its keys against the full `vol -h` plugin list — not estimated
from prose.

Of the 88 wrapped canonical plugins, 9 additionally require a third-party
library (YARA, PyCryptodome) not in the default dependency set. They are
only *usable* when the optional `full` extra is installed (`pip install
.[full]`, or `uv sync --extra full`) — the wrapper modules
(`plugins/registry.py`, `plugins/memory.py`, `plugins/file.py`,
`plugins/malware.py`) guard the import with `try/except ImportError` and
only add the entry to `PLUGIN_MAP` when the dependency resolves:

| Plugin | Requires | MCP tool | Registered in `mcp_server.py`? |
|---|---|---|---|
| `windows.registry.hashdump` | pycryptodome | `windows_registry_hashdump` | **Yes** |
| `windows.registry.lsadump` | pycryptodome | `windows_registry_lsadump` | **Yes** |
| `windows.registry.cachedump` | pycryptodome | `windows_registry_cachedump` | **Yes** |
| `windows.vadyarascan` | yara-python or yara-x | `windows_vadyarascan(yara_rule, pid=0)` | **Yes** |
| `windows.mftscan.MFTScan` | yara-python or yara-x | `windows_mftscan` | **Yes** |
| `windows.mftscan.ADS` | yara-python or yara-x | `windows_mftscan_ads` | **Yes** |
| `windows.mftscan.ResidentData` | yara-python or yara-x | `windows_mftscan_residentdata` | **Yes** |
| `windows.malware.direct_system_calls` | yara-python or yara-x (+ capstone recommended) | `windows_malware_direct_system_calls` | **Yes** |
| `windows.malware.indirect_system_calls` | yara-python or yara-x (+ capstone recommended) | `windows_malware_indirect_system_calls` | **Yes** |

`windows_malware_skeleton_key_check` is a special case: it's always
registered and its primary (PDB-based) detection works without any extra
dependency, but its export-table fallback silently skips (returns no
data, not an error) when `capstone` is missing. `windows_malware_{direct,indirect}_system_calls`
have a similar soft dependency on `capstone`: they're registered and
callable once `yara-python`/`yara-x` resolves, but the plugin itself logs
a warning and returns no rows (not an error) if `capstone` is also
missing.

**"Wrapped in `plugins/`" and "registered as a callable MCP tool" are two
different bars, and this catalog previously conflated them.** `plugins/`
wraps a volatility3 plugin and adds a runner function to the `PLUGIN_MAP`
dict; `mcp_server.py` is a separate, hand-written `@mcp.tool()` function
per tool that an MCP client (Claude) can actually invoke — being in
`PLUGIN_MAP` does not by itself make a tool callable. **All 9 full-extra
plugins are now wrapped *and* registered** — each `@mcp.tool()` function
in `mcp_server.py` is conditional on the plugin's presence in
`PLUGIN_MAP`, so none of them appear in the tool list without the `full`
extra (no error, no crash), matching the intended behavior. This closes
the gap that used to exist here: at one point all 9 were wrapped in
`plugins/` but none had a corresponding `@mcp.tool()` function in
`mcp_server.py`, making them uncallable regardless of which extra was
installed.

See the [Deprecated Alias Audit](#deprecated-alias-audit) section
at the bottom for the full breakdown.

## Naming Convention

MCP tool names mirror the Volatility3 plugin name for easy identification.
Format: `windows_{plugin_name}` (e.g., `windows.pslist` -> `windows_pslist`).
Sub-namespace plugins follow `windows_{namespace}_{name}`:
- `windows.registry.*` -> `windows_registry_{name}`
- `windows.malware.*` -> `windows_malware_{name}`

## OS Compatibility Notes

Most plugins work across the full Windows range supported by volatility3.
The table below flags only those with **hard restrictions** (refuses to
produce data on incompatible images), **implicit OS dependencies**
(structurally runs but only yields data above a threshold version), or
**version-aware adapters** worth knowing about for output interpretation.

### Hard restrictions

| MCP Tool | Constraint | Behaviour on incompatible images |
|---|---|---|
| `windows_svclist` | Win10 build 15063+ on **64-bit** only | Logs `"This plugin only supports Windows 10 version 15063+ 64bit"` and returns an empty list |
| `windows_malware_svcdiff` | Same as `windows_svclist` (depends on it) | Same as above |
| `windows_malware_processghosting` | Win10+ only (requires `_EPROCESS.ImageFilePointer`, introduced in Win10) | Logs `"ImageFilePointer checks are only supported on Windows 10+ builds"` and returns an empty list |
| `windows_virtmap` | Kernel PDB must expose `MiVisibleState` or `MiSystemVaType` | Some builds (confirmed on a Win7 SP1 x64 image) have neither; the upstream plugin raises `SymbolError` uncaught rather than returning empty like the rows above — caught in `plugins/memory.py` and translated into an empty list |

### Implicit OS dependencies

| MCP Tool | When data is available |
|---|---|
| `windows_consoles`, `windows_cmdscan` | Requires `conhost.exe` to be running. On pre-Win7 / Win7 RTM where consoles ran inside `csrss.exe` there is no `conhost.exe` → returns empty (`"No conhost.exe processes found"`). |
| `windows_registry_amcache` | The `AmCache.hve` hive only populates application/driver records from **Windows 8 onward**. Win7 typically returns 0 rows. |

### Version-aware adapters (works everywhere, output may vary)

| MCP Tool | Adaptation notes |
|---|---|
| `windows_shimcachemem` | Format differs between Win7 and Win8+. The `Last Update` and `Exec Flag` columns populate only on 32-bit Win7 / Win8 / Win8.1; elsewhere they are `None`. |
| `windows_netscan` | Different parser branch on Win10 build 18363+ (introduces a new `_TCP_LISTENER` layout). |
| `windows_svcscan` | Adapts the service record signature across Win8+, Win10 builds 16299 / 17763 / 18362 / 19041 / 25398. Functional across the entire range. |
| `windows_timers`, `windows_poolscanner` | Different scan path on Win8+ vs older. |
| `windows_windowstations` | Adapts across Win8 and many Win10 builds (10586 / 15063 / 16299 / 17134 / 17763 / 18362 / 19041 / 19577). |

For everything else, no version gating is applied; the underlying
volatility3 plugin handles structural variation transparently or the
artifact is universal across supported Windows versions.

## Known Limitations (backlog, not yet fixed)

**Unbounded memory growth across a long session.** `run_plugin()` in
`plugins/_common.py` reuses one `Session`-owned `Context` for every
tool call, but re-runs automagic from scratch each time — this
constructs a brand-new kernel translation layer and symbol table per
call (auto-uniquely named, so it never collides like the hive-layer
bug did) and never frees the previous call's copies. Measured directly
against a real 2GB memory image: RSS grew from ~39MB baseline to
5.1GB after 30 of 45 sequential distinct plugin calls in one session,
roughly monotonically (~100–370MB per call). Not a correctness or
security issue — the server produces correct results throughout — but
a long real session (many tool calls over an extended conversation)
could accumulate enough memory to slow down or exhaust the host, or
get the process OOM-killed. A fix along the same lines as the hive-
layer cleanup (`_purge_stale_hive_layers`) is plausible — snapshot and
remove each call's newly-created layers/symbol tables once its results
have been fully extracted — but is a larger, moderate-risk change
since it touches the `run_plugin()`/`parse_treegrid()` calling
convention used by all ~88 plugin wrappers, and needs care not to
free a layer that `LayerData` serialization (see `_common.py`) still
needs to read from at parse time. Deliberately deprioritized: no known
issue in normal (shorter) sessions, and the fix carries real regression
risk for a problem that's a resource concern, not a crash or data-
correctness bug.

---

## Process Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.pslist` | `windows_pslist` | List processes via active process linked list |
| `windows.psscan` | `windows_psscan` | Scan for processes by pool tag (finds hidden) |
| `windows.pstree` | `windows_pstree` | Process tree with parent-child hierarchy |
| `windows.cmdline` | `windows_cmdline` | List process command line arguments |
| `windows.sessions` | `windows_sessions` | List processes with session information |
| `windows.getsids` | `windows_getsids` | Print SIDs owning each process |
| `windows.privileges` | `windows_privileges` | List process token privileges |
| `windows.envars` | `windows_envars` | Display process environment variables |
| `windows.handles` | `windows_handles` | List process open handles |
| `windows.joblinks` | `windows_joblinks` | Print process job link information |
| `windows.thrdscan` | `windows_thrdscan` | Scan for Windows threads |
| `windows.threads` | `windows_threads` | List per-process threads via thread list walk |

## Memory Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.vadinfo` | `windows_vadinfo` | List process memory ranges (VAD) |
| `windows.vadwalk` | `windows_vadwalk` | Walk the VAD tree |
| `windows.memmap` | `windows_memmap` | Print the memory map |
| `windows.virtmap` | `windows_virtmap` | List virtual mapped sections |
| `windows.strings` | `windows_strings` | Map strings output to processes |
| `windows.shimcachemem` | `windows_shimcachemem` | Recover Shimcache / AppCompatCache from kernel memory (evidence of execution) |
| `windows.vadregexscan` | `windows_vadregexscan(pattern, maxsize=128)` | Scan every process VAD for a regex (parameterized) |
| `windows.vadyarascan` † | `windows_vadyarascan(yara_rule, pid=0)` | Scan every process VAD with a Yara rule (parameterized) |

## Module / DLL Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.dlllist` | `windows_dlllist` | List loaded modules per process |
| `windows.modules` | `windows_modules` | List loaded kernel modules |
| `windows.modscan` | `windows_modscan` | Scan for kernel modules by pool tag |
| `windows.verinfo` | `windows_verinfo` | List version information from PE files |
| `windows.iat` | `windows_iat` | Extract Import Address Table |
| `windows.pe_symbols` | `windows_pe_symbols(source, module, symbols="", addresses="")` | Resolve PE symbol names <-> addresses (parameterized) |
| `windows.pedump` | `windows_pedump(base, pid=0, kernel_module=False)` | Reconstruct a PE at base to VOL_DUMP_DIR (parameterized) |

## Network Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.netscan` | `windows_netscan` | Scan for network objects by pool tag |
| `windows.netstat` | `windows_netstat` | Traverse network tracking structures |

## Kernel / Driver Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.bigpools` | `windows_bigpools` | List big page pool allocations |
| `windows.callbacks` | `windows_callbacks` | List kernel callbacks and notification routines |
| `windows.driverscan` | `windows_driverscan` | Scan for driver objects |
| `windows.driverirp` | `windows_driverirp` | List IRPs for drivers |
| `windows.devicetree` | `windows_devicetree` | List device tree by drivers |
| `windows.ssdt` | `windows_ssdt` | List system call table |
| `windows.poolscanner` | `windows_poolscanner` | Generic pool scanner |
| `windows.orphan_kernel_threads` | `windows_orphan_kernel_threads` | Detect kernel threads not mapped to any module (rootkit indicator) |
| `windows.kpcrs` | `windows_kpcrs` | List per-CPU KPCR and PRCB offsets |
| `windows.unloadedmodules` | `windows_unloadedmodules` | List recently-unloaded kernel drivers from MmUnloadedDrivers |
| `windows.timers` | `windows_timers` | Enumerate kernel DPC timers and resolve their routine addresses |
| `windows.debugregisters` | `windows_debugregisters` | Dump per-thread DR0-DR3 hardware breakpoints (HW-hook rootkit indicator) |
| `windows.etwpatch` | `windows_etwpatch(pid=0)` | Detect ETW stub tampering inside ntdll.dll (telemetry evasion) |

## File Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.filescan` | `windows_filescan` | Scan for file objects |
| `windows.dumpfiles` | `windows_dumpfiles(pid, filter, filter_ignore_case, virtaddr, physaddr)` | Dump cached file contents to VOL_DUMP_DIR (parameterized) |
| `windows.symlinkscan` | `windows_symlinkscan` | Scan for symbolic links |
| `windows.mutantscan` | `windows_mutantscan` | Scan for mutexes |
| `windows.mftscan.MFTScan` † | `windows_mftscan` | Recover raw $MFT FILE records from memory (deleted/unlinked file metadata) |
| `windows.mftscan.ADS` † | `windows_mftscan_ads` | Recover Alternate Data Stream records from raw MFT entries |
| `windows.mftscan.ResidentData` † | `windows_mftscan_residentdata` | Recover small file content stored resident inside the $MFT record |

## Registry Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.registry.hivelist` | `windows_registry_hivelist` | List registry hives |
| `windows.registry.hivescan` | `windows_registry_hivescan` | Scan for registry hives |
| `windows.registry.printkey` | `windows_registry_printkey` | Print registry keys and values |
| `windows.registry.userassist` | `windows_registry_userassist` | Print UserAssist registry data |
| `windows.registry.certificates` | `windows_registry_certificates` | List certificates from registry store |
| `windows.registry.scheduled_tasks` | `windows_registry_scheduled_tasks` | Decode Task Scheduler entries (persistence indicator) |
| `windows.registry.getcellroutine` | `windows_registry_getcellroutine` | Detect hives with hooked GetCellRoutine handler (registry rootkit) |
| `windows.registry.amcache` | `windows_registry_amcache` | Decode AmCache.hve application execution records (SHA1, timestamps) |
| `windows.registry.hashdump` † | `windows_registry_hashdump` | Dump LM/NT password hashes from SAM + SYSTEM hives |
| `windows.registry.lsadump` † | `windows_registry_lsadump` | Decrypt and dump LSA secrets from SECURITY + SYSTEM hives |
| `windows.registry.cachedump` † | `windows_registry_cachedump` | Decrypt cached domain-logon credentials (MSCACHE) |

## Service Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.svcscan` | `windows_svcscan` | Enumerate Windows services by scanning services.exe |
| `windows.svclist` | `windows_svclist` | List services via services.exe linked list (Win10 15063+ x64 only) |

## Desktop / GUI

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.windowstations` | `windows_windowstations` | Enumerate tagWINDOWSTATION objects per session |
| `windows.desktops` | `windows_desktops` | Walk per-WindowStation desktop list with attached threads |
| `windows.deskscan` | `windows_deskscan` | Pool-tag scan for tagDESKTOP objects (finds hidden/unlinked) |
| `windows.windows` | `windows_windows` | Enumerate GUI window objects per Desktop (with WindowProc address) |

## Console / Shell

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.consoles` | `windows_consoles(no_registry=False)` | Recover console host buffers + command history |
| `windows.cmdscan` | `windows_cmdscan(no_registry=False)` | Focused command-history extraction from console hosts |

## System Information

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.info` | `windows_info` | OS version, architecture, kernel details |
| `windows.statistics` | `windows_statistics` | Memory space statistics |
| `windows.crashinfo` | `windows_crashinfo` | Windows crash dump information |

## Security / Integrity

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.mbrscan` | `windows_mbrscan` | Scan for Master Boot Records |
| `windows.truecrypt` | `windows_truecrypt` | Find TrueCrypt cached passphrases |
| `windows.getservicesids` | `windows_getservicesids` | List process token service SIDs |
| `windows.suspended_threads` | `windows_suspended_threads` | Detect never-resumed suspended threads (hollowing / EDR evasion) |

## Malware Detection

Canonical `windows.malware.*` plugins for advanced rootkit / injection /
evasion detection. All 10 legacy `windows.*` aliases that redirect into
this namespace are deprecated `PluginRenameClass` wrappers excluded from
this server (see [Deprecated Alias Audit](#deprecated-alias-audit)).

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.malware.drivermodule` | `windows_malware_drivermodule` | Detect hidden driver modules |
| `windows.malware.ldrmodules` | `windows_malware_ldrmodules` | List loaded modules (detects unlinked DLLs) |
| `windows.malware.malfind` | `windows_malware_malfind` | Detect potentially injected code in process memory |
| `windows.malware.skeleton_key_check` | `windows_malware_skeleton_key_check` | Detect Skeleton Key malware |
| `windows.malware.unhooked_system_calls` | `windows_malware_unhooked_system_calls` | Detect ntdll syscall stub divergence (EDR/unhooking malware) |
| `windows.malware.svcdiff` | `windows_malware_svcdiff` | Diff svclist vs svcscan to surface hidden services (Win10 15063+ x64) |
| `windows.malware.processghosting` | `windows_malware_processghosting` | Detect Process Ghosting (DeletePending / DeleteOnClose images) |
| `windows.malware.hollowprocesses` | `windows_malware_hollowprocesses(pid=0)` | Detect Process Hollowing (image-base mismatch / VAD anomalies) |
| `windows.malware.pebmasquerade` | `windows_malware_pebmasquerade(pid=0)` | Detect PEB ImageFilePath / CommandLine spoofing |
| `windows.malware.direct_system_calls` † | `windows_malware_direct_system_calls` | Detect direct/inlined syscall stubs (EDR-hook evasion) |
| `windows.malware.indirect_system_calls` † | `windows_malware_indirect_system_calls` | Detect indirect syscall stubs (EDR-hook evasion) |
| `windows.malware.suspicious_threads` | `windows_malware_suspicious_threads(pid=0)` | Flag userland threads starting in non-image / RWX VADs (injection) |
| `windows.malware.psxview` | `windows_malware_psxview(physical_offsets=False)` | Cross-view process enumeration (pslist / psscan / thrdscan / csrss) |

† Requires the optional `full` extra (`pip install .[full]`); without it,
not even wrapped in `plugins/`, let alone registered as an MCP tool. All
9 full-extra plugins across this document (registry secrets, vadyarascan,
the mftscan family, and these two) are now registered as real
`@mcp.tool()` functions once the extra is present — see the
wrapped-vs-registered note near the top of this document for how that
was verified.

---

## Cross-plugin Correlation Tools

Compound tools that combine results from multiple plugins using
deterministic Python logic on the server side. These guarantee
reproducibility and eliminate comparison errors that arise from
natural-language diffing. Cached plugin results are reused at zero cost.

| MCP Tool Name | Description | Plugins Used |
|---|---|---|
| `detect_hidden_processes` | Compare pslist (linked-list walk) vs psscan (pool-tag scan) to surface processes hidden via DKOM | pslist, psscan |
| `detect_process_anomalies` | Rule-based detection of unexpected parent-child relationships, name masquerading (typosquatting), singleton violations, and Session 0 violations | pslist |
| `triage_process(pid)` | Collect cmdline, DLL list, handles, network connections, and malfind hits for a single PID in one call | cmdline, dlllist, handles, netscan, malfind |
| `detect_dll_injection(pid)` | Cross-reference ldrmodules (InLoad/InInit/InMem), malfind (RWX regions), and dlllist to detect DLL injection or unlinking | ldrmodules, malfind, dlllist |
| `network_process_correlation` | Join netscan connections with pslist process info and cmdline for full network-to-process-to-command attribution | netscan, pslist, cmdline |
| `detect_service_tampering` | Compare svcscan (pool scan) vs svclist (SCM linked list) to detect unlinked service records; includes malware.svcdiff output. Requires Win10 15063+ x64 for full comparison | svcscan, svclist, malware.svcdiff |
| `build_timeline` | Merge timestamps from process lifecycle (pslist/psscan), network connections (netscan), execution evidence (shimcachemem), and user launches (registry.userassist) into a single chronological sequence | pslist, psscan, netscan, shimcachemem, registry.userassist |

---

## Deprecated Alias Audit

Volatility3 v2.28.0 registers exactly **105** Windows plugin classes in
total, confirmed by counting every `windows.*` entry printed by
`uvx --from 'volatility3[full]==2.28.0' vol -h` (this catalog's own
class-discovery pass had been wrong twice before — see the note below —
so this count now comes from volatility3's own plugin listing, not a
`grep`/regex sweep of its source). **17** of these are `PluginRenameClass`
wrappers, thin aliases that emit a deprecation warning and delegate to a
canonical implementation elsewhere in the plugin tree. Every canonical
target is already exposed as an MCP tool by this server, so the deprecated
aliases are intentionally excluded to avoid duplicate tools and runtime
warnings.

**Summary: 105 total = 88 canonical (wrapped in code) + 17 deprecated
aliases (excluded) + 0 canonical plugins not wrapped.** Every canonical
`windows.*` plugin class volatility3 v2.28.0 registers now has a wrapper
in `plugins/`, including the `mftscan.py` trio (`MFTScan`, `ADS`,
`ResidentData`) that was the last unwrapped gap. Of the 88 wrapped
canonical plugins, **79 are always registered** and **9 additionally
require the optional `full` extra** — **all 9 are now actually
registered** as real `@mcp.tool()` functions once it's installed (see
the dependency table earlier in this document). Every canonical plugin
this server wraps is now a callable MCP tool.

These figures were verified by cross-referencing two independent sources:
the full `windows.*` list from `vol -h` (105 entries) against the actual
`plugins.PLUGIN_MAP` dict in this repo's code (imported directly with the
`full` extra installed), matching every entry one for one with no
leftovers on either side.

**Note on these figures:** this catalog originally claimed 91 total (79
canonical + 12 deprecated), then 98. Both earlier passes were undercounts:
- 7 canonical plugins (`hashdump`, `lsadump`, `cachedump`, `vadyarascan`,
  `mftscan`, `direct_system_calls`, `indirect_system_calls`) were missing
  because they import `volatility3.plugins.yarascan` and/or
  `Crypto`/`Cryptodome`, both of which raise `ImportError` at module load
  time without their optional third-party library — a class-discovery pass
  run without those libraries (the default `uv sync` install) silently
  misses them.
- 5 deprecated aliases (`hashdump`, `lsadump`, `cachedump`,
  `direct_system_calls`, `indirect_system_calls` — each also has a
  top-level deprecated twin alongside its canonical implementation) were
  missed by the original manual audit.
- At least one plugin (`windows.malware.indirect_system_calls`) doesn't
  subclass `PluginInterface` directly — it subclasses `DirectSystemCalls`,
  which does — so a naive `grep`/regex sweep for
  `class X(...PluginInterface...)` misses it too. This is why the 105
  figure here comes from volatility3's own `framework.list_plugins()`
  output (via `vol -h`) rather than a source-code sweep.

Verified by actually running `plugins.PLUGIN_MAP` with the `full` extra
installed: 95 entries = 88 canonical plugins + 7 correlation (compound)
tools, matching the 95 `@mcp.tool()` functions actually defined in
`mcp_server.py` (88 canonical + 7 correlation). **Wrapped-in-`plugins/`
and registered-as-a-callable-MCP-tool now agree for every canonical
plugin** — the gap documented in earlier revisions of this file (where
this count and the `mcp_server.py` count diverged) has been closed.

| # | Deprecated Alias | Canonical Path (in PLUGIN_MAP) | Removal Date |
|---|---|---|---|
| 1 | `windows.drivermodule` | `windows.malware.drivermodule` | 2026-06-07 |
| 2 | `windows.direct_system_calls` | `windows.malware.direct_system_calls` | 2026-06-07 |
| 3 | `windows.hollowprocesses` | `windows.malware.hollowprocesses` | 2026-06-07 |
| 4 | `windows.indirect_system_calls` | `windows.malware.indirect_system_calls` | 2026-06-07 |
| 5 | `windows.ldrmodules` | `windows.malware.ldrmodules` | 2026-06-07 |
| 6 | `windows.malfind` | `windows.malware.malfind` | 2026-06-07 |
| 7 | `windows.processghosting` | `windows.malware.processghosting` | 2026-06-07 |
| 8 | `windows.psxview` | `windows.malware.psxview` | 2026-06-07 |
| 9 | `windows.skeleton_key_check` | `windows.malware.skeleton_key_check` | 2026-06-07 |
| 10 | `windows.suspicious_threads` | `windows.malware.suspicious_threads` | 2026-06-07 |
| 11 | `windows.svcdiff` | `windows.malware.svcdiff` | 2026-06-07 |
| 12 | `windows.unhooked_system_calls` | `windows.malware.unhooked_system_calls` | 2026-06-07 |
| 13 | `windows.amcache` | `windows.registry.amcache` | 2026-09-25 |
| 14 | `windows.cachedump` | `windows.registry.cachedump` | 2026-09-25 |
| 15 | `windows.hashdump` | `windows.registry.hashdump` | 2026-09-25 |
| 16 | `windows.lsadump` | `windows.registry.lsadump` | 2026-09-25 |
| 17 | `windows.scheduled_tasks` | `windows.registry.scheduled_tasks` | 2026-09-25 |

- **12 aliases** redirect into `windows.malware.*` (removal: 2026-06-07)
- **5 aliases** redirect into `windows.registry.*` (removal: 2026-09-25)
- **`removal_date` is not an enforced mechanism.** Confirmed by reading
  `volatility3/framework/deprecation.py`: `PluginRenameClass` only formats
  `removal_date` into the `FutureWarning` text ("will be removed in the
  first release after {removal_date}"). There is no code anywhere that
  compares it to the current date — the class stays fully present and
  functional in whatever release it ships in, deprecation warning and all,
  until a Volatility Foundation maintainer manually deletes the file in a
  *later* release. So even though 2026-06-07 has passed (today is
  2026-09-17), all 12 malware-namespace aliases are still present and
  working in the pinned v2.28.0 (released 2026-04-30, before that date) —
  nothing "expires" on its own. Whether a release newer than 2.28.0 has
  since actually deleted them is unconfirmed (not checked against upstream
  as of this writing).
- This server is forward-compatible either way: it only ever calls the
  canonical paths (`windows.malware.*`, `windows.registry.*`) directly and
  never imports the deprecated top-level aliases, so their eventual
  removal upstream — whenever it actually happens — requires no change
  here.
