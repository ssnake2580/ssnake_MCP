# Interface and write-path inspection for the measured configuration

The installed default environment exposes 87 MCP tools: 79 canonical Windows
plugins, seven correlation tools, and integrity verification. The captured schemas
contain 73 zero-argument tools and 14 parameterized tools. Tool inventory and the
source hashes used for each trial are retained in private artifacts.

## Dispatch and binding

- `mcp_server.py` registers dedicated functions with FastMCP. In the observed
  inventory, 86 functions call `session.run_plugin`; `verify_image_integrity`
  calls the session's image-hashing method. The internal `run_plugin` method is
  not itself an exposed generic MCP tool.
- MCP 1.27.0 resolves the tool name in `ToolManager.call_tool`, then invokes
  `call_fn_with_arg_validation` through its `Tool` wrapper. Validation uses
  Pydantic models. The measured extra-field cases are ignored, not rejected.
- `Session` takes its image from startup configuration and sets the image-layer
  location. Exposed analysis functions do not supply a replacement image location.
- Volatility 2.28.0 `framework/layers/physical.py`, `FileLayer._file`, opens the
  backing image with mode `rb`. `Session._verify_read_only` is a readability check
  plus a warning for writable images, not an OS permission change.

## File creation

- `plugins/file.py:run_dumpfiles` and `plugins/module.py:run_pedump` are the two
  wrappers that explicitly pass `session.file_handler` to the common runner.
  Their exposed arguments select process/address/filter parameters, not the
  output directory or arbitrary output filename.
- The upstream dump plugins construct output names; dumpfiles uses a fixed
  prefix and `ntpath.basename` for the recovered name. PEDump constructs its
  process output name from numeric addresses and the PID.
- `FileHandlerInterface.preferred_filename` checks type and the host's native
  path separator; its separate sanitizer is not automatically equivalent to
  universal path validation. Component tests therefore exercise the actual
  handler on the stated host rather than assuming cross-platform behavior.
- `plugins/_file_handler.py` joins the configured directory with the preferred
  name, appends a numeric suffix while the destination exists, and opens the
  selected derivative with `wb`. This is a real write path and must be included
  in the integrity evaluation. Normal extraction and redirection tests exercise
  both dump wrappers; the collision behavior also receives a component test.
- `Session.save_config` writes the separate `.vol3cfg.json` sidecar. Volatility
  also writes runtime caches. These expected writes are distinguished from
  changes to the evidence image and protected pre-existing outputs.

## Limits and tool-specific exception

`windows_strings(strings_file)` accepts a local auxiliary input path. Its wrapper
resolves that path as a file URI and passes it as a strings input to Volatility;
it does not rebind the image. This read capability means that fixed-image binding
is not a general filesystem read sandbox. Confidentiality is outside this study.

No claim is made that every analysis plugin or every possible argument was
executed. The tests cover shared integrity boundaries and the exposed derivative
write paths for this dependency set. Filesystem alias setup, concurrent host-side
path replacement, optional plugins, native-library bugs, and Windows-host path
semantics require separate conditions; they are not silently included in the core
adversary's powers or inferred from macOS observations.
