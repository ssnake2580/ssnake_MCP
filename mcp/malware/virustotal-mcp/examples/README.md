# Query from a Python application

The [lookup example](lookup.py) launches `vt-mcp` as a subprocess using the official MCP Python SDK `2.1.1`. It exercises the four existing report tools without a provider-specific SDK or model account; it does not submit files. Version 0.8 also exposes submission/recovery tools described in the [analysis guide](../docs/analysis.md).

After obtaining the source archive or a source checkout, run from its root directory:

```bash
uv run --no-project --python 3.12 --default-index https://pypi.org/simple --with vt-mcp==0.8.3 \
  examples/lookup.py domain example.com
```

`--no-project` prevents the source checkout from replacing the selected PyPI distribution. The example reads the credential file at `~/.config/vt-mcp/token`; `--token-file` accepts an alternative path. It prints the structured tool result and exits with status 1 when the MCP tool reports an error. Other kinds are `file`, `url` and `ip`. `VTAI_BASE_URL` and `VTAI_TIMEOUT` work as described in the main README; change the base URL only for a trusted VTAI deployment.

Only disclose indicators you are authorized to share. URL input includes its query and fragment; use `domain` when sufficient. This example retrieves existing reports and cannot initiate analyses. A result of `not_found` means unknown, not safe.
