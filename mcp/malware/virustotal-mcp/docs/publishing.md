# Publishing the existing release to PyPI

The `PyPI` workflow verifies the already published GitHub release and can publish
its **exact wheel and sdist** as `vt-mcp`. It never builds or modifies them. This
workflow is separate from `Release`, so it can check a historical release from
the current `main` branch. Creating a GitHub release with `GITHUB_TOKEN` is not
used as an automatic trigger for another publishing workflow.

The default mode is **verify**. Version 0.8.2 is usable for that verification,
but is deliberately rejected by publish: its README still describes PyPI as
unpublished and contains relative consumer links. The first PyPI publication
needs a new reviewed release with a PyPI-ready README and metadata. Fixing those
files means a new version and new CI assets; never rebuild or overwrite 0.8.2.
Version 0.8.3 supplies the PyPI-ready README and metadata. Its GitHub release
is followed by a separate PyPI publication; check the public PyPI files and
hashes before announcing availability. Account setup alone does not establish
a completed publication.

## One-time ownership setup

A maintainer needs a PyPI account with a verified email and 2FA. For a first
release, configure a **pending Trusted Publisher** on PyPI with:

| Field | Value |
|---|---|
| PyPI project | `vt-mcp` |
| GitHub owner | `VirusTotal` |
| Repository | `virustotal-mcp` |
| Workflow filename | `pypi.yml` |
| Environment | Leave empty for this workflow |

For an existing project, its owner adds the same Trusted Publisher to that
project. GitHub access alone does not confer PyPI ownership. An organization
account on PyPI is optional; no long-lived PyPI API token or new VTAI credential
is needed. A pending publisher does not reserve a package name. The anonymous
JSON endpoints for `vt-mcp` and `virustotal-mcp` returned 404 on 8 September 2026;
404 does not prove that a name is available. Use the name already embedded in
the reviewed distribution: `vt-mcp`.

PyPI can receive Trusted Publishing uploads from a private GitHub repository.
**The package, its description, metadata and publishing provenance become
public on PyPI.** GitHub source/release links remain inaccessible to anonymous
visitors while the repository is private. The current PyPI GitHub validator
checks the owner identity and workflow, but does not verify `repository_id` or
require public repository visibility; this workflow additionally fixes the
repository to `VirusTotal/virustotal-mcp`, ID `1361592455`.

Sources: [PyPI first publication](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/),
[publisher setup](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
[GitHub identity validator](https://github.com/pypi/warehouse/blob/main/warehouse/oidc/models/github.py),
[PyPI account and package visibility](https://pypi.org/help/),
[2FA requirement](https://blog.pypi.org/posts/2024-01-01-2fa-enforced/).

## Package and Registry identity

The package README includes `mcp-name: io.github.VirusTotal/virustotal-mcp`.
The MCP Registry checks this published description to associate `vt-mcp` with
the corporate server name. Preserve the marker when editing the README.
Publish and reconcile the PyPI package before publishing a Registry manifest
that references it. The Registry publishing helper verifies the package files
against the annotated GitHub release's checksum manifest.

[Registry package ownership](https://modelcontextprotocol.io/registry/package-types).

## Run verification, then publish the reviewed bytes

Run **PyPI → Run workflow** on `main`, initially with `mode=verify`. Supply the
reviewed annotated tag, its full source SHA, the SHA256 of the `SHA256SUMS`
release asset, and the successful **Release run ID**. The tag already records
the exact CI run ID and the same manifest hash. Inputs are checked as data and
are not interpolated into shell commands.

Verification requires the fixed repository identity, a manual run on current
main, the release source on main's history, and the annotated tag bound to the
reviewed commit and manifest. The current publishing commit must also have a
successful push-main CI. It checks successful push-main CI for the release commit,
all returned jobs and the three Python versions; the Release run must match
that commit/tag, and both live fixture gates, evidence retention, publication
and the fresh installation job must have succeeded. It downloads exactly the
three release assets and checks both distribution hashes, names, versions and
Apache-2.0 metadata. Archives are inspected as data, never installed or executed
by this workflow. No VTAI request or fixture submission is performed.

The retained `pypi-verified-*` artifact contains the two packages, the original
manifest and JSON provenance. The provenance distinguishes the **package source
commit / CI / Release run** from the **current publishing workflow commit / run**.
The known manifest hash is the cross-channel binding to the reviewed CI assets;
the verifier does not rebuild the package or redownload the original CI ZIP.

Once ownership and the target release's public metadata are ready, dispatch
`mode=publish` with the same reviewed identities. The verify job runs again.
Only the separate publishing job has `id-token: write`. It downloads the
verified artifact by its immutable Actions artifact ID, rechecks the bytes and
requires the version to remain absent on PyPI. The pinned official PyPA action
then uploads only the wheel and sdist, with Trusted Publishing and PEP 740
attestations enabled. There is no API-token fallback, `--skip-existing`, build,
automatic release trigger or additional per-run approval imposed here.

The Publish attestation binds the uploaded bytes to the publishing identity.
It does **not** assert that the original build occurred in this later workflow,
nor that the package is safe. The original CI/Release provenance remains in the
verification artifact. PyPI exposes attestations through its Integrity API;
the workflow's final JSON comparison checks filenames and hashes, not an
independent cryptographic verification of those attestations.

Sources: [PyPA publishing action](https://github.com/pypa/gh-action-pypi-publish),
[Trusted Publishing usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[attestation security model](https://docs.pypi.org/attestations/security-model/),
[Integrity API](https://docs.pypi.org/api/integrity/),
[GitHub workflow trigger behavior](https://docs.github.com/en/actions/how-tos/writing-workflows/choosing-when-your-workflow-runs/triggering-a-workflow).

## Failure and reconciliation

Uploading two files is not atomic. A timeout or failure can leave zero, one or
both files published. The workflow does not retry its publication step, and
rejects Actions re-runs in publish mode. **Twine, used inside the official PyPA
action, can itself retry some HTTP 5xx responses**; this is not a guarantee of a
single HTTP POST. PyPI's immutable filenames and `skip-existing: false` prevent
an existing file from being silently replaced or accepted as a skipped upload.

After an upload attempt, the workflow performs a read-only PyPI JSON check and
retains the result, including on upload failure. A failed upload step remains a
failed workflow even if that later read finds both expected files. An absent or
partially visible result is not permission to retry: allow for visibility delay
and run **verify** again for read-only reconciliation. Complete matching files
are reported as `complete`; a partial set, different digests or yanked files
fail closed. Do not rerun publish, delete files to reuse their names, or hide a
partial publication with `--skip-existing`. Resolve a partial upload explicitly;
the helper does not attempt repairs. PyPI does not allow filename reuse, even
after deletion.

Sources: [Twine upload implementation](https://github.com/pypa/twine/blob/main/twine/repository.py),
[PyPI filename reuse](https://pypi.org/help/#file-name-reuse).
