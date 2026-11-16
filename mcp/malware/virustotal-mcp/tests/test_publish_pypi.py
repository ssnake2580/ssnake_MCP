# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish_pypi", ROOT / "scripts/publish_pypi.py")
publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish)

RELEASE_STEPS = [
    "Check explicitly public skill fixture version 1; standard sharing",
    "Check distinct public skill fixture version 2; standard sharing",
    "Retain exact public-fixture evidence, including failed gates",
    "Publish a new GitHub release without rebuilding",
    "Install the published wheel and test its stdio entry point",
]


@pytest.fixture
def release(request):
    settings = getattr(request, "param", {})
    version = settings.get("version", "0.8.3")
    body = (
        f"Metadata-Version: 2.4\nName: vt-mcp\nVersion: {version}\n"
        "License-Expression: Apache-2.0\nDescription-Content-Type: text/markdown\n\n"
        + settings.get(
            "description", "# VirusTotal\nInformación → [Guide](https://ai.virustotal.com/)\n"
        )
    ).encode()
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"vt_mcp-{version}.dist-info/METADATA", body)
    sdist = io.BytesIO()
    with tarfile.open(fileobj=sdist, mode="w:gz") as archive:
        info = tarfile.TarInfo(f"vt_mcp-{version}/PKG-INFO")
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    blobs = {
        f"vt_mcp-{version}-py3-none-any.whl": wheel.getvalue(),
        f"vt_mcp-{version}.tar.gz": sdist.getvalue(),
    }
    manifest = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in blobs.items()).encode()
    selected = {
        "mode": "verify",
        "tag": f"v{version}",
        "source_sha": "a" * 40,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "release_run_id": 22,
    }
    environ = {
        "GITHUB_REPOSITORY": publish.REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(publish.REPOSITORY_ID),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{publish.REPOSITORY}/.github/workflows/pypi.yml@refs/heads/main",
        "GITHUB_SHA": "b" * 40,
        "GITHUB_RUN_ID": "33",
        "GITHUB_RUN_ATTEMPT": "1",
        "PYPI_MODE": "verify",
        "RELEASE_TAG": selected["tag"],
        "SOURCE_SHA": selected["source_sha"],
        "MANIFEST_SHA256": selected["manifest_sha256"],
        "RELEASE_RUN_ID": "22",
    }
    current = publish.context(environ, selected)
    repo = {"id": publish.REPOSITORY_ID, "full_name": publish.REPOSITORY}
    responses = {
        "": repo,
        "git/ref/heads/main": {"object": {"sha": current["publisher_sha"]}},
        f"compare/{selected['source_sha']}...{current['publisher_sha']}": {"status": "ahead"},
        f"git/ref/tags/{selected['tag']}": {"object": {"type": "tag", "sha": "c" * 40}},
        f"git/tags/{'c' * 40}": {
            "tag": selected["tag"],
            "object": {"type": "commit", "sha": selected["source_sha"]},
            "message": (
                f"Reviewed release\nCI-Run: 11\nSHA256SUMS-SHA256: {selected['manifest_sha256']}\n"
            ),
        },
        "actions/workflows/ci.yml": {"id": 101},
        "actions/workflows/release.yml": {"id": 102},
        f"actions/runs?head_sha={current['publisher_sha']}&event=push&branch=main&per_page=100": {
            "total_count": 1,
            "workflow_runs": [{"id": 44, "workflow_id": 101}],
        },
    }
    for run_id, workflow, branch, source in [
        (11, "ci.yml", "main", selected["source_sha"]),
        (22, "release.yml", selected["tag"], selected["source_sha"]),
        (44, "ci.yml", "main", current["publisher_sha"]),
    ]:
        responses[f"actions/runs/{run_id}"] = {
            "id": run_id,
            "head_sha": source,
            "head_branch": branch,
            "event": "push",
            "workflow_id": 101 if workflow == "ci.yml" else 102,
            "path": f".github/workflows/{workflow}",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            "repository": repo,
            "head_repository": repo,
        }
        names = (
            ["Python 3.12", "Python 3.13", "Python 3.14"]
            if workflow == "ci.yml"
            else ["release", "Install the published release"]
        )
        jobs = [
            {"name": n, "status": "completed", "conclusion": "success", "steps": []} for n in names
        ]
        if workflow == "release.yml":
            jobs[0]["steps"] = [{"name": n, "conclusion": "success"} for n in RELEASE_STEPS[:-1]]
            jobs[1]["steps"] = [{"name": RELEASE_STEPS[-1], "conclusion": "success"}]
        responses[f"actions/runs/{run_id}/attempts/1/jobs?per_page=100"] = {
            "total_count": len(jobs),
            "jobs": jobs,
        }
    assets = []
    for asset_id, (name, data) in enumerate({**blobs, "SHA256SUMS": manifest}.items(), 1001):
        assets.append({"id": asset_id, "name": name, "size": len(data), "state": "uploaded"})
        responses[f"releases/assets/{asset_id}"] = data
    responses[f"releases/tags/{selected['tag']}"] = {
        "id": 555,
        "tag_name": selected["tag"],
        "draft": False,
        "prerelease": False,
        "published_at": "2026-09-08T10:00:00Z",
        "assets": assets,
    }
    calls = []

    def api(path, *, binary=False):
        calls.append((path, binary))
        return copy.deepcopy(responses[path])

    return selected, current, environ, responses, api, calls


def test_exact_release_assets_and_separate_publisher_provenance(tmp_path, release):
    selected, current, _, _, api, calls = release
    evidence = publish.prepare(tmp_path / "verified", selected, current, api)
    assert evidence["source_sha"] != evidence["publisher_sha"]
    assert evidence["ci"]["id"] == 11 and evidence["publisher_ci"]["id"] == 44
    assert evidence["release_run"]["id"] == 22
    assert len(publish.validate_files(tmp_path / "verified", selected)) == 2
    assert len([c for c in calls if c[1]]) == 3


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_REPOSITORY", "king-tero/vt-mcp"),
        ("GITHUB_REPOSITORY_ID", "1361592456"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_WORKFLOW_REF", "other/repo/.github/workflows/pypi.yml@refs/heads/main"),
    ],
)
def test_wrong_workflow_identity_rejected(release, key, value):
    selected, _, environ, *_ = release
    environ[key] = value
    with pytest.raises(publish.Rejected, match="wrong_workflow_identity"):
        publish.context(environ, selected)


@pytest.mark.parametrize(
    "key,value",
    [
        ("SOURCE_SHA", "short"),
        ("MANIFEST_SHA256", "a" * 63),
        ("RELEASE_TAG", "v0.8.3; echo nope"),
        ("RELEASE_RUN_ID", "-1"),
    ],
)
def test_invalid_review_inputs(release, key, value):
    environ = release[2]
    environ[key] = value
    with pytest.raises(publish.Rejected):
        publish.inputs(environ)


@pytest.mark.parametrize(
    "run_id,key,value",
    [
        (11, "head_sha", "f" * 40),
        (11, "event", "pull_request"),
        (11, "head_branch", "feature"),
        (11, "workflow_id", 999),
        (11, "repository", {"id": 1, "full_name": publish.REPOSITORY}),
        (11, "head_repository", {"id": 1, "full_name": "other/repo"}),
        (22, "conclusion", "failure"),
        (22, "head_branch", "v0.8.2"),
        (44, "conclusion", "failure"),
    ],
)
def test_wrong_ci_release_or_publisher_fails_before_asset_download(
    tmp_path, release, run_id, key, value
):
    selected, current, _, responses, api, calls = release
    responses[f"actions/runs/{run_id}"][key] = value
    with pytest.raises(publish.Rejected):
        publish.prepare(tmp_path / "verified", selected, current, api)
    assert not any(binary for _, binary in calls)


@pytest.mark.parametrize(
    "failure",
    [
        "missing_install",
        "skipped_pilot",
        "jobs_truncated",
        "lightweight_tag",
        "wrong_tag_hash",
        "main_moved",
    ],
)
def test_incomplete_or_unbound_evidence(release, failure):
    selected, current, _, responses, api, _ = release
    jobs = responses["actions/runs/22/attempts/1/jobs?per_page=100"]
    if failure == "missing_install":
        jobs["jobs"].pop()
        jobs["total_count"] -= 1
    elif failure == "skipped_pilot":
        jobs["jobs"][0]["steps"][0]["conclusion"] = "skipped"
    elif failure == "jobs_truncated":
        jobs["total_count"] += 1
    elif failure == "lightweight_tag":
        responses[f"git/ref/tags/{selected['tag']}"]["object"]["type"] = "commit"
    elif failure == "wrong_tag_hash":
        responses[f"git/tags/{'c' * 40}"]["message"] = "CI-Run: 11\n"
    else:
        responses["git/ref/heads/main"]["object"]["sha"] = "f" * 40
    with pytest.raises(publish.Rejected):
        publish.provenance(api, selected, current)


@pytest.mark.parametrize("failure", ["missing", "tampered", "symlink", "unexpected"])
def test_transferred_packages_fail_closed(tmp_path, release, failure):
    selected, current, _, _, api, _ = release
    directory = tmp_path / "verified"
    publish.prepare(directory, selected, current, api)
    wheel = next((directory / "packages").glob("*.whl"))
    if failure == "missing":
        wheel.unlink()
    elif failure == "tampered":
        wheel.write_bytes(b"changed")
    elif failure == "symlink":
        target = tmp_path / "wheel"
        wheel.rename(target)
        wheel.symlink_to(target)
    else:
        (directory / "packages" / "unexpected.txt").write_text("not a distribution")
    with pytest.raises(publish.Rejected):
        publish.validate_files(directory, selected)


def pypi_response(selected, files):
    return {
        "info": {"name": "vt-mcp", "version": selected["tag"][1:]},
        "urls": [
            {"filename": n, "digests": {"sha256": h}, "yanked": False} for n, h in files.items()
        ],
    }


def test_pypi_absent_complete_partial_and_tampered(tmp_path, release):
    selected, current, _, _, api, _ = release
    files = publish.prepare(tmp_path / "verified", selected, current, api)["files"]
    assert publish.pypi_state(selected, files, lambda _: None)["state"] == "absent"
    data = pypi_response(selected, files)
    assert publish.pypi_state(selected, files, lambda _: data)["state"] == "complete"
    data["urls"].pop()
    assert publish.pypi_state(selected, files, lambda _: data)["state"] == "partial"
    data["urls"][0]["digests"]["sha256"] = "f" * 64
    with pytest.raises(publish.Rejected, match="pypi_files_mismatch"):
        publish.pypi_state(selected, files, lambda _: data)


def test_publish_duplicate_and_reconcile_without_upload(tmp_path, release, monkeypatch, capsys):
    selected, current, environ, _, api, _ = release
    selected["mode"] = environ["PYPI_MODE"] = "publish"
    directory = tmp_path / "verified"
    files = publish.prepare(directory, selected, current, api)["files"]
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        publish, "pypi_state", lambda *_: {"state": "complete", "files": sorted(files)}
    )
    monkeypatch.setattr("sys.argv", ["publish_pypi.py", "check", "--directory", str(directory)])
    assert publish.main() == 2
    assert "pypi_version_already_exists" in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", ["publish_pypi.py", "reconcile", "--directory", str(directory)])
    assert publish.main() == 0
    assert (
        json.loads((directory / "reconcile-result.json").read_text())["pypi"]["state"] == "complete"
    )


def test_publish_rerun_forbidden_but_verify_allowed(release):
    selected, _, environ, *_ = release
    environ["GITHUB_RUN_ATTEMPT"] = "2"
    publish.context(environ, selected)
    selected["mode"] = "publish"
    with pytest.raises(publish.Rejected, match="publish_rerun_forbidden"):
        publish.context(environ, selected)


@pytest.mark.parametrize(
    "path,endpoint",
    [
        ("", "repos/VirusTotal/virustotal-mcp"),
        ("git/ref/heads/main", "repos/VirusTotal/virustotal-mcp/git/ref/heads/main"),
    ],
)
def test_github_repository_and_child_routes(monkeypatch, path, endpoint):
    def run(args, **kwargs):
        # GitHub returns 404 for the repository endpoint with a trailing slash.
        if endpoint not in args:
            return subprocess.CompletedProcess(args, 1, b"", b"Not Found")
        return subprocess.CompletedProcess(args, 0, b'{"id": 1361592455}', b"")

    monkeypatch.setattr(publish.subprocess, "run", run)
    assert publish.github(path) == {"id": 1361592455}


def test_github_reader_only_get_and_sanitizes_failures(monkeypatch):
    observed = []

    def run(args, **kwargs):
        observed.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1, b"private response", b"secret URL")

    monkeypatch.setattr(publish.subprocess, "run", run)
    monkeypatch.setenv("GH_DEBUG", "api")
    with pytest.raises(publish.Rejected, match="^github_read_failed$"):
        publish.github("releases/tags/v0.8.3")
    args, options = observed[0]
    assert args[args.index("--method") + 1] == "GET"
    assert args[args.index("--hostname") + 1] == "github.com"
    assert "GH_DEBUG" not in options["env"]
    assert options["capture_output"] is True


def test_utf8_description_and_publish_path(tmp_path, release):
    selected, current, _, _, api, _ = release
    selected["mode"] = "publish"
    evidence = publish.prepare(tmp_path / "verified", selected, current, api)
    assert len(evidence["files"]) == 2
    wheel = next((tmp_path / "verified/packages").glob("*.whl"))
    description = publish.metadata(wheel, "0.8.3").get_payload(decode=True).decode("utf-8")
    assert "Información →" in description


@pytest.mark.parametrize("release", [{"version": "0.8.2"}], indirect=True)
def test_082_is_verification_only(tmp_path, release):
    selected, current, _, _, api, _ = release
    directory = tmp_path / "verified"
    publish.prepare(directory, selected, current, api)
    selected["mode"] = "publish"
    with pytest.raises(publish.Rejected, match="release_not_prepared_for_pypi"):
        publish.validate_files(directory, selected)


@pytest.mark.parametrize(
    "release",
    [
        {"description": "[Guide](docs/clients.md)"},
        {"description": "[Guide][guide]\n\n[guide]: docs/clients.md"},
    ],
    indirect=True,
)
def test_relative_consumer_links_block_publish(tmp_path, release):
    selected, current, _, _, api, _ = release
    selected["mode"] = "publish"
    with pytest.raises(publish.Rejected, match="relative_description_links"):
        publish.prepare(tmp_path / "verified", selected, current, api)


def test_transferred_review_identity_cannot_change(tmp_path, release, monkeypatch, capsys):
    selected, current, environ, _, api, _ = release
    directory = tmp_path / "verified"
    publish.prepare(directory, selected, current, api)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SOURCE_SHA", "f" * 40)
    monkeypatch.setattr("sys.argv", ["publish_pypi.py", "check", "--directory", str(directory)])
    monkeypatch.setattr(publish, "pypi_state", lambda *_: pytest.fail("must reject before PyPI"))
    assert publish.main() == 2
    assert "transferred_provenance_mismatch" in capsys.readouterr().out


def test_publish_absent_and_partial_state(tmp_path, release, monkeypatch, capsys):
    selected, current, environ, _, api, _ = release
    selected["mode"] = environ["PYPI_MODE"] = "publish"
    directory = tmp_path / "verified"
    publish.prepare(directory, selected, current, api)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("sys.argv", ["publish_pypi.py", "check", "--directory", str(directory)])
    monkeypatch.setattr(publish, "pypi_state", lambda *_: {"state": "absent", "files": []})
    assert publish.main() == 0
    (directory / "check-result.json").unlink()
    monkeypatch.setattr(publish, "pypi_state", lambda *_: {"state": "partial", "files": []})
    assert publish.main() == 2
    assert "partial_publication_requires_reconciliation" in capsys.readouterr().out
