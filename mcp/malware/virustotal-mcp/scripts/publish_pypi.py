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

"""Read-only release verification for pypi.yml; uploads belong to the PyPA action."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import http.client
import json
import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

REPOSITORY = "VirusTotal/virustotal-mcp"
REPOSITORY_ID = 1361592455
SHA = r"[0-9a-f]{40}"
DIGEST = r"[0-9a-f]{64}"
LIMIT = 32 * 1024 * 1024


class Rejected(Exception):
    """A closed diagnostic; never include upstream bodies or subprocess output."""


def require(condition: object, code: str) -> None:
    if not condition:
        raise Rejected(code)


def inputs(environ: dict[str, str]) -> dict:
    value = {
        "mode": environ.get("PYPI_MODE", "verify"),
        "tag": environ.get("RELEASE_TAG", ""),
        "source_sha": environ.get("SOURCE_SHA", ""),
        "manifest_sha256": environ.get("MANIFEST_SHA256", ""),
        "release_run_id": environ.get("RELEASE_RUN_ID", ""),
    }
    require(value["mode"] in {"verify", "publish"}, "invalid_mode")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", value["tag"]), "invalid_tag")
    require(re.fullmatch(SHA, value["source_sha"]), "invalid_source_sha")
    require(re.fullmatch(DIGEST, value["manifest_sha256"]), "invalid_manifest_sha")
    require(re.fullmatch(r"[1-9][0-9]*", value["release_run_id"]), "invalid_release_run")
    value["release_run_id"] = int(value["release_run_id"])
    return value


def context(environ: dict[str, str], selected: dict) -> dict:
    require(
        environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and environ.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID)
        and environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and environ.get("GITHUB_REF") == "refs/heads/main"
        and environ.get("GITHUB_WORKFLOW_REF")
        == f"{REPOSITORY}/.github/workflows/pypi.yml@refs/heads/main",
        "wrong_workflow_identity",
    )
    require(re.fullmatch(SHA, environ.get("GITHUB_SHA", "")), "invalid_publisher_sha")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", environ.get(key, "")), "invalid_run_identity")
    require(
        selected["mode"] != "publish" or environ["GITHUB_RUN_ATTEMPT"] == "1",
        "publish_rerun_forbidden",
    )
    return {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "publisher_sha": environ["GITHUB_SHA"],
        "publisher_run_id": int(environ["GITHUB_RUN_ID"]),
        "publisher_run_attempt": int(environ["GITHUB_RUN_ATTEMPT"]),
    }


def github(path: str, *, binary: bool = False):
    # Fixed host, GET only, no signed URL or error body written to evidence/logs.
    env = {k: os.environ[k] for k in ("PATH", "HOME", "GH_TOKEN") if k in os.environ}
    result = subprocess.run(
        [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "--method",
            "GET",
            f"repos/{REPOSITORY}" + (f"/{path}" if path else ""),
            "-H",
            "Accept: application/octet-stream" if binary else "Accept: application/vnd.github+json",
        ],
        env=env,
        capture_output=True,
        timeout=90,
        check=False,
    )
    require(result.returncode == 0, "github_read_failed")
    require(len(result.stdout) <= LIMIT, "github_response_too_large")
    return result.stdout if binary else json.loads(result.stdout)


def repository_identity(value: dict) -> None:
    require(
        value.get("id") == REPOSITORY_ID and value.get("full_name") == REPOSITORY,
        "wrong_repository",
    )


def successful_run(api, run_id: int, source: str, workflow: str, branch: str) -> dict:
    run = api(f"actions/runs/{run_id}")
    workflow_id = api(f"actions/workflows/{workflow}")["id"]
    repository_identity(run.get("repository", {}))
    repository_identity(run.get("head_repository", {}))
    require(
        run.get("id") == run_id
        and run.get("head_sha") == source
        and run.get("head_branch") == branch
        and run.get("event") == "push"
        and run.get("workflow_id") == workflow_id
        and run.get("path") == f".github/workflows/{workflow}"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "run_not_successful_exact_source",
    )
    attempt = run.get("run_attempt")
    require(type(attempt) is int and attempt > 0, "invalid_run_attempt")
    page = api(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    jobs = page["jobs"]
    require(
        jobs
        and page["total_count"] == len(jobs) <= 100
        and all(j.get("status") == "completed" and j.get("conclusion") == "success" for j in jobs),
        "incomplete_or_failed_jobs",
    )
    names = {j["name"] for j in jobs}
    required = (
        {"Python 3.12", "Python 3.13", "Python 3.14"}
        if workflow == "ci.yml"
        else {
            "release",
            "Install the published release",
        }
    )
    require(required <= names, "missing_required_jobs")
    if workflow == "release.yml":
        steps = {s["name"]: s.get("conclusion") for j in jobs for s in j.get("steps", [])}
        required_steps = {
            "Check explicitly public skill fixture version 1; standard sharing",
            "Check distinct public skill fixture version 2; standard sharing",
            "Retain exact public-fixture evidence, including failed gates",
            "Publish a new GitHub release without rebuilding",
            "Install the published wheel and test its stdio entry point",
        }
        require(all(steps.get(s) == "success" for s in required_steps), "missing_release_gate")
    return {"id": run_id, "attempt": attempt, "jobs": sorted(names)}


def provenance(api, selected: dict, current: dict) -> tuple[dict, list]:
    repository_identity(api(""))
    main = api("git/ref/heads/main")
    require(main["object"]["sha"] == current["publisher_sha"], "main_moved")
    ci_workflow_id = api("actions/workflows/ci.yml")["id"]
    publisher_runs = api(
        f"actions/runs?head_sha={current['publisher_sha']}&event=push&branch=main&per_page=100"
    )
    require(
        publisher_runs["total_count"] == len(publisher_runs["workflow_runs"]) <= 100,
        "incomplete_publisher_runs",
    )
    candidates = [
        r for r in publisher_runs["workflow_runs"] if r.get("workflow_id") == ci_workflow_id
    ]
    require(candidates, "publisher_ci_missing")
    publisher_ci = successful_run(
        api, max(r["id"] for r in candidates), current["publisher_sha"], "ci.yml", "main"
    )
    comparison = api(f"compare/{selected['source_sha']}...{current['publisher_sha']}")
    require(comparison.get("status") in {"ahead", "identical"}, "source_not_on_main")
    tag_ref = api(f"git/ref/tags/{selected['tag']}")
    require(tag_ref["object"]["type"] == "tag", "tag_not_annotated")
    tag_sha = tag_ref["object"]["sha"]
    tag = api(f"git/tags/{tag_sha}")
    require(
        tag.get("tag") == selected["tag"]
        and tag["object"]["type"] == "commit"
        and tag["object"]["sha"] == selected["source_sha"],
        "tag_source_mismatch",
    )
    ci_ids = re.findall(r"^CI-Run: ([1-9][0-9]*)$", tag["message"], re.MULTILINE)
    hashes = re.findall(r"^SHA256SUMS-SHA256: ([0-9a-f]{64})$", tag["message"], re.MULTILINE)
    require(len(ci_ids) == 1 and hashes == [selected["manifest_sha256"]], "tag_evidence_mismatch")
    ci = successful_run(api, int(ci_ids[0]), selected["source_sha"], "ci.yml", "main")
    release_run = successful_run(
        api, selected["release_run_id"], selected["source_sha"], "release.yml", selected["tag"]
    )
    release = api(f"releases/tags/{selected['tag']}")
    require(
        release.get("tag_name") == selected["tag"]
        and release.get("draft") is False
        and release.get("prerelease") is False
        and release.get("published_at"),
        "release_not_published",
    )
    assets = release["assets"]
    require(
        len(assets) == 3 and all(a.get("state") == "uploaded" for a in assets), "unexpected_assets"
    )
    evidence = {
        "schema_version": 1,
        **current,
        **selected,
        "tag_object_sha": tag_sha,
        "ci": ci,
        "publisher_ci": publisher_ci,
        "release_run": release_run,
        "release_id": release["id"],
        "release_published_at": release["published_at"],
        "assets": [{k: a[k] for k in ("id", "name", "size")} for a in assets],
    }
    return evidence, assets


def checksums(data: bytes, selected: dict) -> dict[str, str]:
    require(hashlib.sha256(data).hexdigest() == selected["manifest_sha256"], "manifest_mismatch")
    lines = data.decode("ascii").splitlines()
    require(len(lines) == 2, "invalid_manifest")
    files = {}
    version = re.escape(selected["tag"][1:])
    for line in lines:
        match = re.fullmatch(
            rf"({DIGEST})  (vt_mcp-{version}(?:-py3-none-any\.whl|\.tar\.gz))", line
        )
        require(match is not None, "invalid_manifest_entry")
        require(match[2] not in files, "duplicate_manifest_entry")
        files[match[2]] = match[1]
    require(sum(n.endswith(".whl") for n in files) == 1, "missing_distribution")
    return files


def file_bytes(path: Path, limit: int = LIMIT) -> bytes:
    require(
        path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, "invalid_file"
    )
    return path.read_bytes()


def metadata(path: Path, version: str):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            entries = [
                i
                for i in archive.infolist()
                if i.filename == f"vt_mcp-{version}.dist-info/METADATA"
            ]
            require(
                len(entries) == 1 and entries[0].file_size <= 1024 * 1024, "invalid_wheel_metadata"
            )
            body = archive.read(entries[0])
    else:
        with tarfile.open(path, "r:gz") as archive:
            entries = [i for i in archive if i.name == f"vt_mcp-{version}/PKG-INFO"]
            require(
                len(entries) == 1 and entries[0].isfile() and entries[0].size <= 1024 * 1024,
                "invalid_sdist_metadata",
            )
            body = archive.extractfile(entries[0]).read()
    value = email.parser.BytesParser().parsebytes(body)
    require(
        value.get_all("Name") == ["vt-mcp"]
        and value.get_all("Version") == [version]
        and value.get_all("License-Expression") == ["Apache-2.0"],
        "package_metadata_mismatch",
    )
    return value


def validate_files(directory: Path, selected: dict) -> dict[str, str]:
    files = checksums(file_bytes(directory / "SHA256SUMS", 4096), selected)
    packages = directory / "packages"
    require({p.name for p in packages.iterdir()} == set(files), "unexpected_package_files")
    descriptions = []
    for name, digest in files.items():
        path = packages / name
        require(hashlib.sha256(file_bytes(path)).hexdigest() == digest, "distribution_mismatch")
        value = metadata(path, selected["tag"][1:])
        require(
            value.get_all("Description-Content-Type") == ["text/markdown"],
            "description_not_markdown",
        )
        descriptions.append(value.get_payload(decode=True).decode("utf-8"))
    require(descriptions[0] == descriptions[1], "descriptions_differ")
    if selected["mode"] == "publish":
        # 0.8.2 is a verification fixture: its README still denies PyPI publication.
        require(selected["tag"] != "v0.8.2", "release_not_prepared_for_pypi")
        links = re.findall(r"\]\(<?([^\s)>]+)", descriptions[0])
        links += re.findall(r"(?m)^\s*\[[^\]]+\]:\s*<?([^\s>]+)", descriptions[0])
        require(
            all(link.startswith(("https://", "http://", "#", "mailto:")) for link in links),
            "relative_description_links",
        )
    return files


def pypi_json(path: str):
    connection = http.client.HTTPSConnection("pypi.org", timeout=30)
    try:
        connection.request(
            "GET",
            path,
            headers={"Accept": "application/json", "User-Agent": "vt-mcp-release-verifier"},
        )
        response = connection.getresponse()
        body = response.read(4 * 1024 * 1024 + 1)
        require(len(body) <= 4 * 1024 * 1024, "pypi_response_too_large")
        if response.status == 404:
            return None
        require(response.status == 200, "pypi_read_failed")
        return json.loads(body)
    finally:
        connection.close()


def pypi_state(selected: dict, files: dict, read=pypi_json) -> dict:
    result = read(f"/pypi/vt-mcp/{selected['tag'][1:]}/json")
    if result is None:
        return {"state": "absent", "files": []}
    require(
        result["info"]["name"] == "vt-mcp" and result["info"]["version"] == selected["tag"][1:],
        "pypi_identity_mismatch",
    )
    observed = result["urls"]
    names = [f["filename"] for f in observed]
    require(len(names) == len(set(names)), "pypi_duplicate_filenames")
    require(
        all(
            f["filename"] in files
            and f["digests"]["sha256"] == files[f["filename"]]
            and f.get("yanked") is False
            for f in observed
        ),
        "pypi_files_mismatch",
    )
    return {"state": "complete" if set(names) == set(files) else "partial", "files": sorted(names)}


def save(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def prepare(directory: Path, selected: dict, current: dict, api=github) -> dict:
    evidence, assets = provenance(api, selected, current)
    manifests = [a for a in assets if a["name"] == "SHA256SUMS"]
    require(len(manifests) == 1, "missing_manifest")
    manifest = api(f"releases/assets/{manifests[0]['id']}", binary=True)
    files = checksums(manifest, selected)
    require({a["name"] for a in assets} == {*files, "SHA256SUMS"}, "unexpected_assets")
    directory.mkdir()
    (directory / "packages").mkdir()
    (directory / "SHA256SUMS").write_bytes(manifest)
    for asset in assets:
        if asset["name"] == "SHA256SUMS":
            continue
        require(type(asset["size"]) is int and 0 < asset["size"] <= LIMIT, "invalid_asset_size")
        body = api(f"releases/assets/{asset['id']}", binary=True)
        require(len(body) == asset["size"], "asset_size_mismatch")
        (directory / "packages" / asset["name"]).write_bytes(body)
    validate_files(directory, selected)
    evidence["files"] = files
    save(directory / "provenance.json", evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "check", "reconcile"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        selected = inputs(os.environ)
        current = context(os.environ, selected)
        if args.command == "prepare":
            evidence = prepare(args.directory, selected, current)
        else:
            evidence = json.loads(file_bytes(args.directory / "provenance.json", 65536))
            require(
                all(evidence.get(k) == v for k, v in {**selected, **current}.items()),
                "transferred_provenance_mismatch",
            )
        # After the PyPA action there may be additional attestation files. They
        # are not package inputs; reconciliation uses the reviewed manifest.
        files = checksums(file_bytes(args.directory / "SHA256SUMS", 4096), selected)
        require(evidence.get("files") == files, "transferred_files_mismatch")
        if args.command != "reconcile":
            validate_files(args.directory, selected)
        state = pypi_state(selected, files)
        save(args.directory / f"{args.command}-result.json", {**current, **selected, "pypi": state})
        if args.command == "reconcile":
            require(state["state"] == "complete", "publication_not_complete")
        else:
            require(state["state"] != "partial", "partial_publication_requires_reconciliation")
            require(
                selected["mode"] != "publish" or state["state"] == "absent",
                "pypi_version_already_exists",
            )
        print(json.dumps({"status": "verified", "command": args.command, "pypi": state["state"]}))
        return 0
    except (
        Rejected,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        http.client.HTTPException,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        code = str(error) if isinstance(error, Rejected) else "verification_failed"
        print(json.dumps({"status": "error", "code": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
