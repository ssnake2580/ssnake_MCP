#!/usr/bin/env python3
"""Download and extract the latest Hayabusa release for the current platform.

Usage:
    python scripts/download_hayabusa.py [--dest DIR] [--version TAG] [--musl] [--live-response] [--force]

By default downloads the latest release from
https://github.com/Yamato-Security/hayabusa/releases into <repo root>/hayabusa/
and prints the path to the extracted binary, which can be pointed at via the
HAYABUSA_BIN environment variable.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
API_BY_TAG = f"https://api.github.com/repos/{REPO}/releases/tags/{{tag}}"
USER_AGENT = "mcp-hayabusa-fetch-script"


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def detect_asset_name(version: str, *, musl: bool, live_response: bool) -> str:
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Windows":
        os_tag = "win"
    elif system == "Linux":
        os_tag = "lin"
    elif system == "Darwin":
        os_tag = "mac"
    else:
        raise SystemExit(f"Unsupported platform: {system}")

    if machine in ("amd64", "x86_64"):
        arch_tag = "x64"
    elif machine in ("arm64", "aarch64"):
        arch_tag = "aarch64"
    elif os_tag == "win" and machine in ("x86", "i386", "i686"):
        arch_tag = "x86"
    else:
        raise SystemExit(f"Unsupported architecture: {machine} on {system}")

    suffix = ""
    if os_tag == "lin":
        suffix = "-musl" if musl else "-gnu"
    if live_response:
        suffix += "-live-response"

    return f"hayabusa-{version}-{os_tag}-{arch_tag}{suffix}.zip"


def find_asset(release: dict, asset_name: str) -> dict:
    for asset in release.get("assets", []):
        if asset["name"] == asset_name:
            return asset
    available = ", ".join(a["name"] for a in release.get("assets", []))
    raise SystemExit(
        f"Could not find asset '{asset_name}' in release {release.get('tag_name')}.\n"
        f"Available assets: {available}"
    )


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req) as resp, dest.open("wb") as f:
        shutil.copyfileobj(resp, f)


def extract(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp_path)

        entries = list(tmp_path.iterdir())
        # Flatten a single wrapping top-level directory, if the archive has one,
        # so dest_dir contains the binary directly.
        source = entries[0] if len(entries) == 1 and entries[0].is_dir() else tmp_path

        for item in source.iterdir():
            target = dest_dir / item.name
            if target.exists():
                shutil.rmtree(target) if target.is_dir() else target.unlink()
            shutil.move(str(item), str(target))


def find_binary(dest_dir: Path) -> Path | None:
    # Exact canonical name, if a previous run already normalized it.
    for name in ("hayabusa.exe", "hayabusa"):
        candidate = dest_dir / name
        if candidate.exists():
            return candidate
    # Otherwise Hayabusa ships the binary at the top level named after the
    # release, e.g. hayabusa-3.10.0-win-x64.exe. Only look at the top level
    # (not recursively) so the bundled rules/hayabusa/ directory isn't matched.
    matches = [
        p for p in dest_dir.iterdir()
        if p.is_file() and p.name.startswith("hayabusa") and p.suffix in ("", ".exe")
    ]
    return matches[0] if matches else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", default=None, help="Extraction directory (default: <repo root>/hayabusa)")
    parser.add_argument("--version", default=None, help="Release tag to fetch, e.g. v3.10.0 (default: latest)")
    parser.add_argument("--musl", action="store_true", help="On Linux, fetch the musl build instead of glibc")
    parser.add_argument("--live-response", action="store_true", help="Fetch the live-response bundle")
    parser.add_argument("--force", action="store_true", help="Re-download even if a binary already exists")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    dest_dir = Path(args.dest).resolve() if args.dest else repo_root / "hayabusa"

    if not args.force and dest_dir.exists():
        existing = find_binary(dest_dir)
        if existing:
            print(f"hayabusa already present at {existing} (use --force to re-download)")
            return

    print("Looking up release metadata...")
    release = _get_json(API_BY_TAG.format(tag=args.version)) if args.version else _get_json(API_LATEST)

    tag = release["tag_name"]
    version = tag.lstrip("v")
    asset_name = detect_asset_name(version, musl=args.musl, live_response=args.live_response)
    asset = find_asset(release, asset_name)

    print(f"Downloading {asset_name} ({tag})...")
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / asset_name
        download(asset["browser_download_url"], zip_path)

        print(f"Extracting to {dest_dir}...")
        extract(zip_path, dest_dir)

    binary = find_binary(dest_dir)
    if binary is None:
        raise SystemExit(f"Extraction finished but no hayabusa binary was found under {dest_dir}")

    # Normalize to a version-independent name so HAYABUSA_BIN doesn't need to
    # change across re-downloads/upgrades.
    canonical_name = "hayabusa.exe" if binary.suffix == ".exe" else "hayabusa"
    if binary.name != canonical_name:
        canonical_path = binary.with_name(canonical_name)
        binary.replace(canonical_path)
        binary = canonical_path

    if platform.system() != "Windows":
        binary.chmod(binary.stat().st_mode | 0o111)

    print(f"Done. hayabusa binary: {binary}")
    print(f"Set HAYABUSA_BIN={binary} (or add {dest_dir} to PATH) for mcp-hayabusa to find it.")


if __name__ == "__main__":
    main()
