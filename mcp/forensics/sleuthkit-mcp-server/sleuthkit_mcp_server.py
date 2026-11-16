import json
import math
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Union, Dict, Any
import re

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sleuthkit-MCP")

def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

def _which(name: str) -> Optional[str]:
    return shutil.which(name)

def _sha256(path: Union[str, Path]) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _add_flag(cmd: List[str], cond: bool, flag: str) -> None:
    if cond:
        cmd.append(flag)

def _common_img_fs_opts(cmd: List[str],
                        imgtype: Optional[str],
                        fstype: Optional[str],
                        fs_offset_sectors: Optional[Union[int, float, str]]) -> None:
    if imgtype:
        cmd += ["-i", imgtype]
    if fstype:
        cmd += ["-f", fstype]
    if fs_offset_sectors is not None:
        cmd += ["-o", str(fs_offset_sectors)]

_FLS_LINE = re.compile(r"""
    ^\s*
    (?P<type>[^\s]+)
    \s+
    (?P<inode>\d+(?:-\d+(?:-\d+)?)?)
    :
    \s*
    (?P<name>.+?)\s*$
""", re.X)

def _parse_fls(stdout: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        m = _FLS_LINE.match(line)
        if not m:
            continue
        items.append({
            "raw": line,
            "type": m.group("type"),
            "inode": m.group("inode"),
            "name": m.group("name")
        })
    return items


@mcp.tool()
async def sleuthkit_healthcheck() -> str:
    """
    바이너리 상태 점검
    - file, mmstat, mmls, fls, istat, ifind, icat, tsk_recover 존재 여부
    """
    bins = ["file", "mmstat", "mmls", "fls", "istat", "ifind", "icat", "tsk_recover"]
    present = {b: bool(_which(b)) for b in bins}
    ok = all(present.values())
    return json.dumps({"ok": ok, "binaries": present})

@mcp.tool()
async def disk_info(image_path: str) -> str:
    """
    디스크 기본 정보(file) + 볼륨 개요(mmstat)
    - file: 이미지 포맷/특성 요약
    - mmstat: 멀티-볼륨/컨테이너 개요
    """
    out: Dict[str, Any] = {"image_path": image_path}
    file_ok = False

    if _which("file"):
        p1 = _run(["file", "-b", image_path])
        file_ok = (p1.returncode == 0)
        out["file"] = {"ok": file_ok, "stdout": p1.stdout, "stderr": p1.stderr}
    else:
        try:
            import magic
            info = magic.from_file(image_path)
            if "block special" in info.lower():
                info = "Raw disk image or block device (recognized as 'block special')"
            file_ok = True
            out["file"] = {"ok": True, "stdout": info, "stderr": ""}
        except ImportError:
            out["file"] = {
                "ok": False,
                "stdout": "",
                "stderr": "Neither 'file' command nor 'python-magic' module available"
            }
        except Exception as e:
            out["file"] = {"ok": False, "stdout": "", "stderr": f"magic detection failed: {e}"}

    p2 = _run(["mmstat", image_path])
    out["mmstat"] = {"ok": p2.returncode == 0, "stdout": p2.stdout, "stderr": p2.stderr}
    out["ok"] = (file_ok and p2.returncode == 0)
    return json.dumps(out)

@mcp.tool()
async def disk_partition_info(image_path: str) -> str:
    """
    파티션 테이블(mmls)
    - Start(섹터) 값을 파일시스템 오프셋(-o)로 사용
    """
    p = _run(["mmls", image_path])
    return json.dumps({"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr})

@mcp.tool()
async def search_inode_by_path(
    image_path: str,
    fs_offset_sectors: Union[int, float, str],
    path: str,
    imgtype: Optional[str] = "ewf",
    fstype: Optional[str] = "ntfs"
) -> str:
    """
    경로 → inode (ifind -n)
    - 이미지 내부 절대경로(/Users/<user>/Downloads 등)를 inode 목록으로 변환
    """
    cmd = ["ifind"]; _common_img_fs_opts(cmd, imgtype, fstype, fs_offset_sectors)
    cmd += ["-n", path, image_path]
    r = _run(cmd)
    inodes = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    return json.dumps({
        "ok": r.returncode == 0 and len(inodes) > 0,
        "path": path,
        "inodes": inodes,
        "stderr": r.stderr,
        "cmd": cmd
    })

@mcp.tool()
async def files_in_directory(
    image_path: str,
    fs_offset_sectors: Union[int, float, str],
    dir_inode: Optional[str] = None,
    path: Optional[str] = None,
    imgtype: Optional[str] = "ewf",
    fstype: Optional[str] = "ntfs",
    recursive: bool = False,
    show_full_paths: bool = True,
) -> str:
    """
    디렉터리 목록(fls)
    - inode 기준: fls ... <image> <inode>  (가장 안정적)
    - 경로 기준:  fls ... <image> <path> → 실패 시 fls ... <image> -- <path> 폴백
    - 반환: 파싱된 entries (type/inode/name)
    """
    flags = []
    if show_full_paths: flags.append("-p")
    if recursive: flags.append("-r")

    base = ["fls"] + flags
    _common_img_fs_opts(base, imgtype, fstype, fs_offset_sectors)

    if dir_inode and path:
        return json.dumps({"ok": False, "error": "Provide either dir_inode or path, not both"})

    if dir_inode:
        cmd = base + [image_path, dir_inode]
        p = _run(cmd)
        stdout = p.stdout
        parsed = _parse_fls(stdout) if p.returncode == 0 else []
        return json.dumps({
            "ok": p.returncode == 0,
            "entries": parsed,
            "count": len(parsed),
            "stderr": p.stderr,
            "cmd": cmd,
            "target": {"dir_inode": dir_inode},
            "stdout_head": "\n".join(stdout.splitlines()[:30]),
            "stdout_len": len(stdout)
        })

    if path:
        cmd1 = base + [image_path, path]
        p1 = _run(cmd1)
        if p1.returncode == 0:
            stdout = p1.stdout
            parsed = _parse_fls(stdout)
            return json.dumps({
                "ok": True,
                "entries": parsed,
                "count": len(parsed),
                "stderr": p1.stderr,
                "cmd": cmd1,
                "target": {"path": path},
                "stdout_head": "\n".join(stdout.splitlines()[:30]),
                "stdout_len": len(stdout)
            })

        cmd2 = base + [image_path, "--", path]
        p2 = _run(cmd2)
        ok = (p2.returncode == 0)
        stdout = p2.stdout
        parsed = _parse_fls(stdout) if ok else []
        return json.dumps({
            "ok": ok,
            "entries": parsed,
            "count": len(parsed),
            "stderr": p2.stderr,
            "cmd": cmd2,
            "target": {"path": path},
            "note": "Fallback with '--' applied" if ok else "Both direct and '--' forms failed",
            "stdout_head": "\n".join(stdout.splitlines()[:30]),
            "stdout_len": len(stdout)
        })

    return json.dumps({"ok": False, "error": "Provide either dir_inode or path"})

@mcp.tool()
async def extract_files_by_inode(
    image_path: str,
    fs_offset_sectors: Union[int, float, str],
    inodes: List[str],
    out_dir: str,
    names: Optional[List[str]] = None,
    include_slack: bool = False,
    recover_deleted: bool = True,
    imgtype: Optional[str] = "ewf",
    fstype: Optional[str] = "ntfs"
) -> str:
    """
    파일 추출(icat) - 배치
    - 여러 inode를 한 번에 추출
    - names가 있으면 해당 이름으로 저장(없으면 <inode>.bin)
    - 옵션: 슬랙 포함(-s), 삭제복구 시도(-r)
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    results = []
    for idx, inode in enumerate(inodes):
        fname = names[idx] if (names and idx < len(names) and names[idx]) else f"{inode}.bin"
        out_file = str(Path(out_dir) / fname)

        cmd = ["icat"]; _common_img_fs_opts(cmd, imgtype, fstype, fs_offset_sectors)
        _add_flag(cmd, include_slack, "-s"); _add_flag(cmd, recover_deleted, "-r")
        cmd += [image_path, inode]

        Path(Path(out_file).parent).mkdir(parents=True, exist_ok=True)
        with open(out_file, "wb") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=False)
        if p.returncode != 0:
            results.append({"inode": inode, "ok": False, "stderr": p.stderr.decode("utf-8", "ignore"), "cmd": cmd})
        else:
            results.append({"inode": inode, "ok": True, "saved": str(Path(out_file).resolve()),
                            "sha256": _sha256(out_file), "cmd": cmd})

    return json.dumps({"ok": any(x.get("ok") for x in results), "results": results,
                       "out_dir": str(Path(out_dir).resolve())})

@mcp.tool()
async def extract_directory_tree_by_inode(
    image_path: str,
    fs_offset_sectors: Union[int, float, str],
    dir_inode: str,
    out_dir: str,
    imgtype: Optional[str] = "ewf",
    fstype: Optional[str] = "ntfs"
) -> str:
    """
    디렉터리 트리 재귀 추출
    - fls -pr 로 하위 전체 나열 → 파일 항목만 icat
    - -p 사용 시 name이 Full path 형태이므로 동일한 트리 구조로 저장
    - ADS(:Zone.Identifier 등)도 inode 단위로 별도 저장
    """
    li = await files_in_directory(image_path, fs_offset_sectors, dir_inode=dir_inode,
                                  imgtype=imgtype, fstype=fstype, recursive=True, show_full_paths=True)
    data = json.loads(li)
    if not data.get("ok"):
        return json.dumps({"ok": False, "error": "fls failed", "detail": data})

    entries = data.get("entries", [])
    file_records = [e for e in entries if e.get("type","").startswith("r/") or e.get("type","")=="+"]

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    results = []
    for e in file_records:
        inode = e["inode"]; name = e["name"]
        out_path = Path(out_dir) / name.lstrip("/")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["icat"]; _common_img_fs_opts(cmd, imgtype, fstype, fs_offset_sectors)
        _add_flag(cmd, False, "-s"); _add_flag(cmd, True, "-r")
        cmd += [image_path, inode]
        with open(out_path, "wb") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=False)
        if p.returncode != 0:
            results.append({"inode": inode, "name": name, "ok": False, "stderr": p.stderr.decode("utf-8", "ignore")})
        else:
            results.append({"inode": inode, "name": name, "ok": True, "saved": str(out_path.resolve()), "sha256": _sha256(out_path)})

    return json.dumps({"ok": any(r["ok"] for r in results), "count": len(results), "results": results, "out_dir": str(Path(out_dir).resolve())})

@mcp.tool()
async def istat_metadata(
    image_path: str,
    fs_offset_sectors: Union[int, float, str],
    inode: str,
    imgtype: Optional[str] = "ewf",
    fstype: Optional[str] = "ntfs"
) -> str:
    """
    inode 메타정보(istat)
    - 타임스탬프, 사이즈, 데이터 런 등 확인
    """
    cmd = ["istat"]; _common_img_fs_opts(cmd, imgtype, fstype, fs_offset_sectors)
    cmd += [image_path, inode]
    p = _run(cmd)
    return json.dumps({"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr, "cmd": cmd})

if __name__ == "__main__":
    mcp.run(transport="stdio")
