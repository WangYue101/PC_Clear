"""Read-only Git/file-type audit of generated D-drive files. No cleanup code."""
from __future__ import annotations

from collections import defaultdict
import ctypes
from ctypes import wintypes
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from scan_disk import native, save_json

HERE = Path(__file__).resolve().parent
GIT = r"C:\Users\MSI_NB\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe"
SCRATCH = Path(r"D:\Work\Gitlab\imp\.scratch")
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
COMPRESSED_SIZE = KERNEL.GetCompressedFileSizeW
COMPRESSED_SIZE.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
COMPRESSED_SIZE.restype = wintypes.DWORD
TRACKED = {}


def key(path):
    return os.path.normcase(os.path.abspath(str(path)))


def inside(path, parent):
    p, q = key(path), key(parent)
    return p == q or p.startswith(q.rstrip("\\") + "\\")


def git(repo, *args):
    # Trust only this explicitly inspected repository for this read-only command.
    # No global Git configuration or index refresh is performed.
    result = subprocess.run([GIT, "--no-optional-locks", "-c", f"safe.directory={repo.as_posix()}",
                             "-C", str(repo), *args], capture_output=True, timeout=90)
    return result


def repository(path):
    current = Path(path)
    for parent in (current, *current.parents):
        if (parent / ".git").exists():
            return parent
    return None


def tracked_files(repo):
    if repo is None:
        return None
    if key(repo) not in TRACKED:
        result = git(repo, "ls-files", "--cached", "-z")
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace"))
        TRACKED[key(repo)] = {key(repo / name.decode("utf-8", "surrogateescape"))
                              for name in result.stdout.split(b"\0") if name}
    return TRACKED[key(repo)]


def ignore_evidence(repo, path):
    if repo is None:
        return {"ignored": False, "rule": "No Git repository found"}
    relative = Path(path).relative_to(repo).as_posix() + "/"
    result = git(repo, "check-ignore", "-v", "--", relative)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    return {"ignored": result.returncode == 0, "rule": result.stdout.decode("utf-8", "replace").strip()}


def adjusted_size(path, info):
    if info.st_file_attributes & (0x200 | 0x800):
        high = wintypes.DWORD()
        ctypes.set_last_error(0)
        low = COMPRESSED_SIZE(native(str(path)), ctypes.byref(high))
        if low == 0xFFFFFFFF and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        return (high.value << 32) | low
    return info.st_size


DB_EXTENSIONS = {".ibd", ".myd", ".myi", ".sdi", ".dblwr", ".ibt"}
BUILD_EXTENSIONS = {".class", ".dex", ".jar", ".aar", ".so", ".o", ".obj", ".a", ".lib",
                    ".bin", ".dat", ".cache", ".flat", ".apk", ".zip", ".kotlin_module",
                    ".kotlin_builtins", ".hprof", ".pak", ".tlog", ".pdb", ".res", ".bc"}


def eligible_type(path, kind):
    name = path.name.lower()
    if kind == "mysql_test_data":
        return (path.suffix.lower() in DB_EXTENSIONS or name == "ib_buffer_pool"
                or re.fullmatch(r"(?:ibdata|ibtmp)\d+|undo_\d+|#ib_redo\d+(?:_tmp)?", name) is not None
                or re.fullmatch(r"(?:binlog|mysql-bin|relay-bin)\.(?:\d+|index)", name) is not None)
    return path.suffix.lower() in BUILD_EXTENSIONS


def inspect(path, kind, active_paths):
    repo = repository(path)
    tracked = tracked_files(repo)
    ignored = ignore_evidence(repo, path)
    totals = {"files": 0, "logical_bytes": 0, "adjusted_bytes": 0, "eligible_files": 0,
              "eligible_adjusted_bytes": 0, "tracked_files": 0, "tracked_bytes": 0,
              "shared_link_files": 0, "errors": 0, "reparse_skipped": 0,
              "preserved_other_type_bytes": 0, "newest_mtime": 0}
    types = defaultdict(lambda: [0, 0, 0])
    preserved = []
    failures = []
    stack = [path]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(native(str(folder))) as entries:
                for entry in entries:
                    current = folder / entry.name
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if info.st_file_attributes & 0x400:
                            totals["reparse_skipped"] += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(current)
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        size = adjusted_size(current, info)
                        totals["files"] += 1
                        totals["logical_bytes"] += info.st_size
                        totals["adjusted_bytes"] += size
                        totals["newest_mtime"] = max(totals["newest_mtime"], info.st_mtime)
                        ext = current.suffix.lower() or "[no extension]"
                        if kind == "mysql_test_data" and eligible_type(current, kind) and ext not in DB_EXTENSIONS:
                            ext = "[InnoDB/binlog system files]"
                        types[ext][0] += 1
                        types[ext][1] += info.st_size
                        types[ext][2] += size
                        if tracked is not None and key(current) in tracked:
                            totals["tracked_files"] += 1
                            totals["tracked_bytes"] += size
                        elif eligible_type(current, kind):
                            # DirEntry.stat on Windows lacks hard-link identifiers; os.stat provides them.
                            full_info = os.stat(native(str(current)), follow_symlinks=False)
                            if full_info.st_nlink > 1:
                                totals["shared_link_files"] += 1
                            else:
                                totals["eligible_files"] += 1
                                totals["eligible_adjusted_bytes"] += size
                        else:
                            totals["preserved_other_type_bytes"] += size
                            if len(preserved) < 8:
                                preserved.append(str(current))
                    except OSError as exc:
                        totals["errors"] += 1
                        if len(failures) < 5:
                            failures.append(str(exc))
        except OSError as exc:
            totals["errors"] += 1
            if len(failures) < 5:
                failures.append(str(exc))
    active = [p for p in active_paths if inside(p, path) or inside(path, p)]
    age = (time.time() - totals["newest_mtime"]) / 3600 if totals["newest_mtime"] else None
    status = ("active_keep" if active else "git_unverified_keep" if tracked is None or not ignored["ignored"]
              else "incomplete_keep" if totals["errors"] or totals["reparse_skipped"]
              else "recent_keep" if age is None or age < 24 else "candidate")
    return {"path": str(path), "kind": kind, "repository": str(repo) if repo else None,
            "git": ignored, "status": status, "active_data_directories": active,
            "newest_file_age_hours": round(age, 2) if age is not None else None,
            **totals, "types": [{"type": k, "files": v[0], "logical_bytes": v[1], "adjusted_bytes": v[2]}
                                for k, v in sorted(types.items(), key=lambda item: item[1][2], reverse=True)],
            "preserved_samples": preserved, "errors_sample": failures}


def main():
    inventory = json.loads((HERE / "inventory_D.json").read_text(encoding="utf-8"))
    processes = json.loads((HERE / "database_processes.json").read_text(encoding="utf-8-sig"))
    active = [p["DataDirectory"].strip('"') for p in processes["Processes"] if p["DataDirectory"]]
    roots = []
    for row in inventory["directories"]:
        path = Path(row["path"])
        if path.name.lower() == "data" and inside(path, SCRATCH) and (path / "ibdata1").is_file():
            roots.append((path, "mysql_test_data"))
        if path.name.lower() == "build" and row["bytes"] >= 16 * 1024 ** 2:
            if not any((path.parent / marker).is_file() for marker in ("build.gradle", "build.gradle.kts")):
                continue
            if any(part.lower() in {"node_modules", "site-packages", ".git", ".venv", "venv"} for part in path.parts):
                continue
            for child_name in ("intermediates", ".transforms", "kotlin", "snapshot", "tmp"):
                child = path / child_name
                if child.is_dir():
                    roots.append((child, "android_build_binary"))
    results = []
    started = time.monotonic()
    for index, (path, kind) in enumerate(roots):
        result = inspect(path, kind, active)
        results.append(result)
        if index % 12 == 0 or index == len(roots) - 1:
            save_json(HERE / "project_candidates.json", {"scanned_at": dt.datetime.now().astimezone().isoformat(),
                      "completed": index + 1, "total": len(roots), "process_snapshot": processes,
                      "policy": "Read-only. Candidate requires Git-ignored location, excludes tracked files, unknown types, hard links, reparse points, active DB paths, and filesets changed within 24 hours.",
                      "items": results})
            print(json.dumps({"completed": index + 1, "total": len(roots), "elapsed_seconds": round(time.monotonic()-started),
                              "path": str(path), "status": result["status"]}, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
