"""Measure explicit cache locations; read-only and never clear an application cache."""
from collections import defaultdict
import ctypes
from ctypes import wintypes
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import stat
import time

from inspect_projects import adjusted_size, key, repository, tracked_files
from scan_disk import native, save_json

HERE = Path(__file__).resolve().parent
PROFILE = Path(r"C:\Users\MSI_NB")
LOCAL = PROFILE / "AppData/Local"
ROAMING = PROFILE / "AppData/Roaming"


def measure(path, mode="cache"):
    repo = repository(path)
    tracked = tracked_files(repo)
    totals = {"files": 0, "logical_bytes": 0, "adjusted_bytes": 0, "candidate_bytes": 0,
              "candidate_files": 0, "hardlinked_files_kept": 0, "tracked_files_kept": 0,
              "errors": 0, "reparse_skipped": 0, "nested_repositories_kept": 0}
    kinds = defaultdict(lambda: [0, 0])
    stack = [path]
    cutoff = time.time() - 7 * 86400
    while stack:
        folder = stack.pop()
        if folder != path and (folder / ".git").exists():
            totals["nested_repositories_kept"] += 1
            continue
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
                            if entry.name.lower() not in {".git", "localhistory"}:
                                stack.append(current)
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        size = adjusted_size(current, info)
                        totals["files"] += 1
                        totals["logical_bytes"] += info.st_size
                        totals["adjusted_bytes"] += size
                        ext = current.suffix.lower() or "[no extension]"
                        kinds[ext][0] += 1
                        kinds[ext][1] += size
                        if tracked is not None and key(current) in tracked:
                            totals["tracked_files_kept"] += 1
                            continue
                        if mode == "old_temp" and (info.st_mtime >= cutoff or ext not in {".tmp", ".temp", ".log", ".dmp"}):
                            continue
                        full_info = os.stat(native(str(current)), follow_symlinks=False)
                        if full_info.st_nlink > 1:
                            totals["hardlinked_files_kept"] += 1
                            continue
                        totals["candidate_bytes"] += size
                        totals["candidate_files"] += 1
                    except OSError:
                        totals["errors"] += 1
        except OSError:
            totals["errors"] += 1
    return {"path": str(path), "mode": mode, "repository": str(repo) if repo else None,
            "git_status": "tracked files excluded" if repo else "outside a detected Git repository; identified by application cache location and formats",
            **totals, "types": [{"type": k, "files": v[0], "bytes": v[1]}
                                for k, v in sorted(kinds.items(), key=lambda item: item[1][1], reverse=True)[:20]]}


def main():
    inventory = json.loads((HERE / "full_access/inventory_C.json").read_text(encoding="utf-8"))
    targets = [("C1", PROFILE / ".gradle/caches", "cache"),
               ("C2", PROFILE / ".lldb/module_cache", "cache"),
               ("C4", LOCAL / "Temp", "old_temp"),
               ("C4", LOCAL / "CrashDumps", "old_temp")]
    # Only explicit IDE caches/indexes; Local History, plugins, settings, SDKs are not included.
    for row in inventory["directories"]:
        path = Path(row["path"])
        lower = key(path)
        if path.name.lower() in {"caches", "index"} and path.parent.parent in {LOCAL / "JetBrains", LOCAL / "Google"}:
            targets.append(("C2", path, "cache"))
        # Chromium resource/compiled-code/GPU caches, not profile databases, sessions, or offline storage.
        if path.name.lower() in {"cache", "code cache", "gpucache"} and row["bytes"] > 1024 ** 2:
            approved = [LOCAL / "Microsoft/Edge/User Data", ROAMING / "Code", ROAMING / "Cursor"]
            if any(lower.startswith(key(base) + "\\") for base in approved):
                if not any(part.lower() in {"node_modules", "extensions", "globalstorage", "workspacestorage", "history", "backups"} for part in path.parts):
                    targets.append(("C3", path, "cache"))
    roots = []
    for group, path, mode in sorted(targets, key=lambda row: len(str(row[1]))):
        if not path.is_dir() or any(key(path) == key(p) or key(path).startswith(key(p) + "\\") for _, p, _ in roots):
            continue
        roots.append((group, path, mode))
    results = []
    for index, (group, path, mode) in enumerate(roots):
        result = measure(path, mode)
        results.append({"group": group, **result})
        print(json.dumps({"completed": index + 1, "total": len(roots), "group": group,
                          "path": str(path), "candidate_gib": round(result["candidate_bytes"] / 2**30, 3)}, ensure_ascii=True), flush=True)
    save_json(HERE / "cache_candidates.json", {"scanned_at": dt.datetime.now().astimezone().isoformat(),
              "items": results, "limitations": "Candidate bytes account for compressed/sparse file sizes and exclude files with multiple hard links. Actual release depends on locks, filesystem allocation and concurrent writes. Cache clearing requires the relevant application to be idle or closed."})
    volumes = {}
    for drive in ("C:\\", "D:\\"):
        volumes[drive] = dict(zip(("total", "used", "free"), shutil.disk_usage(drive)))
    save_json(HERE / "volumes_latest.json", {"at": dt.datetime.now().astimezone().isoformat(), "volumes": volumes})


if __name__ == "__main__":
    main()
