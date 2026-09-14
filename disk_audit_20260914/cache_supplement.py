"""Read-only expansion of C-drive cache locations, including all name matches.

The inventory is an index, not a deletion list. Freshly inspect all maximal
cache roots >= 8 MiB and explicit generic cache roots, without following links.
Only file metadata and up to 16 signature bytes from a few large binary samples
are read. No content is uploaded and no cleanup operations are implemented.
"""
from collections import Counter, defaultdict
import datetime as dt
import heapq
import json
import os
from pathlib import Path
import stat
import sys
import time

from inspect_projects import adjusted_size, inside, key, repository, tracked_files
from scan_disk import native, save_json

HERE = Path(__file__).resolve().parent
PROFILE = Path(r"C:\Users\MSI_NB")
EXPLICIT = [Path(r"C:\cache"), Path(r"C:\.cache"), PROFILE / ".cache",
            PROFILE / "AppData/Local/cache", PROFILE / ".codex/cache"]


def signature(path):
    try:
        info = os.stat(native(path), follow_symlinks=False)
        if info.st_file_attributes & (0x400 | 0x1000 | 0x400000):
            return "未读取：链接或云占位文件"
        with open(native(path), "rb") as handle:
            data = handle.read(16)
    except OSError:
        return "文件头不可读"
    for magic, label in [(b"PK\x03\x04", "ZIP 格式归档"), (b"MZ", "Windows PE 程序/库"),
                         (b"\x1f\x8b", "gzip 压缩数据"), (b"7z\xbc\xaf\x27\x1c", "7z 归档"),
                         (b"\xfd7zXZ\x00", "XZ 压缩数据"), (b"\x28\xb5\x2f\xfd", "Zstandard 压缩数据"),
                         (b"Cr24", "Chromium CRX 扩展/组件包"), (b"SQLite format 3", "SQLite 数据库"),
                         (b"fLaC", "FLAC 音频"), (b"ID3", "MP3 音频"),
                         (b"\x7fELF", "ELF 程序/库"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/MSI 类容器")]:
        if data.startswith(magic):
            return label
    return "未由文件头确定格式"


def probe(root):
    started = time.monotonic()
    root = Path(root)
    try:
        info = os.stat(native(str(root)), follow_symlinks=False)
    except OSError as error:
        return {"path": str(root), "status": "missing" if error.winerror in (2,3) else "unreadable", "error": str(error)}
    if info.st_file_attributes & 0x400:
        return {"path": str(root), "status": "reparse_skipped"}
    repo = repository(root)
    tracked = tracked_files(repo)
    totals = Counter()
    types = defaultdict(Counter)
    children = defaultdict(Counter)
    largest = []
    identities = set()
    errors = []
    tracked_samples = []
    stack = [(root, tracked)]
    while stack:
        folder, folder_tracked = stack.pop()
        if folder != root and (folder / ".git").exists():
            folder_tracked = tracked_files(folder)
            totals["nested_git_repositories"] += 1
        try:
            with os.scandir(native(str(folder))) as iterator:
                for entry in iterator:
                    current = folder / entry.name
                    relative = current.relative_to(root)
                    child = relative.parts[0]
                    children[child]["seen"] += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if info.st_file_attributes & 0x400:
                            totals["reparse_skipped"] += 1
                            children[child]["reparse_skipped"] += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            totals["directories"] += 1
                            children[child]["directories"] += 1
                            if entry.name != ".git":
                                stack.append((current, folder_tracked))
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        size = adjusted_size(current, info)
                        full = os.stat(native(str(current)), follow_symlinks=False)
                        if full.st_file_attributes & 0x400:
                            totals["reparse_skipped"] += 1
                            continue
                        ext = current.suffix.lower() or "[无扩展名]"
                        is_tracked = folder_tracked is not None and key(current) in folder_tracked
                        values = {"files": 1, "logical_bytes": info.st_size, "adjusted_bytes": size,
                                  "old7_bytes": size if info.st_mtime < time.time() - 7*86400 else 0,
                                  "old30_bytes": size if info.st_mtime < time.time() - 30*86400 else 0,
                                  "multiple_link_files": int(full.st_nlink > 1),
                                  "multiple_link_bytes": size if full.st_nlink > 1 else 0,
                                  "tracked_files": int(is_tracked),
                                  "tracked_bytes": size if is_tracked else 0,
                                  "single_link_untracked_bytes": size if full.st_nlink == 1 and not is_tracked else 0}
                        identity = (full.st_dev, full.st_ino) if full.st_ino else ("path", key(current))
                        if identity not in identities:
                            identities.add(identity)
                            totals["identity_unique_adjusted_bytes"] += size
                        totals.update(values)
                        children[child].update(values)
                        types[ext].update({"files": 1, "bytes": size})
                        if is_tracked and len(tracked_samples)<5:
                            tracked_samples.append(str(current))
                        item = (info.st_size, str(current), info.st_mtime)
                        if len(largest) < 8:
                            heapq.heappush(largest, item)
                        elif item > largest[0]:
                            heapq.heapreplace(largest,item)
                    except OSError as error:
                        totals["errors"] += 1
                        children[child]["errors"] += 1
                        if len(errors)<6:
                            errors.append({"path":str(current),"error":str(error)})
        except OSError as error:
            totals["errors"] += 1
            if len(errors)<6:
                errors.append({"path":str(folder),"error":str(error)})
    files = [{"path":p,"bytes":s,"mtime":m,
              "signature":signature(p) if s>=1024**2 else "小文件未读取文件头"} for s,p,m in sorted(largest,reverse=True)]
    return {"path":str(root), "status":"partial" if totals["errors"] else "measured",
            "measured_at":dt.datetime.now().astimezone().isoformat(), "elapsed_seconds":round(time.monotonic()-started,2),
            "repository":str(repo) if repo else None, "metrics":dict(totals),
            "immediate_children":[{"name":n,**dict(v)} for n,v in sorted(children.items(),key=lambda item:item[1]["adjusted_bytes"],reverse=True)],
            "types":[{"type":n,**dict(v)} for n,v in sorted(types.items(),key=lambda item:item[1]["bytes"],reverse=True)[:20]],
            "largest_files":files,"errors_sample":errors,"tracked_samples":tracked_samples}


def main():
    source = json.loads((HERE / "full_access/inventory_C.json").read_text(encoding="utf-8"))
    matches = [x for x in source["directories"] if "cache" in Path(x["path"]).name.lower()]
    maximal = []
    for row in sorted(matches,key=lambda row:len(row["path"])):
        if not any(inside(row["path"],x["path"]) for x in maximal):
            maximal.append(row)
    targets = [Path(x["path"]) for x in maximal if x["bytes"]>=8*1024**2]
    for path in EXPLICIT:
        if path not in targets:
            targets.append(path)
    targets.sort(key=lambda p:(0 if p in EXPLICIT else 1,str(p).lower()))
    results = []
    for index,path in enumerate(targets):
        result = probe(path)
        results.append(result)
        if index%5==0 or index==len(targets)-1:
            save_json(HERE / "cache_supplement.json", {"source_scanned_at":source["scanned_at"],
                      "generated_at":dt.datetime.now().astimezone().isoformat(),
                      "progress":{"completed":index+1,"total":len(targets)},
                      "matched_directory_count":len(matches),"maximal_root_count":len(maximal),
                      "snapshot_matches":matches,"snapshot_maximal_roots":maximal,"fresh_roots":results,
                      "no_cleanup_performed":True,
                      "limitations":["Only roots >=8 MiB and explicit generic cache roots are freshly profiled; smaller roots retain snapshot metadata.",
                                      "Overlapping directory sizes must not be added. File identities are deduplicated only within each fresh root, not across separate roots.",
                                      "Single-link untracked byte counts are measurements, not cleanup recommendations.",
                                      "Cache paths may contain application state, installed code, model weights, or source files."]})
        print(json.dumps({"completed":index+1,"total":len(targets),"path":str(path),"status":result["status"],
                          "gib":round(result.get("metrics",{}).get("logical_bytes",0)/2**30,3)},ensure_ascii=True),flush=True)


if __name__ == "__main__":
    main()
