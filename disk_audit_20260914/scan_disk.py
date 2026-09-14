"""Read-only Windows disk inventory. Writes reports only to --output.

No file contents are opened and no deletion, process termination, or system
configuration changes are implemented. Reparse points are never traversed.
Directory totals are logical bytes, not promises of reclaimable disk space.
"""
from __future__ import annotations

import argparse
import datetime as dt
import heapq
import json
import os
from pathlib import Path
import shutil
import stat
import time

MIB = 1024 ** 2
GIB = 1024 ** 3
REPARSE = 0x400


def native(path: str) -> str:
    if os.name == "nt" and not path.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(path)
    return path


def save_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


class Scanner:
    def __init__(self, root: str, minimum: int):
        self.root = os.path.abspath(root)
        self.minimum = minimum
        self.now = time.time()
        self.started = time.monotonic()
        self.last_progress = self.started
        self.files = 0
        self.folders = 0
        self.logical_bytes = 0
        self.directories = []
        self.largest = []
        self.root_files = []
        self.errors = []
        self.error_count = 0
        self.links = []
        self.link_count = 0

    def error(self, path: str, exc: OSError):
        self.error_count += 1
        if len(self.errors) < 400:
            self.errors.append({"path": path, "error": str(exc), "winerror": getattr(exc, "winerror", None)})

    def progress(self, path: str, force: bool = False):
        current = time.monotonic()
        if force or current - self.last_progress >= 8:
            self.last_progress = current
            print(json.dumps({"event": "progress", "drive": self.root,
                              "files": self.files, "directories": self.folders,
                              "logical_gib": round(self.logical_bytes / GIB, 2),
                              "errors": self.error_count, "reparse_skipped": self.link_count,
                              "elapsed_seconds": round(current - self.started), "path": path},
                             ensure_ascii=True), flush=True)

    @staticmethod
    def interesting(path: str) -> bool:
        name = os.path.basename(path).lower()
        return (any(word in name for word in ("cache", "temp", "crash", "dump", "recycle"))
                or name in {".gradle", ".m2", ".pnpm-store", ".npm", ".nuget", "pkgs",
                            "logs", "node_modules", ".venv", "venv", "envs", "blobs",
                            "downloads", "shadercache", "gpuCache", "dist", "build"})

    def walk(self, path: str, depth: int = 0):
        # bytes, files, old7_bytes, old30_bytes, directories, errors, skipped
        totals = [0, 0, 0, 0, 1, 0, 0]
        own_bytes = 0
        children = []
        self.folders += 1
        self.progress(path)
        try:
            with os.scandir(native(path)) as entries:
                for entry in entries:
                    child = os.path.join(path, entry.name)
                    try:
                        info = entry.stat(follow_symlinks=False)
                        attributes = getattr(info, "st_file_attributes", 0)
                        if attributes & REPARSE or entry.is_symlink():
                            self.link_count += 1
                            totals[6] += 1
                            if len(self.links) < 500:
                                link = {"path": child, "attributes": attributes}
                                try:
                                    link["target"] = os.readlink(native(child))
                                except (OSError, ValueError):
                                    link["target"] = None
                                self.links.append(link)
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            children.append(child)
                        elif stat.S_ISREG(info.st_mode):
                            size = info.st_size
                            totals[0] += size
                            totals[1] += 1
                            own_bytes += size
                            self.files += 1
                            self.logical_bytes += size
                            if info.st_mtime < self.now - 7 * 86400:
                                totals[2] += size
                            if info.st_mtime < self.now - 30 * 86400:
                                totals[3] += size
                            if depth == 0:
                                self.root_files.append({"path": child, "bytes": size, "attributes": attributes})
                            item = (size, child, info.st_mtime, attributes)
                            if len(self.largest) < 150:
                                heapq.heappush(self.largest, item)
                            elif item > self.largest[0]:
                                heapq.heapreplace(self.largest, item)
                    except OSError as exc:
                        totals[5] += 1
                        self.error(child, exc)
                    self.progress(path)
        except OSError as exc:
            totals[5] += 1
            self.error(path, exc)
        # Reach the user's data and obvious caches early, while still scanning all ordinary directories.
        children.sort(key=lambda p: (0 if self.interesting(p) else 1 if os.path.basename(p).lower() in
                                     {"users", "msi_nb", "appdata", "local", "roaming", "i"} else 2, p.lower()))
        for child in children:
            values = self.walk(child, depth + 1)
            for index, value in enumerate(values):
                totals[index] += value
        if totals[0] >= self.minimum or depth <= 3 or self.interesting(path):
            self.directories.append({"path": path, "depth": depth, "bytes": totals[0],
                                     "own_bytes": own_bytes, "files": totals[1],
                                     "modified_over_7_days_bytes": totals[2],
                                     "modified_over_30_days_bytes": totals[3],
                                     "directories": totals[4], "errors": totals[5],
                                     "reparse_skipped": totals[6]})
        return totals

    def run(self):
        before = shutil.disk_usage(self.root)
        totals = self.walk(self.root)
        after = shutil.disk_usage(self.root)
        self.progress(self.root, True)
        return {"root": self.root, "scanned_at": dt.datetime.now().astimezone().isoformat(),
                "elapsed_seconds": round(time.monotonic() - self.started, 1),
                "volume_before": dict(zip(("total", "used", "free"), before)),
                "volume_after": dict(zip(("total", "used", "free"), after)),
                "logical_bytes_scanned": totals[0], "files_scanned": self.files,
                "directories_scanned": self.folders, "errors_count": self.error_count,
                "reparse_skipped_count": self.link_count, "errors_sample": self.errors,
                "reparse_sample": self.links, "root_files": self.root_files,
                "directories": sorted(self.directories, key=lambda item: item["bytes"], reverse=True),
                "largest_files": [{"bytes": s, "path": p, "mtime": m, "attributes": a}
                                  for s, p, m, a in sorted(self.largest, reverse=True)],
                "limitations": ["Logical size can double-count NTFS hard links and differ from allocated size.",
                                "Unreadable paths and reparse points are skipped and reported.",
                                "File modification age is not proof of last use or disposability.",
                                "A live scan is not a filesystem snapshot."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drives", nargs="+", default=["D:\\", "C:\\"])
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--min-size-mib", type=float, default=16)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    summary = []
    for root in args.drives:
        result = Scanner(root, int(args.min_size_mib * MIB)).run()
        letter = Path(os.path.abspath(root)).drive.replace(":", "") or "root"
        save_json(args.output / f"inventory_{letter}.json", result)
        brief = {k: v for k, v in result.items() if k not in
                 {"directories", "largest_files", "errors_sample", "reparse_sample", "root_files"}}
        summary.append(brief)
        save_json(args.output / "summary.json", summary)
        print(json.dumps({"event": "drive_complete", **brief}, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
