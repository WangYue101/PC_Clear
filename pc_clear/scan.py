"""Inventory every accessible regular file; never follow links or delete data."""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import time

REPARSE = 0x400


def native(path):
    text = os.path.abspath(path)
    if os.name == 'nt' and not text.startswith('\\\\?\\'):
        return '\\\\?\\' + text
    return text


def stamp():
    return dt.datetime.now().astimezone().isoformat(timespec='seconds')


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def beneath(path, parent):
    try:
        return os.path.commonpath((os.path.abspath(path), os.path.abspath(parent))) == os.path.abspath(parent)
    except ValueError:
        return False


def inventory(root: Path, output: Path, excludes=()):
    root, output = root.absolute(), output.absolute()
    root_info = os.stat(native(root), follow_symlinks=False)
    if getattr(root_info, 'st_file_attributes', 0) & REPARSE or stat.S_ISLNK(root_info.st_mode):
        raise ValueError('A scan root must not be a link/reparse point')
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError('Scan root is not a directory')
    if root == output or beneath(root, output):
        raise ValueError('Output must not contain the scan root')
    output.mkdir(parents=True, exist_ok=True)
    database = output / 'inventory.sqlite'
    if database.exists():
        raise FileExistsError(f'Refusing to overwrite existing inventory: {database}')
    exclusions = [output] + [Path(p).absolute() for p in excludes]
    connection = sqlite3.connect(database)
    connection.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA cache_size=-32768;
        CREATE TABLE directories(id INTEGER PRIMARY KEY, parent INTEGER, path TEXT NOT NULL,
            depth INTEGER NOT NULL, own_bytes INTEGER DEFAULT 0, own_files INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0, total_files INTEGER DEFAULT 0,
            newest REAL DEFAULT 0, oldest REAL DEFAULT 0, errors INTEGER DEFAULT 0,
            skipped INTEGER DEFAULT 0, repository INTEGER DEFAULT 0);
        CREATE TABLE files(id INTEGER PRIMARY KEY, directory INTEGER NOT NULL, name TEXT NOT NULL,
            extension TEXT NOT NULL, bytes INTEGER NOT NULL, mtime REAL NOT NULL,
            attributes INTEGER NOT NULL);
        CREATE TABLE gaps(path TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT, bytes INTEGER DEFAULT 0);
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''')
    count = Counter()
    started = time.monotonic()
    scan_time = time.time()
    last_progress = 0
    before = dict(zip(('total','used','free'), shutil.disk_usage(root)))
    # A directory record is allocated before its children. Reverse IDs are postorder.
    directories = [[0, str(root), 0, 0, 0, 0, 0, 0.0, scan_time, 0, 0, 0]]
    connection.execute('INSERT INTO directories(id,parent,path,depth) VALUES(1,NULL,?,0)', (str(root),))
    stack = [1]
    pending_files = []
    pending_gaps = []

    def flush():
        if pending_files:
            connection.executemany('INSERT INTO files(directory,name,extension,bytes,mtime,attributes) VALUES(?,?,?,?,?,?)', pending_files)
            pending_files.clear()
        if pending_gaps:
            connection.executemany('INSERT INTO gaps(path,reason,detail,bytes) VALUES(?,?,?,?)', pending_gaps)
            pending_gaps.clear()
        connection.commit()

    def progress(force=False):
        nonlocal last_progress
        now = time.monotonic()
        if force or now - last_progress >= 10:
            last_progress = now
            flush()
            data = {'root':str(root), 'complete':False, 'at':stamp(), 'elapsed_seconds':round(now-started),
                    **dict(count), 'database_bytes':database.stat().st_size}
            write_json(output/'progress.json', data)
            print(json.dumps(data, ensure_ascii=True), flush=True)

    try:
        while stack:
            ident = stack.pop()
            record = directories[ident-1]
            parent, folder, depth = record[:3]
            count['directories'] += 1
            child_rows = []
            try:
                with os.scandir(native(folder)) as entries:
                    for entry in entries:
                        path = os.path.join(folder, entry.name)
                        if entry.name.lower() == '.git':
                            record[11] = 1
                        try:
                            info = entry.stat(follow_symlinks=False)
                            attributes = getattr(info, 'st_file_attributes', 0)
                            if attributes & REPARSE or stat.S_ISLNK(info.st_mode):
                                record[10] += 1
                                count['reparse_skipped'] += 1
                                pending_gaps.append((path, 'reparse', 'Not followed', info.st_size))
                                continue
                            if stat.S_ISDIR(info.st_mode):
                                if any(beneath(path, exclusion) for exclusion in exclusions):
                                    count['explicit_exclusions'] += 1
                                    record[10] += 1
                                    pending_gaps.append((path, 'scan_exclusion', 'Own output or configured scan exclusion', 0))
                                    continue
                                child = len(directories) + 1
                                directories.append([ident,path,depth+1,0,0,0,0,0.0,scan_time,0,0,0])
                                child_rows.append((child,ident,path,depth+1))
                                stack.append(child)
                            elif stat.S_ISREG(info.st_mode):
                                count['files'] += 1
                                count['logical_bytes'] += info.st_size
                                record[3] += info.st_size
                                record[4] += 1
                                record[7] = max(record[7], info.st_mtime)
                                record[8] = min(record[8], info.st_mtime)
                                extension = os.path.splitext(entry.name)[1].lower()
                                pending_files.append((ident,entry.name,extension,info.st_size,info.st_mtime,attributes))
                        except OSError as error:
                            record[9] += 1
                            count['errors'] += 1
                            pending_gaps.append((path,'unreadable',str(error),0))
                        if len(pending_files) >= 5000:
                            flush()
                        progress()
            except OSError as error:
                record[9] += 1
                count['errors'] += 1
                pending_gaps.append((folder,'unreadable',str(error),0))
            connection.executemany('INSERT INTO directories(id,parent,path,depth) VALUES(?,?,?,?)', child_rows)
            progress()
        flush()
        # Aggregate all directories, including small/non-cache directories.
        for ident in range(len(directories), 0, -1):
            row = directories[ident-1]
            row[5] += row[3]
            row[6] += row[4]
            if row[0]:
                parent = directories[row[0]-1]
                parent[5] += row[5]
                parent[6] += row[6]
                parent[7] = max(parent[7], row[7])
                parent[8] = min(parent[8], row[8])
                parent[9] += row[9]
                parent[10] += row[10]
        connection.executemany('''UPDATE directories SET own_bytes=?,own_files=?,total_bytes=?,total_files=?,
            newest=?,oldest=?,errors=?,skipped=?,repository=? WHERE id=?''',
            ((r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11],i) for i,r in enumerate(directories,1)))
        connection.executescript('CREATE INDEX files_directory ON files(directory); CREATE INDEX directories_parent ON directories(parent);')
        result = {'root':str(root),'complete':True,'started_epoch':scan_time,'finished_at':stamp(),
                  'elapsed_seconds':round(time.monotonic()-started),**dict(count),
                  'volume_before':before,'volume_after':dict(zip(('total','used','free'),shutil.disk_usage(root))),
                  'scan_excludes':[str(p) for p in exclusions],
                  'limitations':['Logical bytes are not allocated bytes; hard links may repeat.',
                                 'Modification time is not last-use time or proof of obsolescence.',
                                 'Live scan; denied paths and reparse points remain coverage gaps.',
                                 'No file content, cleanup, process termination, or permission changes.']}
        connection.execute('INSERT INTO metadata(key,value) VALUES(?,?)',('summary',json.dumps(result)))
        connection.commit()
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        write_json(output/'summary.json',result)
        print(json.dumps(result,ensure_ascii=True),flush=True)
        return result
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--exclude',type=Path,action='append',default=[])
    parser.add_argument('--policy',type=Path,default=Path(__file__).resolve().parents[1]/'scan_policy.json')
    args = parser.parse_args()
    settings = json.loads(args.policy.read_text(encoding='utf-8-sig'))
    inventory(args.root,args.output,args.exclude+[Path(os.path.expandvars(p)) for p in settings.get('scan_excludes',[])])


if __name__ == '__main__':
    main()
