"""Local, read-only Git and Windows application evidence."""
from __future__ import annotations
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from .rules import norm
from .scan import native, stamp


def git_executable():
    found = shutil.which('git')
    if found:
        return found
    candidate = Path(os.environ.get('USERPROFILE',''))/'.cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/cmd/git.exe'
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError('Git executable unavailable')


def git_run(repo, arguments, input_data=None):
    return subprocess.run([git_executable(),'--no-optional-locks','-c',f'safe.directory={Path(repo).as_posix()}',
                           '-C',str(repo),*arguments],input=input_data,capture_output=True,timeout=60)


def git_filter(repo, paths):
    """Return dispositions; failure never turns into permission to clean."""
    try:
        result = git_run(repo,['ls-files','--cached','-z'])
        if result.returncode:
            return {p:'git_unverified' for p in paths}, result.stderr.decode('utf-8','replace')[:300]
        tracked = {norm(Path(repo)/p.decode('utf-8','surrogateescape')) for p in result.stdout.split(b'\0') if p}
        answer = {p:'tracked' if norm(p) in tracked else 'untracked_not_ignored' for p in paths}
        remaining = [p for p in paths if answer[p] != 'tracked']
        for offset in range(0,len(remaining),2000):
            batch = remaining[offset:offset+2000]
            result = git_run(repo,['check-ignore','--stdin','-z'],b'\0'.join(p.encode('utf-8','surrogateescape') for p in batch)+b'\0')
            if result.returncode not in (0,1):
                return {p:'git_unverified' for p in paths}, result.stderr.decode('utf-8','replace')[:300]
            ignored = {norm(p.decode('utf-8','surrogateescape')) for p in result.stdout.split(b'\0') if p}
            for p in batch:
                if norm(p) in ignored:
                    answer[p] = 'ignored_untracked'
        return answer, ''
    except (OSError,subprocess.SubprocessError):
        return {p:'git_unverified' for p in paths}, 'Git query unavailable or timed out'


def powershell_json(command):
    code = '[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); ' + command
    result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],
                            capture_output=True,timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8','replace')[:300])
    text = result.stdout.decode('utf-8-sig').strip()
    if not text:
        return []
    data = json.loads(text)
    return data if isinstance(data,list) else [data]


def option(text, name):
    match = re.search(r'--'+re.escape(name)+r'(?:=|\s+)(?:"([^"]+)"|(\S+))', text or '', re.I)
    return (match.group(1) or match.group(2)).rstrip('"') if match else None


def database_dir(command):
    direct = option(command,'datadir')
    if direct:
        return direct
    config = option(command,'defaults-file')
    if config:
        try:
            text = Path(config).read_text(encoding='utf-8-sig',errors='replace')
            matches = re.findall(r'^\s*datadir\s*=\s*"?([^"\r\n]+)',text,re.M|re.I)
            if len(set(matches)) == 1:
                return matches[0].strip()
        except OSError:
            pass
    return None


def environment_snapshot():
    data = {'at':stamp(),'installed_apps':[],'packaged_apps':[],'processes':[],'database_processes':[],
            'active_datadirs':[],'unresolved_database_processes':[],'errors':[]}
    if os.name != 'nt':
        data['errors'].append('Windows registry/process evidence unavailable')
        return data
    import winreg
    keys = [(winreg.HKEY_LOCAL_MACHINE,winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE,winreg.KEY_WOW64_32KEY),(winreg.HKEY_CURRENT_USER,0)]
    for hive,view in keys:
        try:
            with winreg.OpenKey(hive,r'Software\Microsoft\Windows\CurrentVersion\Uninstall',0,winreg.KEY_READ|view) as top:
                for i in range(winreg.QueryInfoKey(top)[0]):
                    try:
                        with winreg.OpenKey(top,winreg.EnumKey(top,i)) as app:
                            values={}
                            for key in ('DisplayName','DisplayVersion','InstallLocation','InstallDate','Publisher'):
                                try: values[key]=winreg.QueryValueEx(app,key)[0]
                                except OSError: pass
                            if values.get('DisplayName'):
                                data['installed_apps'].append(values)
                    except OSError:
                        continue
        except OSError as error:
            data['errors'].append(f'Registry view unavailable: {error}')
    try:
        data['packaged_apps'] = powershell_json('Get-AppxPackage | Select-Object Name,Version,InstallLocation | ConvertTo-Json -Depth 3 -Compress')
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        data['errors'].append('Store app list: '+str(error))
    try:
        data['processes'] = powershell_json('Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath | ConvertTo-Json -Depth 3 -Compress')
        dbs = powershell_json("Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(mysqld|mariadbd)(\\.exe)?$' } | Select-Object Name,ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Depth 3 -Compress")
        services = powershell_json("Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'mysql|mariadb' } | Select-Object ProcessId,PathName | ConvertTo-Json -Compress")
        by_pid = {s['ProcessId']:database_dir(s.get('PathName')) for s in services if s}
        for row in dbs:
            if not row: continue
            resolved = database_dir(row.get('CommandLine')) or by_pid.get(row['ProcessId']) or by_pid.get(row['ParentProcessId'])
            data['database_processes'].append({'pid':row['ProcessId'],'name':row['Name'],'datadir':resolved})
            if resolved:
                data['active_datadirs'].append(norm(resolved))
            else:
                data['unresolved_database_processes'].append(row['ProcessId'])
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        data['errors'].append(str(error))
        data['unresolved_database_processes'].append('snapshot_incomplete')
    return data


def adjusted_size(path, info):
    if os.name != 'nt' or not info.st_file_attributes & (0x200|0x800):
        return info.st_size
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    method = kernel.GetCompressedFileSizeW
    method.argtypes = [ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_ulong)]
    method.restype = ctypes.c_ulong
    high = ctypes.c_ulong()
    ctypes.set_last_error(0)
    low = method(native(path),ctypes.byref(high))
    if low == 0xffffffff and ctypes.get_last_error():
        raise OSError(ctypes.get_last_error(),'Unable to measure compressed/sparse size')
    return (high.value << 32) + low
