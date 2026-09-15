"""Delete one verified ordinary file using its exclusive Windows handle.

Parent handles prevent directory replacement while the file is validated/deleted.
No recursive deletion, attribute changes, link following, or delayed reboot deletes.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import stat

from .scan import native


def identity(info):
    # Windows stat/fstat can differ in deprecated ctime semantics. Use the explicit
    # creation timestamp on both paths; keep the manifest key for compatibility.
    return {'dev': info.st_dev, 'ino': info.st_ino, 'size': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': getattr(info, 'st_birthtime_ns', info.st_ctime_ns)}


def checked_path(value):
    text = str(value)
    if not re.match(r'^[a-zA-Z]:[\\/]', text) or ':' in text[2:]:
        raise ValueError('只支持普通本地磁盘绝对路径，不支持 UNC、设备路径或数据流')
    if any(part in {'.', '..'} or part.endswith((' ', '.')) for part in text.replace('\\', '/').split('/')[1:]):
        raise ValueError('路径含歧义分段')
    path = Path(text)
    if path == Path(path.anchor):
        raise ValueError('不能删除磁盘根目录')
    return path


def inspect_file(path, expected):
    path = checked_path(path)
    for ancestor in reversed(path.parents):
        info = os.stat(native(ancestor), follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('父目录是链接、重解析点或非目录')
    info = os.stat(native(path), follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & (0x400 | 0x1000 | 0x40000):
        raise ValueError('链接、云占位或非普通文件')
    if info.st_nlink != 1:
        raise ValueError('多个硬链接')
    if identity(info) != expected:
        raise ValueError('文件身份、大小或时间已变化；请重新扫描')
    return info


def kernel_api():
    if os.name != 'nt':
        raise OSError('清理执行仅支持 Windows')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                               wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    api.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    api.SetFileInformationByHandle.restype = wintypes.BOOL
    return api


@contextmanager
def pinned_parents(path, api):
    handles = []
    try:
        for ancestor in reversed(path.parents):
            # Share read/write, but not delete: directory rename/replacement is denied.
            handle = api.CreateFileW(native(ancestor), 0x80, 3, None, 3, 0x02000000 | 0x00200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
            info = os.stat(native(ancestor), follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_file_attributes & 0x400:
                raise ValueError('父目录是重解析点或非目录')
        yield
    finally:
        for handle in reversed(handles):
            api.CloseHandle(handle)


def delete_verified_file(value, expected):
    """Permanent deletion; caller must already have explicit selection/confirmation."""
    import msvcrt
    path = checked_path(value)
    api = kernel_api()
    with pinned_parents(path, api):
        handle = api.CreateFileW(native(path), 0x80000000 | 0x10000, 0, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        fd = None
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_file_attributes & (0x400 | 0x1000 | 0x40000):
                raise ValueError('不是独占的普通本地文件')
            if identity(info) != expected:
                differences = {key: (expected.get(key), value) for key, value in identity(info).items() if expected.get(key) != value}
                raise ValueError('文件已被替换或修改：' + str(differences))
            disposition = wintypes.BOOL(True)
            if not api.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if fd is not None:
                os.close(fd)
            else:
                api.CloseHandle(handle)
