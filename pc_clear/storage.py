"""Explain storage by layout, including valuable data that must remain visible."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath


def normalized(path):
    return str(path).replace('\\', '/').rstrip('/').lower()


@dataclass(frozen=True)
class Storage:
    app: str
    kind: str
    scope: str
    reason: str
    action: str


LABELS = {
    'chat_database': '聊天记录数据库', 'chat_media': '聊天图片、视频或语音',
    'chat_attachment': '聊天接收文件', 'chat_cache': '聊天缩略图或缓存副本',
    'chat_state': '聊天配置、小程序及其他数据',
    'codex_history': 'Codex 会话与归档', 'codex_runtime': 'Codex 运行环境和插件',
    'codex_cache': 'Codex 可重新获取的目录缓存', 'codex_state': 'Codex 配置与任务状态',
    'generated': '任务生成目录（混合内容）', 'database': '数据库文件',
    'archive': '压缩包或安装包', 'disk_image': '虚拟磁盘与镜像',
    'model': '模型权重', 'media': '图片、音视频', 'document': '文档与表格',
    'source': '源码与配置', 'other': '其他文件',
    'application_cache': '应用资源缓存', 'temporary': '临时文件或日志', 'build_output': '构建输出',
}
MEDIA_TYPES = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.mp4', '.mkv', '.mov',
               '.avi', '.webm', '.mp3', '.wav', '.aac', '.amr', '.silk', '.hevc'}
GENERATED_DIRS = {'.codex-tmp', '.codex-build', '.scratch', '.local-work', '.tmp-build'}


def discover_chat_roots(directories):
    """Find renamed/redirected accounts by sibling layout; never read messages."""
    children = {}
    paths = {}
    for row in directories.values():
        paths[row['id']] = row['path']
        children.setdefault(row['parent'], set()).add(PureWindowsPath(row['path']).name.lower())
    result = {}
    for ident, names in children.items():
        if ident not in paths:
            continue
        if {'db_storage', 'msg'} <= names or {'msg', 'filestorage'} <= names:
            result[normalized(paths[ident])] = '微信'
        elif {'nt_db', 'nt_data'} <= names:
            result[normalized(paths[ident])] = 'QQ'
    return result


def directory_storage(path, chat_roots=None):
    p = normalized(path)
    parts = p.split('/')
    root = ''
    app = ''
    for i, part in enumerate(parts):
        if part in {'xwechat_files', 'wechat files', 'tencent files', 'qq files', 'nt_qq'}:
            root = '/'.join(parts[:i + 1])
            app = 'QQ' if part in {'tencent files', 'qq files', 'nt_qq'} else '微信'
            break
    if not root and chat_roots:
        for candidate, owner in chat_roots.items():
            if p == candidate or p.startswith(candidate + '/'):
                root, app = candidate, owner
                break
    if root:
        tail = p[len(root):].strip('/').split('/')
        kinds = [
            ({'db_storage', 'nt_db', 'multimsg', 'msgbackup'}, 'chat_database',
             '记录数据库或备份布局，删除可能破坏聊天历史', '保留；到应用内管理聊天记录'),
            ({'cache', 'caches', 'thumb', 'thumbs', 'thumbnail', 'thumbnails'}, 'chat_cache',
             '聊天缓存或缩略图布局，可能包含无法重新获取的副本', '可手选媒体文件；删除后可能无法再次查看'),
            ({'image', 'images', 'pic', 'video', 'audio', 'voice', 'emoji', 'attach'}, 'chat_media',
             '聊天媒体目录布局，包含原图、视频或语音', '可手选媒体文件；删除后聊天中的媒体可能失效'),
            ({'file', 'files', 'filerecv'}, 'chat_attachment',
             '聊天接收或下载的文件，可能是唯一副本', '保留；核实文件用途后在应用内管理'),
        ]
        for names, kind, reason, action in kinds:
            for i, part in enumerate(tail):
                if part in names:
                    return Storage(app, kind, root + '/' + '/'.join(tail[:i + 1]), reason, action)
        return Storage(app, 'chat_state', root, '已识别聊天数据根目录', '保留；到应用内管理')
    if '.codex' in parts:
        i = parts.index('.codex')
        root = '/'.join(parts[:i + 1])
        tail = parts[i + 1:]
        if tail and tail[0] in {'sessions', 'archived_sessions'}:
            return Storage('Codex', 'codex_history', root + '/' + tail[0],
                           '会话和归档记录；归档不等于可丢弃缓存', '保留；通过 Codex 管理任务历史')
        if tail and tail[0] == 'cache':
            return Storage('Codex', 'codex_cache', '/'.join(parts[:i + 3]),
                           '工具目录或服务目录的本地缓存；仅已识别目录进入候选', '可预览已识别缓存')
        if tail and tail[0] in {'plugins', 'skills', 'vendor_imports'}:
            return Storage('Codex', 'codex_runtime', root + '/' + tail[0],
                           '安装的插件、技能或导入代码，运行时需要', '保留')
        return Storage('Codex', 'codex_state', root + ('/' + tail[0] if tail else ''),
                       '任务状态、设置或凭据', '保留')
    if 'codex-runtimes' in parts or ('ms-playwright' in parts and 'openai.codex' in p):
        return Storage('Codex', 'codex_runtime', p[:p.index('codex-runtimes') + 14] if 'codex-runtimes' in p else p.split('/ms-playwright')[0] + '/ms-playwright',
                       'Python、Node 或浏览器程序，正在使用的版本不是临时数据', '保留')
    for i, part in enumerate(parts):
        if part in GENERATED_DIRS:
            return Storage('任务生成数据', 'generated', '/'.join(parts[:i + 1]),
                           '任务中间目录可能同时含源码、依赖、测试数据和产物；须结合 Git 和类型', '仅选择已验证可重建的文件')
    return None


def file_kind(name):
    ext = PureWindowsPath(name).suffix.lower()
    if ext in {'.db', '.sqlite', '.sqlite3', '.db3', '.ibd', '.myd'} or name.lower().startswith(('msg.db', 'message_', 'ibdata')):
        return 'database'
    if ext in {'.vhd', '.vhdx', '.vmdk', '.qcow2', '.iso'}:
        return 'disk_image'
    if ext in {'.gguf', '.safetensors', '.pth', '.pt', '.onnx'}:
        return 'model'
    if ext in {'.zip', '.7z', '.rar', '.tar', '.gz', '.msi', '.exe'}:
        return 'archive'
    if ext in MEDIA_TYPES:
        return 'media'
    if ext in {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv'}:
        return 'document'
    if ext in {'.py', '.js', '.ts', '.cs', '.java', '.go', '.cpp', '.sql', '.json', '.jsonl', '.toml', '.yaml', '.ini', '.xml'}:
        return 'source'
    return 'other'


def file_storage(storage, name):
    """Database sidecars and legacy msg*.db remain recognizable under any subfolder."""
    if storage and storage.app in {'微信', 'QQ'}:
        lower = name.lower()
        if file_kind(name) == 'database' or lower.endswith(('.db-wal', '.db-shm', '.db-journal')):
            return Storage(storage.app, 'chat_database', storage.scope,
                           '聊天数据库及事务配套文件', '保留；到应用内管理聊天记录')
    return storage
