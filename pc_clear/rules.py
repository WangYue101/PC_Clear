"""Explainable classification. No classification authorizes deletion."""
from __future__ import annotations
from dataclasses import dataclass
import fnmatch
import json
import ntpath
import os
from pathlib import Path
import re


def norm(path):
    return str(path).replace('\\','/').rstrip('/').lower()


def inside(path, parent):
    p, q = norm(path), norm(parent)
    return p == q or p.startswith(q + '/')


def load_policy(path):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if data['schema_version'] != 1:
        raise ValueError('Unsupported policy version')
    for field in ('protected_paths','custom_protected_paths'):
        data[field] = [norm(os.path.expandvars(p)) for p in data[field]]
    for field in ('protected_components','protected_extensions','protected_names'):
        data[field] = {x.lower() for x in data[field]}
    return data


@dataclass(frozen=True)
class Context:
    category: str
    reason: str
    scope: str = ''
    min_days: float = 0


def classify_directory(path, policy, chromium_roots=(), mysql_roots=()):
    p = norm(path)
    parts = p.split('/')
    for root in policy['protected_paths'] + policy['custom_protected_paths']:
        if inside(p,root):
            return Context('protected','显式保护的程序、配置或凭据')
    if any(fnmatch.fnmatchcase(p, norm(glob)) for glob in policy['custom_protected_globs']):
        return Context('protected','自定义保护模式')
    if any(x in policy['protected_components'] or 'backup' in x or '.bak' in x for x in parts):
        return Context('protected','源码依赖、版本控制、备份或用户状态目录')
    if p.startswith('c:/windows') or '/system volume information' in p or '/$recycle.bin' in p:
        return Context('system','由 Windows 管理，保留并统计占用')
    if '/appdata/local/packages/microsoft' in p:
        return Context('system','Microsoft 商店/系统应用容器，交由应用或 Windows 管理')
    if any(x in {'package cache','installer cache','product cache','update cache','$patchcache$'} for x in parts):
        return Context('managed','安装/修复介质，应由安装器管理')
    if '/program files' in p or '/programdata/microsoft/visualstudio/packages' in p:
        return Context('installed','安装目录，旧版本也不能直接删除')
    if any(x in {'documents','desktop','pictures','music','videos','downloads','xwechat_files'} for x in parts):
        return Context('user_data','文档、下载或聊天/媒体文件，需按用途单独选择')
    if '/.cache/torch' in p or '/.cache/huggingface' in p or '/.nuget/packages' in p:
        return Context('dependency','模型或直接引用的依赖，需确认重新下载/还原能力')
    if any(x in {'.m2','.pnpm-store','pnpm-store','pkgs'} for x in parts) or '/npm-cache/_npx' in p or '/go/pkg/mod/' in p:
        return Context('dependency','包存储或可执行工具，使用包管理器核验引用与修剪')
    if '/lghub/cache' in p or '/logioptionsplus/cache' in p:
        return Context('review_cache','罗技更新资源，未核实格式与更新状态')
    if '/cloudmusic/cache' in p or 'subscriptionplaycache' in p or '/wmpfcache' in p:
        return Context('app_managed','播放/离线/小程序资源，建议在应用内选择清理')
    for root in mysql_roots:
        if inside(p,root):
            return Context('test_database','用户已确认可重建的测试数据库，仍需 Git、实例状态与年龄核验',root,policy['database_quiet_hours']/24)
    for i in range(len(parts)-1,-1,-1):
        segment = parts[i]
        scope = '/'.join(parts[:i+1])
        if segment in {'__pycache__','.pytest_cache','.ruff_cache','.mypy_cache','.next'}:
            if segment == '.next' and 'cache' not in parts[i+1:]:
                continue
            return Context('build_cache','生成的 Python/代码检查/框架缓存',scope)
        if segment in {'intermediates','.transforms','cmakefiles','obj','.cxx'}:
            return Context('build_binary','仅 Git 忽略的编译中间二进制',scope,1)
        if segment in {'code cache','gpucache','dawncache','dawngraphitecache','dawnwebgpucache','d3dscache','dxcache','glcache','grshadercache','shadercache','computecache'}:
            return Context('cache','资源代码或 GPU/着色器缓存',scope)
        if scope in chromium_roots:
            return Context('cache','已识别 index/data 文件或 Cache_Data 布局的 Chromium 资源缓存',scope)
        if segment == 'component_crx_cache' and '/appdata/' in p:
            return Context('cache','浏览器可重新下载的组件包',scope)
        if segment == 'cacheddata' and any(x in parts for x in ('code','cursor')):
            return Context('cache','编辑器编译代码缓存',scope)
        if segment == 'caches' and '.gradle' in parts[:i]:
            return Context('cache','Gradle 构建与依赖缓存；需要重建或下载',scope)
        if segment in {'caches','index'} and ('jetbrains' in parts or any(x.startswith('androidstudio') for x in parts)):
            return Context('cache','IDE 生成缓存/索引，保留 LocalHistory',scope)
        if segment == 'cache' and any(x in parts[:i] for x in ('roslyn','designer')) and 'visualstudio' in parts:
            return Context('cache','Visual Studio 设计器副本或 Roslyn 索引',scope)
        if segment in {'http-v2','wheels','_cacache','http-cache'} and any(x in parts[:i] for x in ('pip','pip-cache','npm-cache','nuget')):
            return Context('cache','包管理器下载缓存，保留安装环境',scope)
        if segment.startswith('qtshadercache'):
            return Context('cache','Qt 可再生成的着色器缓存',scope)
        if segment in {'temp','tmp','crashdumps','crashes','minidump','minidumps'}:
            return Context('temporary','临时/崩溃目录，按文件类型与修改年龄筛选',scope,policy['temporary_min_days'])
        if segment in {'logs','log'} and ('appdata' in parts or 'programdata' in parts):
            return Context('logs','应用日志目录，按日志类型与修改年龄筛选',scope,policy['log_min_days'])
    if any('cache' in x or 'temp' in x or 'dump' in x for x in parts):
        return Context('review_cache','名称提示缓存/临时内容，但用途或内部布局尚未充分确认')
    return Context('other','常规数据，未认定为可清理')


BUILD_TYPES = {'.class','.dex','.jar','.aar','.so','.o','.obj','.a','.lib','.bin','.dat','.flat','.pdb','.res','.bc','.kotlin_module'}
DATABASE_TYPES = {'.ibd','.myd','.myi','.sdi','.dblwr','.ibt'}
DB_NAMES = re.compile(r'^(?:ibdata\d+|ibtmp\d+|undo_\d+|#ib_redo\d+|binlog\.\d+|mysql-bin\.\d+|ib_logfile\d+)$')


def classify_file(context, name, age_days, policy):
    lower = name.lower()
    extension = ntpath.splitext(lower)[1]
    if lower in policy['protected_names'] or lower == '.env' or lower.startswith('.env.'):
        return 'protected','配置、凭据或用户状态文件'
    if extension in policy['protected_extensions']:
        return 'protected','源码、文档、数据库、模型或磁盘镜像格式'
    if context.category in {'cache','build_cache','build_binary','temporary','logs','test_database'} and age_days < context.min_days:
        return 'recent','尚未满足候选的静置时间'
    if context.category == 'temporary':
        if extension in policy['temporary_extensions'] or (extension in policy['log_extensions'] and age_days >= policy['log_min_days']):
            return 'candidate','临时/转储格式且满足年龄条件'
        return 'review','临时目录内的其他格式，不能整目录删除'
    if context.category == 'logs':
        return ('candidate','较早的应用日志') if extension in policy['log_extensions'] else ('review','日志目录中的其他文件')
    if context.category == 'build_binary':
        return ('candidate','编译中间二进制') if extension in BUILD_TYPES else ('protected','不是允许的编译二进制格式')
    if context.category == 'build_cache' and '__pycache__' in context.scope and extension != '.pyc':
        return 'protected','__pycache__ 中的非字节码文件'
    if context.category == 'test_database':
        return ('candidate','测试数据库生成数据') if extension in DATABASE_TYPES or DB_NAMES.match(lower) else ('protected','保留 SQL、配置、日志、凭据或未知数据库文件')
    if context.category in {'cache','build_cache'}:
        return 'candidate',context.reason
    return context.category,context.reason


def application(path, repository=''):
    if repository:
        return '项目 · ' + repository
    p = str(path).replace('\\','/')
    lower = p.lower()
    for marker in ('/AppData/Local/','/AppData/Roaming/','/AppData/LocalLow/','/ProgramData/','/Program Files (x86)/','/Program Files/'):
        start = lower.find(marker.lower())
        if start >= 0:
            tail = p[start+len(marker):].split('/')
            take = 2 if tail[0].lower() in {'microsoft','google','jetbrains','tencent','kingsoft','nvidia corporation','packages'} else 1
            return ' / '.join(tail[:take])
    parts = p.split('/')
    if len(parts)>3 and parts[1].lower()=='users':
        return parts[3]
    if len(parts)>1 and parts[1].lower()=='windows':
        return 'Windows 系统'
    return '/'.join(parts[:3])
