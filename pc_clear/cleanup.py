"""Explicit selection -> read-only preview -> confirmed, revalidated file cleanup."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import threading
import time

from .evidence import git_filter, powershell_json
from .rules import classify_directory, classify_file, inside, load_policy, norm
from .scan import stamp, write_json
from .windows_files import checked_path, delete_verified_file, inspect_file


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def current_processes():
    return powershell_json('Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath | ConvertTo-Json -Compress')


def running_reason(row, processes):
    text = norm(row['path']) + ' ' + row['app'].lower()
    names = {str(p.get('Name', '')).lower() for p in processes}
    identified_apps = {'QQ': {'qq.exe', 'qqnt.exe'},
                       '微信': {'weixin.exe', 'wechat.exe', 'wechatappex.exe', 'weixinappex.exe'},
                       'Codex': {'codex.exe', 'codex-app-server.exe'}}
    matches = names & identified_apps.get(row['app'], set())
    if matches:
        return '对应应用仍在运行：' + ', '.join(sorted(matches))
    families = [
        (('codex',), {'codex.exe', 'codex-app-server.exe'}),
        (('xwechat', 'wechat files', '微信'), {'weixin.exe', 'wechat.exe', 'wechatappex.exe', 'weixinappex.exe'}),
        (('tencent files', 'nt_qq', 'qqnt', 'tencent/qq', '|qq'), {'qq.exe', 'qqnt.exe'}),
        (('pycharm',), {'pycharm64.exe'}), (('intellij',), {'idea64.exe'}),
        (('webstorm',), {'webstorm64.exe'}), (('goland',), {'goland64.exe'}),
        (('/google/chrome',), {'chrome.exe'}), (('/microsoft/edge',), {'msedge.exe'}),
        (('/cursor',), {'cursor.exe'}), (('/code/',), {'code.exe'}),
        (('kingsoft', 'wps'), {'wps.exe', 'et.exe', 'wpp.exe', 'wpscloudsvr.exe'}),
        (('dingtalk',), {'dingtalk.exe'}), (('lark', 'feishu'), {'lark.exe', 'feishu.exe'}),
    ]
    for markers, executables in families:
        if any(marker in text for marker in markers) and names & executables:
            return '对应应用仍在运行：' + ', '.join(sorted(names & executables))
    if row['category'] in {'generated_binary', 'build_binary', 'build_cache'}:
        active = names & {'dotnet.exe', 'msbuild.exe', 'javac.exe', 'gradle.exe', 'cl.exe', 'cmake.exe', 'ninja.exe'}
        if active:
            return '构建进程仍在运行：' + ', '.join(sorted(active))
    for process in processes:
        executable = process.get('ExecutablePath')
        if executable and (inside(executable, row['scope']) or norm(executable) == norm(row['path'])):
            return '范围内存在运行程序：' + str(process.get('Name'))
    return ''


def nearest_repository(path):
    for folder in Path(path).parents:
        marker = folder / '.git'
        # lexists also catches a broken .git link, which Git must verify rather than ignore.
        if os.path.lexists(marker):
            return str(folder)
    return ''


def chromium_layout(scope):
    folder = Path(scope)
    if folder.name.lower() not in {'cache', 'cache_data'}:
        return set()
    names = {name for name in ('cache_data', 'index', 'data_0', 'data_1', 'index-dir') if (folder / name).exists()}
    if 'cache_data' in names or ('index' in names and names & {'data_0', 'data_1', 'index-dir'}):
        return {norm(folder)}
    return set()


def revalidate_rule(row, policy, chromium_roots=None, generated_outputs=()):
    path = checked_path(row['path'])
    scope = checked_path(row['scope'])
    if not inside(path, scope) or norm(path) == norm(scope):
        raise ValueError('文件不在候选的精确范围内')
    # A current directory layout is evidence; manifest-provided layout hints are not authority.
    chat_roots = {}
    if row['category'] == 'chat_media' and not any(x in norm(path).split('/') for x in ('xwechat_files','wechat files','tencent files','nt_qq','qq files')):
        for ancestor in path.parents:
            if (ancestor / 'db_storage').is_dir() and (ancestor / 'msg').is_dir():
                chat_roots[norm(ancestor)] = '微信'
            elif (ancestor / 'nt_db').is_dir() and (ancestor / 'nt_data').is_dir():
                chat_roots[norm(ancestor)] = 'QQ'
    mysql = ()
    if row['category'] == 'test_database':
        if not any(inside(scope, p) for p in policy['confirmed_rebuildable_database_roots']) or not (scope / 'ibdata1').is_file():
            raise ValueError('测试数据库范围无法核实')
        mysql = (norm(scope),)
    context = classify_directory(path.parent, policy,
        chromium_layout(scope) if chromium_roots is None else chromium_roots, mysql, chat_roots, generated_outputs)
    decision, reason = classify_file(context, path.name, (time.time() - row['mtime']) / 86400, policy)
    if context.category != row['category'] or decision != 'candidate' or norm(context.scope) != norm(scope):
        raise ValueError('当前规则不再允许该候选：' + reason)
    repo = nearest_repository(path)
    if norm(repo) != norm(row.get('repository', '')):
        raise ValueError('Git 仓库边界已变化；请重新分析')
    if context.category in {'generated_binary', 'build_binary', 'test_database'} and not repo:
        raise ValueError('缺少 Git 仓库依据')


def verified_generated_outputs(rows):
    roots = {root for row in rows for root in row.get('generated_output_roots', []) if inside(row['path'],root) and inside(root,row['scope'])}
    answer = set()
    for root in roots:
        folder = checked_path(root)
        # Only inspect the directly referenced output directory, never recurse.
        try:
            names = (entry.name.lower() for entry in folder.iterdir())
            if any(name.endswith(('.deps.json','.runtimeconfig.json')) or name in {'cmakecache.txt','build.ninja'} for name in names):
                answer.add(norm(root))
        except OSError:
            pass
    return answer


@dataclass
class Preview:
    token: str
    created: float
    rows: list
    summary: dict
    manifest_hash: str
    plan_hash: str
    policy_hash: str
    used: bool = False


class CleanupSession:
    """A preview belongs to one session, expires, and can only be consumed once."""

    def __init__(self, run, policy_path):
        self.run = Path(run).resolve()
        self.policy_path = Path(policy_path).resolve()
        self.plan_path = self.run / 'cleanup_plan.json'
        self.manifest_path = self.run / 'candidate_files.jsonl'
        self.plan = json.loads(self.plan_path.read_text(encoding='utf-8'))
        self.plan_hash = digest(self.plan_path)
        if self.plan.get('schema_version') != 2:
            raise ValueError('这是旧版清单，请先重新扫描或重新分析')
        if self.plan.get('manifest') != self.manifest_path.name:
            raise ValueError('清单文件名不受支持')
        self.policy = load_policy(self.policy_path)
        self._lock = threading.Lock()
        self.preview = None

    def _check_binding(self):
        if digest(self.plan_path) != self.plan_hash:
            raise ValueError('分析结果已更新，请重新打开清理清单')
        if digest(self.policy_path) != self.plan.get('policy_sha256'):
            raise ValueError('规则已变化，请重新分析')
        if digest(self.manifest_path) != self.plan.get('manifest_sha256'):
            raise ValueError('逐文件清单已变化或不完整，请重新分析')

    def _read_selection(self, ids, personal):
        ids = set(ids)
        if not ids:
            raise ValueError('请先勾选清理项；默认不选择任何文件')
        groups = {g['id']: g for g in self.plan['groups']}
        if ids - groups.keys():
            raise ValueError('存在不属于本次分析的编号')
        if not personal and any(groups[i]['risk'] == 'personal' for i in ids):
            raise ValueError('聊天媒体需要单独启用个人数据选项')
        keys = {groups[i]['group_key'] for i in ids}
        seen = set()
        rows = []
        with self.manifest_path.open(encoding='utf-8') as handle:
            for line in handle:
                row = json.loads(line)
                if row['group_key'] not in keys:
                    continue
                if norm(row['path']) in seen:
                    raise ValueError('清单包含重复文件')
                seen.add(norm(row['path']))
                rows.append(row)
        if not rows:
            raise ValueError('所选项没有文件')
        return rows

    def prepare(self, ids, *, personal=False, progress=lambda message: None, cancel=None):
        self.preview = None
        self._check_binding()
        plan_hash = digest(self.plan_path)
        rows = self._read_selection(ids, personal)
        processes = current_processes()  # Any failure aborts the preview.
        groups = defaultdict(list)
        for row in rows:
            if row['repository']:
                groups[row['repository']].append(row['path'])
        git_states = {}
        for repo, paths in groups.items():
            progress('复核 Git：' + repo)
            states, error = git_filter(repo, paths)
            git_states.update(states)
        ready = []
        chromium_roots = set().union(*(chromium_layout(scope) for scope in {r['scope'] for r in rows}))
        generated_outputs = verified_generated_outputs(rows)
        reasons = Counter()
        token = secrets.token_hex(8)
        records_path = self.run / ('preview_' + token + '.jsonl')
        with records_path.open('x', encoding='utf-8') as records:
            for index, row in enumerate(rows):
                if cancel and cancel.is_set():
                    raise InterruptedError('预览已取消，未删除文件')
                try:
                    if row['repository'] and git_states.get(row['path']) != 'ignored_untracked':
                        raise ValueError('Git 已跟踪、未忽略或无法验证')
                    revalidate_rule(row, self.policy, chromium_roots, generated_outputs)
                    inspect_file(row['path'], row['identity'])
                    active = running_reason(row, processes)
                    if active:
                        raise ValueError(active)
                    # Database consistency requires application-native removal, not a partial file sweep.
                    if row['category'] == 'test_database':
                        raise ValueError('测试数据库请停止实例后使用数据库管理方式整体处理；此入口不做部分数据文件删除')
                    ready.append(row)
                    record = {'status': 'ready', **row}
                except (OSError, ValueError, KeyError) as error:
                    reasons[str(error)] += 1
                    record = {'status': 'skip', 'path': row['path'], 'reason': str(error)}
                records.write(json.dumps(record, ensure_ascii=False) + '\n')
                if index % 500 == 0:
                    progress(f'预览核验 {index + 1:,}/{len(rows):,}；可执行 {len(ready):,}')
        if plan_hash != digest(self.plan_path):
            raise ValueError('预览期间分析结果被更新，请重新预览')
        if cancel and cancel.is_set():
            raise InterruptedError('预览已取消，未删除文件')
        summary = {'at': stamp(), 'selected_groups': sorted(ids), 'requested_files': len(rows),
                   'ready_files': len(ready), 'estimated_bytes': sum(r['estimated_bytes'] for r in ready),
                   'skipped_files': len(rows) - len(ready), 'skip_reasons': dict(reasons),
                   'personal': any(r['category'] == 'chat_media' for r in ready),
                   'records_path': str(records_path), 'operation': '永久删除逐文件清单，不经过回收站',
                   'confirmation': '永久删除 ' + token}
        write_json(self.run / ('preview_' + token + '.json'), summary)
        self.preview = Preview(token, time.time(), ready, summary, self.plan['manifest_sha256'], plan_hash, digest(self.policy_path))
        return self.preview

    def execute(self, preview, *, confirmation='', apps_closed=False, progress=lambda message: None, cancel=None):
        if not self._lock.acquire(blocking=False):
            raise ValueError('清理正在执行')
        try:
            return self._execute(preview, confirmation, apps_closed, progress, cancel)
        finally:
            self._lock.release()

    def _execute(self, preview, confirmation, apps_closed, progress, cancel):
        if preview is not self.preview or preview.used or time.time() - preview.created > 900:
            raise ValueError('预览已过期、已使用或不属于本次会话，请重新预览')
        if not preview.rows:
            raise ValueError('没有通过预览核验的文件')
        if confirmation != preview.summary['confirmation'] or not apps_closed:
            raise ValueError('需要确认关闭相关应用，并输入本次预览的永久删除确认词')
        if digest(self.plan_path) != preview.plan_hash or digest(self.policy_path) != preview.policy_hash:
            raise ValueError('清单或规则已变化，请重新预览')
        self._check_binding()
        preview.used = True
        processes = current_processes()
        process_check_time = time.monotonic()
        # Capture current layout before deleting its own index/data markers. File identities
        # and pinned directory handles still protect every later individual deletion.
        chromium_roots = set().union(*(chromium_layout(scope) for scope in {r['scope'] for r in preview.rows}))
        generated_outputs = verified_generated_outputs(preview.rows)
        roots = {Path(r['path']).anchor for r in preview.rows}
        before = {root: shutil.disk_usage(root).free for root in roots}
        counts = Counter()
        log = self.run / ('cleanup_' + preview.token + '.jsonl')
        cancelled = False
        failure = ''
        with log.open('x', encoding='utf-8') as handle:
            for offset in range(0, len(preview.rows), 500):
                if cancel and cancel.is_set():
                    cancelled = True
                    break
                if time.monotonic() - process_check_time > 10:
                    try:
                        processes = current_processes()
                        process_check_time = time.monotonic()
                    except Exception as error:
                        failure = '进程复核失败，已停止：' + str(error)
                        break
                batch = preview.rows[offset:offset + 500]
                git_states = {}
                repos = defaultdict(list)
                for row in batch:
                    if row['repository']:
                        repos[row['repository']].append(row['path'])
                for repo, paths in repos.items():
                    states, error = git_filter(repo, paths)
                    git_states.update(states)
                for row in batch:
                    if cancel and cancel.is_set():
                        cancelled = True
                        break
                    try:
                        if row['repository'] and git_states.get(row['path']) != 'ignored_untracked':
                            raise ValueError('Git 复核未通过')
                        revalidate_rule(row, self.policy, chromium_roots, generated_outputs)
                        active = running_reason(row, processes)
                        if active:
                            raise ValueError(active)
                        intent = {'at': stamp(), 'status': 'attempt', 'path': row['path']}
                        handle.write(json.dumps(intent, ensure_ascii=False) + '\n')
                        handle.flush()
                        delete_verified_file(row['path'], row['identity'])
                        counts['deleted_files'] += 1
                        counts['deleted_estimated_bytes'] += row['estimated_bytes']
                        result = {'status': 'deleted', 'path': row['path'], 'estimated_bytes': row['estimated_bytes']}
                    except (OSError, ValueError, KeyError) as error:
                        counts['skipped_files'] += 1
                        result = {'status': 'skip', 'path': row['path'], 'reason': str(error)}
                    handle.write(json.dumps({'at': stamp(), **result}, ensure_ascii=False) + '\n')
                    handle.flush()
                progress(f"已删除 {counts['deleted_files']:,}；跳过 {counts['skipped_files']:,}")
        result = {'at': stamp(), **dict(counts), 'cancelled': cancelled, 'failure': failure, 'log': str(log),
                  'free_space_delta': {root: shutil.disk_usage(root).free - before[root] for root in roots},
                  'note': '空闲空间变化包含其他程序的同期写入；具体结果以逐文件日志为准'}
        write_json(self.run / ('cleanup_' + preview.token + '.json'), result)
        return result
