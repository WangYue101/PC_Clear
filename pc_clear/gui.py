"""Desktop analysis and opt-in cleanup. Tk widgets are owned by the UI thread."""
from __future__ import annotations

from datetime import datetime
from contextlib import closing
import json
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .cleanup import CleanupSession
from .report import TITLES, human
from .topology import drive_to_disk, partition_title, storage_topology

PROJECT = Path(__file__).resolve().parents[1]
REPORTS = PROJECT / 'reports'
POLICY = PROJECT / 'scan_policy.json'


def latest_scan_run(reports):
    """Choose the newest complete full-scan report, never a UI/demo fixture."""
    required = ('cleanup_plan.json', 'C/analysis.json', 'D/analysis.json',
                'C/inventory.sqlite', 'D/inventory.sqlite')
    candidates = [plan.parent for plan in reports.glob('full_*/cleanup_plan.json')
                  if all((plan.parent / relative).is_file() for relative in required)]
    return max(candidates, key=lambda run: (run / 'cleanup_plan.json').stat().st_mtime, default=None)


class Application:
    def __init__(self, root, run=None):
        self.root = root
        root.title('PC_Clear · 磁盘分析与清理')
        root.geometry('1240x820')
        root.minsize(980, 680)
        self.messages = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
        self.process = None
        self.run = None
        self.plan = {}
        self.data = {}
        self.topology = ()
        self.topology_sampled_at = None
        self.topology_read_failed = False
        self.selected = set()
        self.session = None
        self.preview = None
        self.path_rows = {}
        self.overview_rows = {}
        self.overview_lazy = {}
        self.overview_trees = {}
        self.overview_details = {}
        self.overview_serial = 0
        self.topology_details = {}
        self.topology_serial = 0
        self.active_query = ''
        self.folder_matches = {}
        self.status = tk.StringVar(value='默认只分析。所有可清理项均未勾选。')
        self.search = tk.StringVar()
        self.personal = tk.BooleanVar(value=False)
        self.personal_state = False
        self.apps_closed = tk.BooleanVar(value=False)
        self.confirmation = tk.StringVar()
        self.drive = tk.StringVar(value='C')
        self.folder = tk.StringVar(value='C:\\')
        self.file_query = tk.StringVar()
        style = ttk.Style(root)
        style.configure('DetailTitle.TLabel', font=('Segoe UI Semibold', 11))
        toolbar = ttk.Frame(root, padding=10)
        toolbar.pack(fill='x')
        for label, command in [('完整扫描分析', self.scan), ('打开已有分析', self.choose_run),
                               ('重新分析当前清单', self.reanalyze), ('打开报告目录', self.open_run),
                               ('刷新实时容量', self.refresh_live_topology),
                               ('停止当前操作', self.stop)]:
            ttk.Button(toolbar, text=label, command=command).pack(side='left', padx=(0, 8))
        ttk.Label(root, textvariable=self.status, padding=(12, 2), wraplength=1180).pack(fill='x')
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=8)
        self.overview = ttk.Frame(self.notebook, padding=8)
        self.choices = ttk.Frame(self.notebook, padding=8)
        self.browser = ttk.Frame(self.notebook, padding=8)
        self.preview_tab = ttk.Frame(self.notebook, padding=8)
        self.log_tab = ttk.Frame(self.notebook, padding=8)
        for frame, label in [(self.overview, '全部占用'), (self.choices, '可清理项'),
                             (self.browser, '目录与文件'), (self.preview_tab, '执行预览'), (self.log_tab, '进度与日志')]:
            self.notebook.add(frame, text=label)
        searchbar = ttk.Frame(self.overview)
        searchbar.pack(fill='x', pady=(0, 8))
        ttk.Label(searchbar, text='搜索应用、类型或路径（同时过滤清理项）：').pack(side='left')
        ttk.Entry(searchbar, textvariable=self.search, width=45).pack(side='left')
        ttk.Button(searchbar, text='搜索', command=self.search_overview).pack(side='left', padx=6)
        ttk.Button(searchbar, text='重置', command=self.reset_search).pack(side='left')
        self.topology_title = tk.StringVar(value='物理硬盘与分区 · 当前实时容量（正在读取）')
        topology_box = ttk.LabelFrame(self.overview, text=self.topology_title.get(), padding=(6, 4))
        self.topology_box = topology_box
        topology_box.pack(fill='x', pady=(0, 6))
        topology_columns = [('kind','类型',100), ('capacity','容量',110), ('used','当前已用',110),
                            ('free','当前可用',110), ('health','状态',90), ('coverage','扫描范围',220)]
        self.topology_tree = self.tree(topology_box, topology_columns,
                                       hierarchy_label='物理硬盘 / 分区', height=7)
        self.topology_tree.bind('<<TreeviewSelect>>', self.show_topology_detail)
        self.summary_label = ttk.Label(self.overview, text='点击“完整扫描分析”，或载入已有报告；容量将从 Windows 读取，扫描快照单独说明。', wraplength=1140)
        self.summary_label.pack(fill='x', pady=(0, 8))
        self.overview_notebook = ttk.Notebook(self.overview)
        self.overview_notebook.pack(fill='both', expand=True)
        self.app_view = ttk.Frame(self.overview_notebook, padding=6)
        self.folder_view = ttk.Frame(self.overview_notebook, padding=6)
        self.overview_notebook.add(self.app_view, text='应用智能分析')
        self.overview_notebook.add(self.folder_view, text='文件夹分析')
        columns = [('kind','分类',110), ('bytes','逻辑占用',120),
                   ('candidate','可清理上限',105), ('files','文件数',90)]
        self.app_tree = self.tree(self.app_view, columns, hierarchy_label='物理硬盘 / 分区 / 应用')
        self.folder_tree = self.tree(self.folder_view, columns, hierarchy_label='物理硬盘 / 分区 / 文件夹')
        self.usage_tree = self.app_tree
        for tree in (self.app_tree, self.folder_tree):
            tree.bind('<<TreeviewOpen>>', lambda event, current=tree: self.open_overview_node(current, event))
            tree.bind('<<TreeviewSelect>>', lambda event, current=tree: self.show_overview_detail(current))
            tree.bind('<Double-1>', lambda event, current=tree: self.show_storage(current, event))
        detail_box = ttk.LabelFrame(self.overview, text='所选项目说明', padding=(10, 6))
        detail_box.pack(fill='x', pady=(8, 0))
        self.overview_detail_title = tk.StringVar(value='选择硬盘、分区、应用或文件夹')
        self.overview_detail = tk.StringVar(value='实时容量来自 Windows；扫描逻辑占用来自报告。可清理上限只是分析结果，预览后才可执行。')
        ttk.Label(detail_box, textvariable=self.overview_detail_title, style='DetailTitle.TLabel').pack(anchor='w')
        ttk.Label(detail_box, textvariable=self.overview_detail, wraplength=1130, justify='left').pack(fill='x', pady=(3, 0))
        ttk.Label(self.overview, text='物理容量不把 C、D 当成两块硬盘相加；系统、保留和恢复分区只展示容量，不扫描或清理。应用与文件夹分别分析；可清理项须在清理页预览。', wraplength=1150).pack(fill='x', pady=(5, 0))
        self.personal_button = ttk.Checkbutton(self.choices, text='显示需确认的个人聊天媒体（可能失去原图、视频或语音；数据库、文档附件继续保留）',
                        variable=self.personal, command=self.personal_changed)
        self.personal_button.pack(anchor='w', pady=4)
        choicebar = ttk.Frame(self.choices)
        choicebar.pack(fill='x', pady=6)
        ttk.Button(choicebar, text='预览已选文件', command=self.prepare).pack(side='left')
        ttk.Button(choicebar, text='取消全部勾选', command=self.clear_selection).pack(side='left', padx=8)
        self.selection_label = ttk.Label(choicebar, text='尚未勾选')
        self.selection_label.pack(side='left', padx=8)
        self.cleanup_summary = ttk.Label(self.choices, wraplength=1150, justify='left')
        self.cleanup_summary.pack(fill='x', pady=(0, 6))
        self.choice_tree = self.tree(self.choices, [('check','勾选',72), ('id','编号',70), ('drive','分区',54),
            ('app','应用 / 项目',250), ('category','内容类型',190), ('bytes','可清理上限',100), ('files','文件数',80)],
            hierarchy_label='智能清理建议 / 分区')
        self.choice_tree.bind('<Button-1>', self.click_choice)
        self.choice_tree.bind('<space>', self.toggle_focus)
        self.choice_tree.bind('<Double-1>', self.show_choice)
        ttk.Label(self.choices, text='“可清理内容”和已显示的聊天媒体可以勾选。点击第一列勾选；双击其他列查看精确范围。默认不删除，预览会再次核验 Git、文件类型、文件身份和运行状态。', wraplength=1150).pack(fill='x', pady=6)
        browsebar = ttk.Frame(self.browser)
        browsebar.pack(fill='x')
        self.drive_combo = ttk.Combobox(browsebar, textvariable=self.drive, values=('C','D'), state='readonly', width=3)
        self.drive_combo.pack(side='left')
        self.drive_combo.bind('<<ComboboxSelected>>', self.drive_changed)
        ttk.Entry(browsebar, textvariable=self.folder, width=65).pack(side='left', padx=6, fill='x', expand=True)
        ttk.Button(browsebar, text='查看目录', command=self.browse).pack(side='left')
        ttk.Button(browsebar, text='上一级', command=self.parent_folder).pack(side='left', padx=6)
        ttk.Entry(browsebar, textvariable=self.file_query, width=20).pack(side='left')
        ttk.Button(browsebar, text='全盘搜文件名', command=self.search_files).pack(side='left', padx=6)
        self.path_tree = self.tree(self.browser, [('kind','类型',75), ('name','文件或目录',670), ('bytes','逻辑占用',120), ('detail','文件数 / 修改时间',180)])
        self.path_tree.bind('<Double-1>', self.open_path_row)
        ttk.Label(self.browser, text='按大小显示前 1,000 条；完整索引保存在 inventory.sqlite。可逐层浏览任意目录；父子目录占用不能相加。').pack(fill='x', pady=5)
        self.preview_text = scrolledtext.ScrolledText(self.preview_tab, wrap='word', height=24)
        self.preview_text.pack(fill='both', expand=True)
        self.preview_text.configure(state='disabled')
        ttk.Button(self.preview_tab, text='打开完整逐文件预览', command=self.open_preview).pack(anchor='w', pady=6)
        ttk.Checkbutton(self.preview_tab, text='我已退出所选项目的应用、构建和任务，接受清单中的删除影响', variable=self.apps_closed).pack(anchor='w', pady=4)
        confirmbar = ttk.Frame(self.preview_tab)
        confirmbar.pack(fill='x', pady=6)
        ttk.Label(confirmbar, text='输入上方本次预览的确认词：').pack(side='left')
        ttk.Entry(confirmbar, textvariable=self.confirmation, width=35).pack(side='left', padx=8)
        self.execute_button = ttk.Button(confirmbar, text='永久删除已预览文件', command=self.execute, state='disabled')
        self.execute_button.pack(side='left')
        self.log_text = scrolledtext.ScrolledText(self.log_tab, wrap='word')
        self.log_text.pack(fill='both', expand=True)
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.poll)
        if run:
            self.load(run)
        elif REPORTS.exists() and (recent := latest_scan_run(REPORTS)):
            self.load(recent)
        else:
            self.refresh_live_topology()

    def tree(self, frame, columns, hierarchy_label=None, height=15):
        holder = ttk.Frame(frame)
        holder.pack(fill='both', expand=True)
        tree = ttk.Treeview(holder, columns=[x[0] for x in columns], height=height,
                            show='tree headings' if hierarchy_label else 'headings', selectmode='browse')
        if hierarchy_label:
            tree.heading('#0', text=hierarchy_label)
            tree.column('#0', width=330, minwidth=180, stretch=True)
        for key, label, width in columns:
            tree.heading(key, text=label)
            tree.column(key, width=width, minwidth=40, stretch=key in {'app','action','name'})
        ybar = ttk.Scrollbar(holder, orient='vertical', command=tree.yview)
        xbar = ttk.Scrollbar(holder, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky='nsew')
        ybar.grid(row=0, column=1, sticky='ns')
        xbar.grid(row=1, column=0, sticky='ew')
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        return tree

    def worker(self, action, done):
        if self.busy:
            messagebox.showinfo('操作正在进行', '请等待当前操作完成，或先停止。')
            return
        self.busy = True
        self.personal_button.configure(state='disabled')
        self.cancel.clear()
        self.execute_button.configure(state='disabled')
        def target():
            try:
                result = action()
                self.messages.put(('done', (done, result)))
            except Exception as error:
                self.messages.put(('error', str(error)))
        threading.Thread(target=target, daemon=True).start()

    def progress(self, text):
        self.messages.put(('progress', text))

    def poll(self):
        try:
            for _ in range(100):
                kind, value = self.messages.get_nowait()
                if kind == 'progress':
                    self.status.set(value)
                    self.log_text.insert('end', value + '\n')
                    self.log_text.see('end')
                elif kind == 'done':
                    self.busy = False
                    self.personal_button.configure(state='normal')
                    callback, result = value
                    callback(result)
                elif kind == 'error':
                    self.busy = False
                    self.personal_button.configure(state='normal')
                    self.invalidate()
                    self.status.set('操作未完成：' + value)
                    self.log_text.insert('end', '错误：' + value + '\n')
                    messagebox.showerror('操作未完成', value)
        except queue.Empty:
            pass
        except Exception as error:
            self.busy = False
            self.personal_button.configure(state='normal')
            self.invalidate()
            self.status.set('界面更新未完成：' + str(error))
            self.log_text.insert('end', '界面更新错误：' + str(error) + '\n')
            messagebox.showerror('界面更新未完成', str(error))
        finally:
            self.root.after(100, self.poll)

    def load(self, path):
        path = Path(path).resolve()
        def action():
            plan = json.loads((path/'cleanup_plan.json').read_text(encoding='utf-8'))
            data = {d:json.loads((path/d/'analysis.json').read_text(encoding='utf-8')) for d in ('C','D')}
            return path, plan, data, storage_topology(), datetime.now()
        def done(result):
            self.run, self.plan, self.data, self.topology, self.topology_sampled_at = result
            self.topology_read_failed = not bool(self.topology)
            self.selected.clear()
            self.personal.set(False)
            self.personal_state = False
            self.search.set('')
            self.active_query = ''
            self.folder_matches = {}
            self.invalidate()
            self.refresh()
            times = '；'.join(d + ' 盘 ' + a['scan']['finished_at'] for d,a in self.data.items())
            self.status.set('已载入扫描快照：' + times + ('。Windows 实时容量读取失败，已标为扫描时容量。' if self.topology_read_failed else '。默认只分析，未勾选清理项。'))
            self.notebook.select(self.overview)
        self.worker(action, done)

    def refresh_live_topology(self):
        """Read only the current Windows disk capacities, without rescanning files."""
        if self.busy:
            return
        def action():
            return storage_topology(), datetime.now()
        def done(result):
            self.topology, self.topology_sampled_at = result
            self.topology_read_failed = not bool(self.topology)
            self.refresh()
            if self.preview and self.preview.summary['ready_files']:
                self.execute_button.configure(state='normal')
            self.status.set('Windows 实时硬盘容量读取失败；已保留扫描时容量，扫描快照和可清理项没有变化。'
                            if self.topology_read_failed else
                            '已刷新 Windows 实时硬盘容量；扫描快照和可清理项保持不变。')
        self.worker(action, done)

    def choose_run(self):
        if self.busy: return
        selected = filedialog.askdirectory(title='选择含 cleanup_plan.json 的报告目录', initialdir=REPORTS)
        if selected: self.load(selected)

    def pipeline(self, mode, run):
        command = [sys.executable, '-u', str(PROJECT/'main.py'), '--mode', mode, '--run', str(run)]
        env = {**os.environ, 'PYTHONUTF8':'1', 'PYTHONUNBUFFERED':'1'}
        with subprocess.Popen(command, cwd=PROJECT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              encoding='utf-8', errors='replace', creationflags=subprocess.CREATE_NO_WINDOW) as process:
            self.process = process
            try:
                for line in process.stdout:
                    self.progress(line.rstrip())
                result = process.wait()
                if result or self.cancel.is_set():
                    raise RuntimeError('扫描或分析已停止 / 失败；已有清单保留，可查看日志。')
            finally:
                self.process = None
        return run

    def scan(self):
        if self.busy: return
        self.invalidate()
        run = REPORTS / ('full_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
        self.notebook.select(self.log_tab)
        self.worker(lambda:self.pipeline('full', run), self.load)

    def reanalyze(self):
        if self.busy or not self.run: return
        self.invalidate()
        self.notebook.select(self.log_tab)
        run = self.run
        self.worker(lambda:self.pipeline('analyze', run), self.load)

    def reset_search(self):
        if self.busy:
            return
        self.search.set('')
        self.active_query = ''
        self.folder_matches = {}
        self.refresh()

    def query_folder_matches(self, run, drive, query, offset=0):
        escaped=query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        with closing(sqlite3.connect((run/drive/'inventory.sqlite').as_uri()+'?mode=ro', uri=True)) as con:
            con.set_progress_handler(lambda:1 if self.cancel.is_set() else 0,10000)
            return con.execute("SELECT id,path,total_bytes,total_files,EXISTS(SELECT 1 FROM directories c WHERE c.parent=d.id) FROM directories d WHERE lower(path) LIKE ? ESCAPE '\\' ORDER BY total_bytes DESC LIMIT 501 OFFSET ?",
                               ('%'+escaped+'%',offset)).fetchall()

    def search_overview(self):
        if self.busy:
            return
        query=self.search.get().strip().lower()
        if not query:
            self.reset_search()
            return
        if not self.run:
            self.active_query=query
            self.folder_matches={}
            self.refresh()
            return
        run=self.run
        def action():
            return {drive:self.query_folder_matches(run,drive,query) for drive in self.data}
        def done(result):
            self.active_query=query
            self.folder_matches=result
            self.refresh()
            self.status.set(f'已按“{query}”筛选应用、用途和文件夹；文件夹结果按大小分页显示。')
        self.worker(action,done)

    def refresh(self):
        query = self.active_query
        self.build_overview(query)
        total = sum(analysis['scan']['files'] for analysis in self.data.values())
        rebuild = sum(g['estimated_bytes'] for g in self.plan.get('groups',[])
                      if g.get('risk') != 'personal' and g.get('category') != 'test_database')
        databases = sum(g['estimated_bytes'] for g in self.plan.get('groups',[])
                        if g.get('category') == 'test_database')
        media = sum(g['estimated_bytes'] for g in self.plan.get('groups',[]) if g.get('risk') == 'personal')
        self.summary_label.configure(text=(
            f'已索引 {total:,} 个文件。可清理内容 {human(rebuild)}；'
            f'测试数据库 {human(databases)} 需应用内整体处理；个人聊天媒体需确认 {human(media)}。'
            '所有清理都须预览核验。'
            + (' 旧版报告需点击“重新分析当前清单”。' if self.plan.get('schema_version') != 2 else '')
        ))
        self.build_cleanup_choices(query)
        self.selection_label.configure(text=f'已勾选 {len(self.selected)} 组 · 可清理上限 {human(sum(g["estimated_bytes"] for g in self.plan.get("groups",[]) if g["id"] in self.selected))}')

    def cleanup_bucket(self, group):
        """Return the UI safety bucket for a cleanup group."""
        if group.get('category') == 'test_database':
            return ('database', '需要应用内处理',
                    '测试数据库可重建，但不能逐文件删除；请停止实例后用数据库管理工具整体处理。')
        if group.get('risk') == 'personal':
            return ('personal', '聊天媒体需确认',
                    '可能失去唯一的原图、视频或语音；聊天数据库、附件和配置继续保留。')
        return ('rebuild', '可清理内容',
                '已按 Git、文件类型和静置时间筛选；预览会再次核验每个文件。')

    def build_cleanup_choices(self, query=''):
        self.choice_tree.delete(*self.choice_tree.get_children())
        buckets = {}
        order = ('rebuild', 'database', 'personal')
        for group in self.plan.get('groups', []):
            key, title, note = self.cleanup_bucket(group)
            if key == 'personal' and not self.personal.get():
                continue
            scopes = group.get('scopes', {})
            scope_paths = scopes.keys() if isinstance(scopes, dict) else scopes
            searchable = ' '.join(str(value) for value in (
                group.get('app', ''), TITLES.get(group.get('category'), group.get('category', '')), *scope_paths
            )).lower()
            if query and query not in searchable:
                continue
            buckets.setdefault(key, {'title': title, 'note': note, 'groups': []})['groups'].append(group)

        selectable = sum(group.get('estimated_bytes', 0)
                         for key, item in buckets.items() if key != 'database' for group in item['groups'])
        database = sum(group.get('estimated_bytes', 0) for group in buckets.get('database', {}).get('groups', []))
        personal = sum(group.get('estimated_bytes', 0) for group in buckets.get('personal', {}).get('groups', []))
        personal_note = (f'；当前显示需确认聊天媒体 {human(personal)}' if self.personal.get()
                         else '；需确认聊天媒体默认隐藏')
        self.cleanup_summary.configure(text=(
            f'智能建议按操作方式分组：可清理 {human(selectable)}，'
            f'测试数据库 {human(database)} 需要应用内处理{personal_note}。'
        ))

        for bucket_key in order:
            item = buckets.get(bucket_key)
            if not item:
                continue
            grouped = {}
            for group in item['groups']:
                grouped.setdefault(group.get('drive', '未知'), []).append(group)
            total = sum(group.get('estimated_bytes', 0) for group in item['groups'])
            root_id = f'cleanup-{bucket_key}'
            self.choice_tree.insert('', 'end', iid=root_id, text=item['title'],
                                    values=('', '', '', '', '', human(total), f'{len(item["groups"]):,} 组'), open=True)
            for drive in sorted(grouped):
                drive_groups = sorted(grouped[drive], key=lambda group: (-group.get('estimated_bytes', 0), group['id']))
                drive_total = sum(group.get('estimated_bytes', 0) for group in drive_groups)
                drive_id = f'{root_id}-{drive}'
                self.choice_tree.insert(root_id, 'end', iid=drive_id, text=f'{drive}: 分区',
                                        values=('', '', drive, '', '', human(drive_total), f'{len(drive_groups):,} 组'), open=True)
                for group in drive_groups:
                    mark = '应用内处理' if bucket_key == 'database' else ('☑ 已选' if group['id'] in self.selected else '□ 未选')
                    category = TITLES.get(group.get('category'), group.get('category', ''))
                    self.choice_tree.insert(drive_id, 'end', iid=group['id'],
                                            text=f'{group.get("app", "未识别应用")} · {category}',
                                            values=(mark, group['id'], group.get('drive', ''), group.get('app', ''),
                                                    category, human(group.get('estimated_bytes', 0)),
                                                    f'{group.get("files", 0):,}'))

    def overview_insert(self, tree, parent, text, kind, size=0, candidate=0, files=0, action='', *, row=None, lazy=None, opened=False):
        self.overview_serial += 1
        ident = 'overview-' + str(self.overview_serial)
        tree.insert(parent, 'end', iid=ident, text=text,
            values=(kind, human(size), '—' if candidate is None else human(candidate), f'{files:,}'), open=opened)
        self.overview_trees[ident] = tree
        self.overview_details[ident] = action
        if row is not None:
            self.overview_rows[ident] = row
        if lazy is not None:
            self.overview_lazy[ident] = lazy
            tree.insert(ident, 'end', iid=ident + '-placeholder', text='展开加载…', values=('加载中', '', '', ''))
        return ident

    def topology_insert(self, parent, text, kind, capacity=None, used=None, free=None,
                        health='', coverage='', detail='', opened=False):
        self.topology_serial += 1
        ident = 'topology-' + str(self.topology_serial)
        value = lambda amount: '—' if amount is None else human(amount)
        self.topology_tree.insert(parent, 'end', iid=ident, text=text,
                                  values=(kind, value(capacity), value(used), value(free), health or '—', coverage),
                                  open=opened)
        self.topology_details[ident] = detail
        return ident

    def disk_title(self, disk):
        parts = [f'磁盘 {disk.number}', disk.bus_type, disk.name]
        return ' · '.join(part for part in parts if part)

    def partition_for_drive(self, drive):
        for disk in self.topology:
            for partition in disk.partitions:
                if partition.drive_letter == drive:
                    return partition
        return None

    def drive_title(self, drive):
        partition = self.partition_for_drive(drive)
        return partition_title(partition) if partition else f'{drive}: 扫描分区'

    def scan_disk_groups(self):
        mapping = drive_to_disk(self.topology)
        groups = []
        mapped = set()
        for disk in self.topology:
            drives = [drive for drive in ('C', 'D') if drive in self.data and mapping.get(drive) == disk]
            if drives:
                groups.append((disk, drives))
                mapped.update(drives)
        remaining = [drive for drive in ('C', 'D') if drive in self.data and drive not in mapped]
        if remaining:
            groups.append((None, remaining))
        return groups

    def build_topology(self):
        self.topology_tree.delete(*self.topology_tree.get_children())
        self.topology_details = {}
        self.topology_serial = 0
        sampled = self.topology_sampled_at.strftime('%Y-%m-%d %H:%M:%S') if self.topology_sampled_at else '未读取'
        if self.topology_read_failed:
            self.topology_title.set(f'物理硬盘与分区 · 实时容量读取失败（尝试于 {sampled}）')
            self.topology_tree.heading('used', text='扫描时已用')
            self.topology_tree.heading('free', text='扫描时可用')
        else:
            self.topology_title.set(f'物理硬盘与分区 · 当前实时容量（读取于 {sampled}）')
            self.topology_tree.heading('used', text='当前已用')
            self.topology_tree.heading('free', text='当前可用')
        self.topology_box.configure(text=self.topology_title.get())
        if not self.topology:
            root = self.topology_insert('', '实时容量读取失败' if self.topology_read_failed else '未读取物理硬盘拓扑',
                                        '扫描快照', detail=(
                'Windows 未返回物理硬盘信息，以下仅显示报告扫描时的 C、D 容量快照，不是当前容量。'
                if self.topology_read_failed else
                'Windows 未返回物理硬盘信息，以下仅显示已载入报告中的 C、D 扫描快照。'))
            for drive in ('C', 'D'):
                if drive not in self.data:
                    continue
                scan = self.data[drive]['scan']
                volume = scan.get('volume_after', {})
                self.topology_insert(root, f'{drive}: 扫描快照', '扫描快照', volume.get('total'),
                    volume.get('used'), volume.get('free'), '—', '扫描快照',
                    f'扫描完成：{scan.get("finished_at", "未知")}；逻辑文件 {human(scan.get("logical_bytes", 0))}。'
                    ' Windows 实时容量当前不可用。')
            return
        for disk in self.topology:
            scanned = [part.drive_letter for part in disk.partitions if part.drive_letter in self.data]
            root = self.topology_insert('', self.disk_title(disk), '物理硬盘', disk.size, health=disk.health,
                coverage=(f'扫描分区：{", ".join(scanned)}' if scanned else '没有已载入的扫描分区'),
                detail=(f'这是一个物理硬盘，容量 {human(disk.size)}；其分区不能当作多块硬盘相加。'
                        f' 状态：{disk.health or "未知"} / {disk.operational_status or "未知"}。'), opened=True)
            for partition in disk.partitions:
                drive = partition.drive_letter
                scan = self.data.get(drive, {}).get('scan') if drive else None
                if scan:
                    candidate = sum(group.get('estimated_bytes', 0) for group in self.plan.get('groups', [])
                                    if group.get('drive') == drive)
                    coverage = f'已扫描 · 可清理上限 {human(candidate)}'
                    detail = (f'{self.drive_title(drive)} 的实时容量来自 Windows；扫描快照完成于 '
                              f'{scan.get("finished_at", "未知")}，索引逻辑文件 {human(scan.get("logical_bytes", 0))} '
                              f'、{scan.get("files", 0):,} 个。可清理项须在清理页预览后才能执行。')
                else:
                    coverage = '仅容量展示 · 不扫描/清理'
                    system_partition = partition.partition_type in {'System', 'Reserved', 'Recovery'}
                    detail = ('该分区用于系统、保留或恢复；仅展示容量，不提供可清理项。'
                              if system_partition else
                              '该数据分区不在本次 C/D 扫描范围内；仅展示容量，不提供可清理项。')
                self.topology_insert(root, partition_title(partition),
                    '已扫描分区' if scan else ('系统 / 恢复分区' if partition.partition_type in {'System', 'Reserved', 'Recovery'} else '未扫描分区'),
                    partition.volume_size if partition.volume_size is not None else partition.size,
                    partition.used, partition.free, partition.health, coverage, detail)

    def show_topology_detail(self, event=None):
        ident = self.topology_tree.focus()
        if not ident or not self.topology_tree.exists(ident):
            return
        values = self.topology_tree.item(ident, 'values')
        self.overview_detail_title.set(self.topology_tree.item(ident, 'text'))
        metrics = ' · '.join(str(value) for value in values if value and value != '—')
        detail = self.topology_details.get(ident, '')
        self.overview_detail.set(metrics + (('\n' + detail) if detail else ''))

    def build_overview(self, query=''):
        for tree in (self.app_tree, self.folder_tree):
            tree.delete(*tree.get_children())
        self.overview_rows = {}
        self.overview_lazy = {}
        self.overview_trees = {}
        self.overview_details = {}
        self.overview_serial = 0
        self.build_topology()
        if not self.data:
            return
        groups = self.plan.get('groups', [])
        scans = [analysis['scan'] for analysis in self.data.values()]
        total_logical = sum(scan.get('logical_bytes', 0) for scan in scans)
        total_candidate = sum(group.get('estimated_bytes', 0) for group in groups)
        total_files = sum(scan.get('files', 0) for scan in scans)
        app_root = self.overview_insert(self.app_tree, '', '应用智能分析', '扫描范围', total_logical,
            total_candidate, total_files, '文件按应用、数据布局或最近 Git 项目归属；同一文件只归入一个应用。', opened=True)
        folder_root = self.overview_insert(self.folder_tree, '', '文件夹分析', '扫描范围', total_logical,
            None, total_files, '目录大小包含子目录，父子目录不能相加；可清理项不在此树中重复计算。', opened=True)
        for disk, drives in self.scan_disk_groups():
            disk_logical = sum(self.data[drive]['scan'].get('logical_bytes', 0) for drive in drives)
            disk_candidate = sum(group.get('estimated_bytes', 0) for group in groups if group.get('drive') in drives)
            disk_files = sum(self.data[drive]['scan'].get('files', 0) for drive in drives)
            if disk:
                title = self.disk_title(disk)
                action = f'物理容量 {human(disk.size)}；下方按该硬盘的已扫描分区展开。'
            else:
                title = '未匹配物理硬盘的扫描分区'
                action = 'Windows 未返回这些扫描分区的物理硬盘映射；仍可分别查看分析结果。'
            app_disk = self.overview_insert(self.app_tree, app_root, title, '物理硬盘', disk_logical,
                disk_candidate, disk_files, action, opened=True)
            folder_disk = self.overview_insert(self.folder_tree, folder_root, title, '物理硬盘', disk_logical,
                None, disk_files, action, opened=True)
            for drive in drives:
                analysis = self.data[drive]
                scan = analysis['scan']
                candidate = sum(group.get('estimated_bytes', 0) for group in groups if group.get('drive') == drive)
                title = self.drive_title(drive)
                app_drive = self.overview_insert(self.app_tree, app_disk, title, '已扫描分区',
                    scan.get('logical_bytes', 0), candidate, scan.get('files', 0),
                    '按应用、已识别数据布局或最近 Git 项目归属汇总。', opened=True)
                self.populate_applications(self.app_tree, app_drive, drive, query)
                folder_drive = self.overview_insert(self.folder_tree, folder_disk, title, '已扫描分区',
                    scan.get('logical_bytes', 0), None, scan.get('files', 0),
                    '按真实目录结构逐层展开；双击文件夹可进入完整目录浏览。', opened=True)
                if query:
                    self.populate_folder_rows(self.folder_tree, folder_drive, drive,
                                              self.folder_matches.get(drive, []), query, 0)
                else:
                    self.populate_folders(self.folder_tree, folder_drive, drive, 1, 0)

    def open_overview_node(self, tree=None, event=None):
        tree = tree or self.app_tree
        self.expand_overview(tree.focus())

    def expand_overview(self, ident):
        lazy = self.overview_lazy.pop(ident, None)
        if not lazy:
            return
        tree = self.overview_trees[ident]
        placeholder = ident + '-placeholder'
        if tree.exists(placeholder):
            tree.delete(placeholder)
        kind = lazy['kind']
        if kind == 'app_details':
            self.populate_app_details(tree, ident, lazy['drive'], lazy['app'], lazy.get('query',''))
        elif kind in {'folders','folder'}:
            self.populate_folders(tree, ident, lazy['drive'], lazy['parent_id'], lazy.get('offset',0))

    def populate_applications(self, tree, parent, drive, query=''):
        analysis = self.data[drive]
        storage = analysis.get('storage_groups', [])
        by_app={}
        shown = 0
        for row in storage:
            by_app.setdefault(row['app'],[]).append(row)
        for app, values in sorted(analysis.get('applications', {}).items(), key=lambda item:item[1].get('logical_bytes',0), reverse=True):
            matching = [row for row in by_app.get(app,[]) if not query or query in (app+' '+row['label']+' '+row['scope']).lower()]
            if query and query not in app.lower() and not matching:
                continue
            self.overview_insert(tree, parent, app, '应用 / 项目', values.get('logical_bytes',0), values.get('candidate_bytes',0),
                values.get('files',0), '展开查看用途与分析路径',
                lazy={'kind':'app_details','drive':drive,'app':app,'query':query})
            shown += 1
        if not shown:
            self.overview_insert(tree, parent, '无匹配应用', '结果', 0, 0, 0,
                                 '清除搜索可查看完整应用树。')

    def populate_app_details(self, tree, parent, drive, app, query=''):
        rows = [row for row in self.data[drive].get('storage_groups', []) if row['app'] == app]
        for row in sorted(rows, key=lambda value:value['logical_bytes'], reverse=True):
            if query and query not in (app+' '+row['label']+' '+row['scope']).lower():
                continue
            label = row['label'] + ((' · ' + row['scope']) if row['scope'] else '')
            self.overview_insert(tree, parent, label, '用途 / 路径', row['logical_bytes'], row.get('candidate_bytes',0),
                row['files'], row['action'], row={'kind':'storage','drive':drive,'storage':row})

    def populate_folders(self, tree, parent, drive, parent_id, offset=0):
        if not self.run:
            return
        try:
            with closing(sqlite3.connect((self.run/drive/'inventory.sqlite').as_uri()+'?mode=ro', uri=True)) as con:
                rows=con.execute('SELECT id,path,total_bytes,total_files,EXISTS(SELECT 1 FROM directories c WHERE c.parent=d.id) FROM directories d WHERE parent=? ORDER BY total_bytes DESC LIMIT 501 OFFSET ?',
                                 (parent_id,offset)).fetchall()
        except (OSError, sqlite3.Error) as error:
            self.overview_insert(tree, parent, '文件夹索引不可用', '扫描缺口', 0, None, 0,
                f'{drive} 盘目录索引无法读取：{error}。可重新扫描，应用占用结果仍可查看。')
            return
        shown = rows[:500]
        for directory_id,path,size,files,has_children in shown:
            self.overview_insert(tree, parent, Path(path).name or path, '文件夹', size, None, files,
                '双击进入完整目录浏览；展开查看下一级', row={'kind':'folder','drive':drive,'path':path},
                lazy={'kind':'folder','drive':drive,'parent_id':directory_id,'offset':0} if has_children else None)
        if len(rows)>500:
            self.overview_insert(tree, parent, f'继续加载后续文件夹（已显示 {offset+500:,}）', '加载更多', 0, None, 0,
                '双击加载下一批', row={'kind':'more','target':parent,'drive':drive,'parent_id':parent_id,
                                       'offset':offset+500})
        if not shown:
            self.overview_insert(tree, parent, '此文件夹下没有子文件夹', '结果', 0, None, 0, '')

    def populate_folder_rows(self,tree,parent,drive,rows,query,offset):
        for directory_id,path,size,files,has_children in rows[:500]:
            self.overview_insert(tree,parent,path,'匹配文件夹',size,None,files,
                '双击进入完整目录浏览',row={'kind':'folder','drive':drive,'path':path})
        if len(rows)>500:
            self.overview_insert(tree,parent,f'继续加载搜索结果（已显示 {offset+500:,}）','加载更多',0,None,0,
                '双击在后台加载下一批',row={'kind':'search_more','target':parent,'drive':drive,
                                             'offset':offset+500,'query':query})
        if not rows:
            self.overview_insert(tree,parent,'无匹配文件夹','结果',0,None,0,'清除搜索可浏览完整目录树')

    def invalidate(self):
        self.session = self.preview = None
        self.apps_closed.set(False)
        self.confirmation.set('')
        self.execute_button.configure(state='disabled')

    def personal_changed(self):
        if self.busy:
            self.personal.set(self.personal_state)
            return
        self.personal_state = self.personal.get()
        if not self.personal.get():
            self.selected -= {g['id'] for g in self.plan.get('groups',[]) if g.get('risk') == 'personal'}
        self.invalidate()
        self.refresh()

    def clear_selection(self):
        if self.busy: return
        self.selected.clear()
        self.invalidate()
        self.refresh()

    def toggle(self, key):
        if self.busy or not key: return
        group = next((g for g in self.plan.get('groups', []) if g['id'] == key), None)
        if not group:
            return
        if group['category'] == 'test_database':
            messagebox.showinfo('测试数据库', '数据仍计入占用。请停止实例后使用数据库管理方式整体处理，避免逐文件清理破坏数据库。')
            return
        if key in self.selected: self.selected.remove(key)
        else: self.selected.add(key)
        self.invalidate()
        self.refresh()

    def click_choice(self, event):
        if self.choice_tree.identify_column(event.x) == '#1':
            self.toggle(self.choice_tree.identify_row(event.y))

    def toggle_focus(self, event):
        self.toggle(self.choice_tree.focus())
        return 'break'

    def show_text(self, title, text):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry('940x620')
        box = scrolledtext.ScrolledText(window, wrap='word')
        box.pack(fill='both', expand=True, padx=10, pady=10)
        box.insert('1.0', text)
        box.configure(state='disabled')

    def show_overview_detail(self, tree=None):
        tree = tree or self.app_tree
        ident = tree.focus()
        if not ident or not tree.exists(ident):
            return
        values = tree.item(ident, 'values')
        self.overview_detail_title.set(tree.item(ident, 'text'))
        metrics = ' · '.join(str(value) for value in values if value)
        detail = self.overview_details.get(ident, '')
        self.overview_detail.set(metrics + (('\n' + detail) if detail else ''))

    def show_storage(self, tree=None, event=None):
        tree = tree or self.app_tree
        item = self.overview_rows.get(tree.focus())
        if not item:
            return
        if item['kind'] == 'storage':
            row=item['storage']
            self.show_text(row['app']+' · '+row['label'], json.dumps(row, ensure_ascii=False, indent=2))
        elif item['kind'] == 'folder':
            self.drive.set(item['drive'])
            self.folder.set(item['path'])
            self.notebook.select(self.browser)
            self.browse()
        elif item['kind'] == 'more':
            tree.delete(tree.focus())
            self.populate_folders(tree, item['target'], item['drive'], item['parent_id'], item['offset'])
        elif item['kind'] == 'search_more' and not self.busy:
            row_id=tree.focus()
            run=self.run
            def done(rows):
                if tree.exists(row_id):
                    tree.delete(row_id)
                    self.populate_folder_rows(tree,item['target'],item['drive'],rows,item['query'],item['offset'])
            self.worker(lambda:self.query_folder_matches(run,item['drive'],item['query'],item['offset']),done)

    def show_choice(self, event=None):
        if event and self.choice_tree.identify_column(event.x) == '#1': return
        key = self.choice_tree.focus()
        row = next((g for g in self.plan.get('groups',[]) if g['id']==key),None)
        if row: self.show_text('可清理范围 '+key, json.dumps(row, ensure_ascii=False, indent=2))

    def prepare(self):
        if self.busy: return
        if not self.run or not self.selected:
            messagebox.showinfo('尚未勾选', '请先在“可清理项”第一列勾选要预览的组。')
            return
        ids, personal, run = set(self.selected), self.personal.get(), self.run
        self.invalidate()
        self.notebook.select(self.preview_tab)
        def action():
            session = CleanupSession(run, POLICY)
            preview = session.prepare(ids, personal=personal, progress=self.progress, cancel=self.cancel)
            return session, preview
        def done(result):
            self.session, self.preview = result
            summary = self.preview.summary
            text = ('本次预览不会删除文件。执行将永久删除以下已验证文件，不经过回收站。\n'
                    + ('包含个人聊天媒体，原图、视频或语音可能无法恢复。\n' if summary['personal'] else '')
                    + f"\n可执行：{summary['ready_files']:,} 个，估算 {human(summary['estimated_bytes'])}\n跳过：{summary['skipped_files']:,} 个\n"
                    + '\n跳过依据：\n' + json.dumps(summary['skip_reasons'],ensure_ascii=False,indent=2)
                    + '\n\n完整逐文件预览：'+summary['records_path']
                    + '\n\n确认词：'+summary['confirmation']+'\n（15 分钟内有效；变更选择需重新预览）\n\n前 30 个文件：\n'
                    + '\n'.join(r['path']+'  '+human(r['estimated_bytes']) for r in self.preview.rows[:30]))
            self.preview_text.configure(state='normal')
            self.preview_text.delete('1.0','end')
            self.preview_text.insert('1.0',text)
            self.preview_text.configure(state='disabled')
            self.execute_button.configure(state='normal' if summary['ready_files'] else 'disabled')
            self.status.set('预览完成，尚未删除任何文件。')
        self.worker(action, done)

    def execute(self):
        if self.busy or not self.preview or not self.session: return
        if not self.apps_closed.get() or self.confirmation.get() != self.preview.summary['confirmation']:
            messagebox.showinfo('尚未确认', '请确认已退出相关应用，并准确输入上方的本次永久删除确认词。')
            return
        if not messagebox.askyesno('永久删除确认', f"将永久删除预览中的 {self.preview.summary['ready_files']:,} 个文件。不会放入回收站。\n是否执行？", default='no'):
            return
        session, preview = self.session, self.preview
        confirmation = self.confirmation.get()
        def done(result):
            result, topology, sampled_at = result
            self.topology = topology
            self.topology_sampled_at = sampled_at
            self.topology_read_failed = not bool(self.topology)
            self.invalidate()
            self.selected.clear()
            self.refresh()
            self.show_text('清理结果', json.dumps(result, ensure_ascii=False, indent=2))
            self.status.set('清理结束；Windows 实时容量读取失败，已保留扫描时容量。逐文件结果已保存，请重新扫描更新旧占用快照。'
                            if self.topology_read_failed else
                            '清理结束；实时容量已刷新。逐文件结果已保存，请重新扫描更新旧占用快照。')
        def action():
            result = session.execute(preview, confirmation=confirmation, apps_closed=True,
                                     progress=self.progress, cancel=self.cancel)
            return result, storage_topology(), datetime.now()
        self.worker(action, done)

    def browse(self, search=False):
        if self.busy or not self.run: return
        drive, folder, query, run = self.drive.get(), self.folder.get().rstrip('\\/'), self.file_query.get(), self.run
        if not folder or folder.lower() == drive.lower()+':': folder=drive+':\\'
        folder = str(Path(folder))
        if not search and Path(folder).drive.upper() in {'C:', 'D:'}:
            drive = Path(folder).drive[0].upper()
            self.drive.set(drive)
            self.folder.set(folder)
        def action():
            con=sqlite3.connect((run/drive/'inventory.sqlite').as_uri()+'?mode=ro',uri=True)
            try:
                if search:
                    escaped=query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
                    rows=con.execute("SELECT d.path,f.name,f.bytes,f.mtime FROM files f JOIN directories d ON d.id=f.directory WHERE f.name LIKE ? ESCAPE '\\' ORDER BY f.bytes DESC LIMIT 1001",('%'+escaped+'%',)).fetchall()
                    return [('文件',str(Path(p)/n),b,datetime.fromtimestamp(t).isoformat(' ',timespec='seconds')) for p,n,b,t in rows]
                ident=con.execute('SELECT id FROM directories WHERE path = ? COLLATE NOCASE',(folder,)).fetchone()
                if not ident: raise ValueError('此目录不在扫描索引中；检查盘符、路径或扫描缺口报告')
                rows=[('目录',p,b,f'{n:,} 个文件') for p,b,n in con.execute('SELECT path,total_bytes,total_files FROM directories WHERE parent=? ORDER BY total_bytes DESC LIMIT 1001',ident)]
                rows.extend(('文件',str(Path(folder)/n),b,datetime.fromtimestamp(t).isoformat(' ',timespec='seconds')) for n,b,t in con.execute('SELECT name,bytes,mtime FROM files WHERE directory=? ORDER BY bytes DESC LIMIT 1001',ident))
                return sorted(rows,key=lambda r:r[2],reverse=True)
            finally:
                con.close()
        def done(rows):
            self.path_tree.delete(*self.path_tree.get_children())
            self.path_rows={}
            for i,(kind,path,size,detail) in enumerate(rows[:1000]):
                key=str(i)
                self.path_rows[key]=(kind,path)
                self.path_tree.insert('','end',iid=key,values=(kind,path,human(size),detail))
            self.status.set('已显示目录 / 搜索结果前 '+str(min(len(rows),1000))+' 条。'+('更多结果请缩小范围。' if len(rows)>1000 else ''))
        self.worker(action,done)

    def search_files(self):
        if not self.file_query.get().strip(): return
        self.browse(search=True)

    def parent_folder(self):
        self.folder.set(str(Path(self.folder.get()).parent))
        self.browse()

    def drive_changed(self,event=None):
        self.folder.set(self.drive.get()+':\\')

    def open_path_row(self,event=None):
        row=self.path_rows.get(self.path_tree.focus())
        if not row: return
        kind,path=row
        if kind=='目录':
            self.folder.set(path)
            self.browse()
        else:
            self.show_text('文件位置',path+'\n\n此浏览器只显示元数据；清理请在“可清理项”中勾选。')

    def open_run(self):
        if self.run: os.startfile(self.run)

    def open_preview(self):
        if self.preview: os.startfile(self.preview.summary['records_path'])

    def stop(self):
        self.cancel.set()
        process=self.process
        if process and process.poll() is None:
            # Only this application's child process tree is stopped; user applications are untouched.
            subprocess.run(['taskkill.exe','/PID',str(process.pid),'/T','/F'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self.status.set('已请求停止；清理会在当前文件完成后停止，已完成结果保留。')

    def close(self):
        if self.busy:
            messagebox.showinfo('操作仍在进行','请先点击“停止当前操作”，等待当前操作结束后关闭窗口。')
            return
        self.root.destroy()


def launch(run=None):
    root=tk.Tk()
    Application(root,run)
    root.mainloop()
