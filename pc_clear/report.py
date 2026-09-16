"""Render complete local reports from the inventory and unapproved manifest."""
from __future__ import annotations
import argparse
from collections import Counter,defaultdict
import datetime as dt
import json
from pathlib import Path
import shutil
import sqlite3

from .rules import norm
from .scan import stamp,write_json
from .topology import partition_title, storage_topology

TITLES={'cache':'应用缓存','build_cache':'代码生成缓存','build_binary':'编译中间二进制',
        'temporary':'较早的临时文件/转储','logs':'较早的应用日志','test_database':'测试数据库（应用内管理）',
        'codex_catalog':'Codex 目录缓存','generated_binary':'任务生成的二进制','chat_media':'个人聊天媒体（明确选择）'}
IMPACTS={'cache':'退出对应应用；资源、依赖或索引需重新加载、下载或生成',
         'build_cache':'结束相关任务；下次运行重新生成',
         'build_binary':'结束构建；下次完整编译会更慢',
         'temporary':'仅清单中的类型与年龄合格文件；退出使用它们的应用',
         'logs':'将失去对应时期的排障记录；仅选择明确不再需要的日志',
         'test_database':'停止状态且已确认可重建的实例；使用数据库管理方式整体处理，文件清理入口不执行部分删除',
         'codex_catalog':'退出 Codex；目录信息需要重新获取。会话、状态、配置、技能和运行环境保留',
         'generated_binary':'结束相关构建和任务；只含 Git 忽略且未跟踪的允许格式，重新构建时会生成',
         'chat_media':'个人数据：删除后聊天中的原图、视频、表情或语音可能无法查看或再次下载；数据库和文档附件保留。默认隐藏，须单独启用和确认'}


def human(n):
    for unit,factor in (('GiB',2**30),('MiB',2**20),('KiB',2**10)):
        if n>=factor:
            return f'{n/factor:.2f} {unit}'
    return f'{n} B'


def table(headers,rows):
    def escape(value):
        return str(value).replace('|','\\|').replace('\n',' ').replace('\r','')
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join('---' for _ in headers)+' |']+
                     ['| '+' | '.join(escape(v) for v in row)+' |' for row in rows])


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write(path,lines):
    path.write_text('\n'.join(lines)+'\n',encoding='utf-8')


def local_link(run,name):
    return f'[{name}]({(run/name).as_posix()})'


def physical_storage_section(disks, scanned_drives=('C', 'D')):
    """Render current physical disks before the logical scan-partition summary."""
    if not disks:
        return ['## 当前物理硬盘与分区', '',
                'Windows 未返回物理硬盘拓扑。本报告仍按 C、D 扫描分区展示；它们不应被解释为两块物理硬盘。', '']
    rows=[]
    for disk in disks:
        disk_name=' · '.join(value for value in (f'磁盘 {disk.number}', disk.bus_type, disk.name) if value)
        rows.append((disk_name, '物理硬盘', human(disk.size), '—', '—', disk.health or '—',
                     f'{len(disk.partitions)} 个分区'))
        for partition in disk.partitions:
            capacity=partition.volume_size if partition.volume_size is not None else partition.size
            used=human(partition.used) if partition.used is not None else '—'
            free=human(partition.free) if partition.free is not None else '—'
            coverage='本轮已扫描' if partition.drive_letter in scanned_drives else '仅容量展示，不扫描或清理'
            rows.append((f'　└ {partition_title(partition)}', partition.partition_type or '分区', human(capacity),
                         used, free, partition.health or '—', coverage))
    return ['## 当前物理硬盘与分区', '',
            '先按物理硬盘列出其分区。C、D 是分区；其容量相加只是扫描范围，不代表硬盘总容量。系统、保留和恢复分区只展示容量。', '',
            table(['硬盘 / 分区','类型','容量','当前已用','当前可用','状态','扫描范围'], rows), '']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    args=parser.parse_args()
    run=args.run.absolute()
    data={d:read(run/d/'analysis.json') for d in ('C','D')}
    plan=read(run/'cleanup_plan.json')
    env=read(run/'environment.json')
    assert plan['approved'] is False
    group_ids={g['group_key']:g['id'] for g in plan['groups']}
    selected={}
    git_counts=defaultdict(Counter)
    with (run/plan['manifest']).open(encoding='utf-8') as stream:
        for line in stream:
            item=json.loads(line)
            selected[norm(item['path'])]=group_ids[item['group_key']]
            git_counts[item['group_key']][item['git_state']]+=1
    volumes={d:dict(zip(('total','used','free'),shutil.disk_usage(d+':\\'))) for d in data}
    write_json(run/'volumes_latest.json',{'at':stamp(),'volumes':volumes})
    topology=storage_topology()
    total_files=sum(a['scan']['files'] for a in data.values())
    reclaim={d:sum(g['estimated_bytes'] for g in plan['groups'] if g['drive']==d) for d in data}
    direct_reclaim={d:sum(g['estimated_bytes'] for g in plan['groups']
                           if g['drive']==d and g.get('risk')!='personal' and g.get('category')!='test_database')
                    for d in data}
    database_reclaim={d:sum(g['estimated_bytes'] for g in plan['groups']
                             if g['drive']==d and g.get('category')=='test_database') for d in data}
    personal_reclaim={d:sum(g['estimated_bytes'] for g in plan['groups']
                             if g['drive']==d and g.get('risk')=='personal') for d in data}
    aged=[x for a in data.values() for x in a['large_aged_files']]
    versions=[x for a in data.values() for x in a['version_reviews']]
    ignored_sources=sum(a['dispositions'].get('tracked',{}).get('files',0) for a in data.values())
    app_count=sum(len(a['applications']) for a in data.values())
    lines=['# C、D 扫描分区完整分析与待选清理清单','',
           f'报告生成：{stamp()}。已完成全盘可访问文件的元数据扫描，共 **{total_files:,} 个文件**。未执行用户文件清理，也没有停止应用或服务。','',
           '## 本轮结论','',
           table(['扫描分区','当前可用空间','本轮候选估算','扫描文件数','扫描完成时间'],
                 [[d+':',human(volumes[d]['free']),human(reclaim[d]),f"{a['scan']['files']:,}",a['scan']['finished_at']] for d,a in data.items()]),'',
           f"可预览的可重建内容 **{human(sum(direct_reclaim.values()))}**；测试数据库 **{human(sum(database_reclaim.values()))}** 需停止实例后在应用内整体处理；另有个人聊天媒体可选范围 **{human(sum(personal_reclaim.values()))}**。聊天媒体不能视作无损可清理缓存。按应用和用途共 {len(plan['groups'])} 组；只能按逐文件清单选择，不能整删上级目录。","",
            '本轮编号以 F 开头。此前生成的审计估算属于历史快照；磁盘内容已变化，请以本轮清单为准，不与旧清单相加。磁盘空闲空间的变化不代表本任务执行了清理。','',
           *physical_storage_section(topology),
           f'读取到 {len(env["installed_apps"])} 条卸载注册表记录、{len(env["packaged_apps"])} 个当前用户商店包，以及 {len(env["processes"])} 条进程记录。注册记录可能含组件或重复项，不等于独立应用数量。按路径/仓库归属建立 {app_count} 个磁盘分组，完整占用表包含没有清理候选的应用和数据。','',
           f'初筛候选中 {ignored_sources} 个 Git 已跟踪文件被保留；仓库内只有“未跟踪且被忽略”的文件才可能通过。配置、源码、凭据、聊天数据库、文档附件、安装环境、多个硬链接、读取失败或扫描后变化的文件均保留。个人聊天媒体单列，默认不选择。','',
           '## 较大的待选项','',
           table(['编号','盘','应用 / 项目','类型','估计上限','文件数'],
                 [[g['id'],g['drive'],g['app'],TITLES[g['category']],human(g['estimated_bytes']),g['files']]
                  for g in plan['groups'] if g['estimated_bytes']>=100*2**20]),'',
           f"全部编号、精确目录、Git 依据、类型与影响见 {local_link(run,'全部清理选项.md')}。运行 main.py 打开图形界面，在“清理选项”勾选，再“预览已选文件”；所有选项默认不选。个人聊天媒体独立显示，需要额外启用。",'',
           f"Codex 会话、插件、运行环境、中间产物，以及微信/QQ 数据库、接收文件和媒体的明细见 {local_link(run,'智能占用分析.md')}。保护只影响清理，不隐藏占用。",'',
           '## 过时、旧版本和临时文件','',
           f'发现 **{len(versions)} 处较旧版本目录**（同系列有较新版本并存），以及 **{len(aged)} 个至少 100 MiB、超过 90 天未修改的文件**。它们是复核线索，不能仅凭版本号或修改日期认定可删。旧目录大小可能包含已列出的缓存，不能再累加为释放量。','',
           f"完整清单见 {local_link(run,'旧版本与旧文件.md')}。应用缓存、临时文件与日志目录的完整分类见 {local_link(run,'缓存临时目录全表.md')}。",'',
           '普通临时目录仅对超过 7 天的 .tmp/.temp/.dmp/.mdmp/.hdmp 等进行筛选；应用日志默认超过 30 天。临时目录里的 Git 项目、源码、配置、安装包和其他未知格式保留。散落在其他位置的旧 .tmp 文件仍列为用途待核实。','',
           '## 应保留或另行处理的内容','',
           '用户目录 .cache 仍含当前 Python/Node 运行环境和模型；LocalCache、WPS cache 等名称可能表示完整数据容器。只选择内部确认的资源缓存，保留 IndexedDB、Local Storage、会话、数据库与配置。音乐/小程序离线资源建议在应用内选择。','',
           'Windows、商店系统应用、Installer、Package Cache、WinSxS 和安装目录由系统或安装器管理。NuGet 全局包、Maven/Go 模块、pnpm 存储、虚拟环境、node_modules、模型和虚拟机继续统计，但未因为体积大或年代久远就加入删除清单。','',
           f"全部应用/路径分组占用见 {local_link(run,'应用占用全表.md')}，其中“含 cache 路径的文件字节”也可能是源码或依赖，并非可清理空间。",'',
           '## 覆盖范围与误差','',
           table(['盘','目录数','读取失败','跳过重解析点','显式跳过'],
                 [[d,a['scan']['directories'],a['scan'].get('errors',0),a['scan'].get('reparse_skipped',0),a['scan'].get('explicit_exclusions',0)] for d,a in data.items()]),'',
           f"全量逐文件索引位于 C/inventory.sqlite、D/inventory.sqlite；无法读取与跳过路径见 {local_link(run,'扫描缺口全表.md')}。本次显式跳过本工具 reports 输出，避免扫描过程中把自己的增长文件反复纳入。Git 忽略和保护规则不会让普通数据在全盘统计中消失。",'',
           '目录与应用占用使用逻辑字节，硬链接会重复，受保护系统内容及重解析点没有完整计入。候选在实测时排除多硬链接，并针对压缩/稀疏文件修正大小；仍不是严格的磁盘簇释放量。正在使用的文件要先关闭应用并再次检查，实际释放以清理后的空闲空间增量为准。','',
           '本轮按扩展名、固定文件名及目录布局判断文件类型，没有解析文档、模型或聊天内容。安装列表可能漏掉便携程序；运行进程没命中路径不能证明应用未使用。全盘扫描也是动态观察，不是文件系统冻结快照。','',
           '## 忽略规则和复用','',
           '[.gitignore](../../.gitignore) 忽略含本机私有路径的报告、SQLite 清单、旧报告、日志和 Python 生成物，保留扫描源码、规则和测试。','',
           '[scan_policy.json](../../scan_policy.json) 提供保护路径、保护文件类型、自定义保护规则、年龄阈值与独立扫描排除项。默认扫描排除列表为空；保护只影响候选。修改 Git 忽略规则不能将用户数据变成可删除缓存。','',
           '扫描与分析命令不删除文件。图形界面支持先预览再明确确认的永久清理，逐文件核验、记录结果；过期或变化文件跳过。复用方式见仓库 [README.md](../../README.md)。','']
    write(run/'完整分析结论.md',lines)
    options=['# 全部待选清理项','', '所有编号均未批准。每组只对应 candidate_files.jsonl 中 group_key 匹配的文件，目录表仅帮助定位，禁止解释为整目录删除。','',
             table(['编号','盘','应用 / 项目','用途','候选上限','文件数'],
                   [[g['id'],g['drive'],g['app'],TITLES[g['category']],human(g['estimated_bytes']),g['files']] for g in plan['groups']]),'']
    for g in plan['groups']:
        options += [f"## {g['id']} · {g['app']} · {TITLES[g['category']]} · {human(g['estimated_bytes'])}",'',
                    IMPACTS[g['category']],'',
                    'Git 依据：'+ '；'.join(f'{k}: {v} 个文件' for k,v in git_counts[g['group_key']].items())+'。','',
                    '主要后缀：'+ '；'.join(f'{k if len(k)<32 else "[散列后缀]"} {human(v)}' for k,v in sorted(g['types'].items(),key=lambda x:x[1],reverse=True)[:8])+'。','',
                    table(['精确范围（按清单内文件筛选）','候选文件数','候选上限'],
                          [[p,v['files'],human(v['estimated_bytes'])] for p,v in sorted(g['scopes'].items(),key=lambda x:x[1]['estimated_bytes'],reverse=True)]),'']
    write(run/'全部清理选项.md',options)
    storage=[(d,r) for d,a in data.items() for r in a.get('storage_groups',[])]
    special=[(d,r) for d,r in storage if r['kind'].startswith(('chat_','codex_')) or r['kind']=='generated']
    smart=['# 智能占用分析','',
           '按实际目录布局、文件格式、Git 状态、修改时间和运行状态给出可解释结论。不会读取聊天正文。每个文件仅归入一个用途组；可选聊天媒体不是可重建缓存，默认不选择。','',
           '## C、D 扫描分区汇总（非物理硬盘）','',
           table(['范围','分区容量合计','当前已用','当前可用','扫描逻辑文件','扫描文件数','可预览候选','测试数据库（应用内）','个人聊天媒体可选范围'],
                 [['C、D 扫描范围',human(sum(v['total'] for v in volumes.values())),human(sum(v['used'] for v in volumes.values())),
                   human(sum(v['free'] for v in volumes.values())),human(sum(a['scan']['logical_bytes'] for a in data.values())),
                   f'{total_files:,}',human(sum(direct_reclaim.values())),human(sum(database_reclaim.values())),
                   human(sum(personal_reclaim.values()))]]),'',
           '“分区容量合计”不是物理硬盘容量，且不含系统、保留和恢复分区。物理硬盘关系见“完整分析结论”开头；“当前已用”来自磁盘容量统计，“扫描逻辑文件”来自可访问普通文件求和。系统保护内容、硬链接、压缩文件和扫描过程中的变化会使两者不同。','']
    for d,a in data.items():
        app_rows=[(name,value) for name,value in a['applications'].items() if value.get('logical_bytes',0)]
        connection=sqlite3.connect((run/d/'inventory.sqlite').as_uri()+'?mode=ro',uri=True)
        try:
            folder_rows=connection.execute('SELECT path,total_bytes,total_files FROM directories WHERE parent=1 ORDER BY total_bytes DESC').fetchall()
        finally:
            connection.close()
        smart += [f'## {d} 盘','',
                  table(['分区容量','当前已用','当前可用','扫描逻辑文件','扫描文件数','可预览候选','测试数据库（应用内）','个人聊天媒体可选范围'],
                        [[human(volumes[d]['total']),human(volumes[d]['used']),human(volumes[d]['free']),human(a['scan']['logical_bytes']),
                          f"{a['scan']['files']:,}",human(direct_reclaim[d]),human(database_reclaim[d]),human(personal_reclaim[d])]]),'',
                  f'### {d} 盘 · 按应用','',
                  table(['应用 / 项目','逻辑占用','文件数','候选上限'],
                        [[name,human(value['logical_bytes']),value['files'],human(value.get('candidate_bytes',0))]
                         for name,value in sorted(app_rows,key=lambda item:item[1]['logical_bytes'],reverse=True)]),'',
                  f'### {d} 盘 · 按文件夹（根目录第一级）','',
                  table(['文件夹','逻辑占用','文件数'],[[path,human(size),files] for path,size,files in folder_rows]),'',
                  '图形界面可从上述根文件夹继续逐层展开；父子目录是包含关系，不能相加。','']
    smart += ['## Codex、任务生成数据、微信和 QQ','',
           table(['盘','应用','用途','逻辑占用','文件数','可选范围上限','目录','依据','处理方式'],
                 [[d,r['app'],r['label'],human(r['logical_bytes']),r['files'],human(r['candidate_bytes']),r['scope'],r['reason'],r['action']]
                  for d,r in sorted(special,key=lambda x:x[1]['logical_bytes'],reverse=True)]),'',
           '## 所有应用用途与路径明细','',
           table(['盘','应用/项目','用途','逻辑占用','文件数','超过 90 天未修改','可选范围上限'],
                 [[d,r['app'],r['label'],human(r['logical_bytes']),r['files'],human(r['old_bytes']),human(r['candidate_bytes'])]
                  for d,r in sorted(storage,key=lambda x:x[1]['logical_bytes'],reverse=True)]),'',
           '## 最大文件（不限制文件年龄）','',
           table(['盘','路径','占用','应用','类型','未修改天数'],
                 [[d,r['path'],human(r['bytes']),r['app'],r['kind'],r['age_days']]
                  for d,a in data.items() for r in a.get('largest_files',[])]),'',
           '每盘最大 500 个文件仅用于定位；图形界面“目录与文件”可以访问完整 SQLite 索引。未知目录、旧文件和安装包会显示出来，但不会仅凭名称或年龄列入删除。', '']
    write(run/'智能占用分析.md',smart)
    app_rows=[]
    for d,a in data.items():
        for app,v in a['applications'].items():
            if v.get('logical_bytes',0):
                app_rows.append((d,app,v))
    write(run/'应用占用全表.md',['# 应用和路径分组占用','',
          '每个已扫描文件仅归入一个分组；应用名称来自路径/最近 Git 仓库，不能等同于注册表产品数量。同一应用在不同磁盘、版本或路径可能分组显示。各列是重叠维度，不相加。','',
          table(['盘','应用 / 路径组','逻辑占用','文件数','含 cache 路径字节','临时/日志目录字节','超过 90 天未改字节','候选估算'],
                [[d,n,human(v['logical_bytes']),v['files'],human(v.get('cache_name_bytes',0)),human(v.get('temp_log_directory_bytes',0)),
                  human(v.get('modified_over_90_days_bytes',0)),human(v.get('candidate_bytes',0))]
                 for d,n,v in sorted(app_rows,key=lambda x:x[2]['logical_bytes'],reverse=True)])])
    cache_rows=[(d,x) for d,a in data.items() for x in a['cache_directories']]
    write(run/'缓存临时目录全表.md',['# 缓存、临时、日志和转储目录全表','',
          '包含所有此次扫描中名称匹配的目录，无大小阈值。父子目录不可相加。分类为缓存也不表示全部内容可删除；最终通过 Git、类型、链接和实时核验的文件见候选清单。','',
          table(['盘','路径','逻辑大小','文件数','分类','依据','读取失败','跳过项'],
                [[d,x['path'],human(x['logical_bytes']),x['files'],x['category'],x['reason'],x['errors'],x['skipped']]
                 for d,x in sorted(cache_rows,key=lambda x:x[1]['logical_bytes'],reverse=True)])])
    old_lines=['# 旧版本、旧文件与零散临时文件','',
               '这里只提供核实线索。“未修改”不等于“未使用”。版本目录、文件与缓存候选可能重合，不能累计为额外释放空间。','',
               '## 有较新同系列目录并存的旧版本','',
               table(['路径','旧版本','较新版本','逻辑大小','判断'],
                     [[x['path'],x['version'],x['newer_sibling'],human(x['logical_bytes']),x['decision']] for x in versions]),'',
               '## 已安装应用版本（注册表）','',
               table(['应用/组件','版本','安装位置'],
                     [[x.get('DisplayName',''),x.get('DisplayVersion',''),x.get('InstallLocation','')] for x in env['installed_apps']]),'',
               '## 至少 100 MiB 且超过 90 天未修改的文件','',
               table(['文件','逻辑大小','未修改天数','当前清单','初筛依据'],
                     [[x['path'],human(x['bytes']),x['age_days'],selected.get(norm(x['path']),'未列入清理'),x['reason']]
                      for x in sorted(aged,key=lambda x:x['bytes'],reverse=True)]),'',
               '## 至少 1 MiB、超过 7 天的临时/转储扩展名文件','',
               table(['文件','逻辑大小','未修改天数','当前清单','初筛依据'],
                     [[x['path'],human(x['bytes']),x['age_days'],selected.get(norm(x['path']),'未列入清理'),x['reason']]
                      for a in data.values() for x in a['temporary_extension_files']])]
    write(run/'旧版本与旧文件.md',old_lines)
    gaps=[]
    for d in data:
        con=sqlite3.connect((run/d/'inventory.sqlite').as_uri()+'?mode=ro',uri=True)
        gaps.extend((d,*row) for row in con.execute('SELECT path,reason,detail,bytes FROM gaps'))
        con.close()
    write(run/'扫描缺口全表.md',['# 扫描缺口全表','',
          '拒绝访问、重解析点、云占位或显式扫描排除均记录，不提升系统权限、不修改 ACL、不跟随链接。重解析点的字节仅为该条目元数据，不代表其目标内容大小。','',
          table(['盘','路径','原因','详情','条目字节'],gaps)])
    print(json.dumps({'reports_written':True,'files':total_files,'groups':len(plan['groups']),
                      'candidate_gib':{d:round(n/2**30,3) for d,n in reclaim.items()},'old_versions':len(versions),
                      'large_aged_files':len(aged),'gaps':len(gaps),'applications':app_count},ensure_ascii=True))


if __name__=='__main__':
    main()
