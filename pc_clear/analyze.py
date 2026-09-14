"""Analyze complete inventories and emit a proposal; no cleanup implementation."""
from __future__ import annotations
import argparse
from collections import Counter,defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from .evidence import adjusted_size, environment_snapshot, git_filter
from .rules import application, classify_directory, classify_file, inside, load_policy, norm
from .scan import native, stamp, write_json

POTENTIAL = {'cache','build_cache','build_binary','temporary','logs','test_database'}
INHERITED = {'protected','system','installed','managed','user_data','dependency','app_managed'}


def read_inventory(path):
    connection = sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
    connection.row_factory = sqlite3.Row
    row = connection.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()
    if not row or not json.loads(row[0]).get('complete'):
        connection.close()
        raise ValueError(f'Incomplete inventory: {path}')
    return connection,json.loads(row[0])


def version_reviews(directories):
    groups=defaultdict(list)
    pattern=re.compile(r'^(PyCharm|IntelliJIdea|IdeaIC|Rider|GoLand|CLion|WebStorm|DataGrip|AndroidStudio|app-)(\d+(?:\.\d+){1,4})$',re.I)
    for row in directories.values():
        path=Path(row['path'])
        match=pattern.match(path.name)
        if not match or row['total_bytes'] < 1024**2:
            continue
        # Do not interpret versioned package directories inside dependencies as old apps.
        if any(x in norm(path).split('/') for x in ('node_modules','.git','site-packages')):
            continue
        groups[(norm(path.parent),match[1].lower())].append((tuple(map(int,match[2].split('.'))),row,match[2]))
    result=[]
    for values in groups.values():
        if len(values)<2:
            continue
        newest=max(x[0] for x in values)
        for version,row,text in values:
            if version < newest:
                result.append({'path':row['path'],'version':text,'newer_sibling':'.'.join(map(str,newest)),
                               'logical_bytes':row['total_bytes'],'newest_mtime':row['newest'],
                               'decision':'版本号较旧；兼容、回退、配置或插件用途未确认，未列入自动清理候选'})
    return sorted(result,key=lambda x:x['logical_bytes'],reverse=True)


def analyze_drive(database,policy,environment,manifest):
    con,scan=read_inventory(database)
    drive=scan['root'][:1]
    directories={r['id']:dict(r) for r in con.execute('SELECT * FROM directories ORDER BY id')}
    by_path={norm(r['path']):r for r in directories.values()}
    for gap in con.execute("SELECT path FROM gaps"):
        if Path(gap['path']).name.lower()=='.git':
            parent=by_path.get(norm(Path(gap['path']).parent))
            if parent:
                parent['repository']=1
    repositories={}
    contexts={}
    owners={}
    shapes=defaultdict(set)
    for row in con.execute("SELECT directory,name FROM files WHERE name IN ('index','data_0','data_1','ibdata1')"):
        shapes[row['directory']].add(row['name'])
    for row in directories.values():
        if Path(row['path']).name.lower() in {'cache_data','index-dir'} and row['parent']:
            shapes[row['parent']].add(Path(row['path']).name.lower())
    chromium=set()
    for ident,features in shapes.items():
        row=directories[ident]
        if Path(row['path']).name.lower() in {'cache','cache_data'} and (
            'cache_data' in features or ('index' in features and features & {'data_0','data_1','index-dir'})):
            chromium.add(norm(row['path']))
    mysql_roots=[]
    for ident,features in shapes.items():
        path=directories[ident]['path']
        if 'ibdata1' in features and Path(path).name.lower()=='data' and any(inside(path,p) for p in policy['confirmed_rebuildable_database_roots']):
            mysql_roots.append(norm(path))
    apps=defaultdict(Counter)
    category_totals=defaultdict(Counter)
    proposals=[]
    large_old=[]
    scattered_temp=[]
    types=defaultdict(Counter)
    dispositions=defaultdict(Counter)
    started=time.monotonic()
    last_progress=started
    for ident,row in directories.items():
        parent=row['parent']
        repo=row['path'] if row['repository'] else repositories.get(parent,'')
        repositories[ident]=repo
        inherited=contexts.get(parent)
        if inherited and inherited.category in INHERITED:
            context=inherited
        else:
            context=classify_directory(row['path'],policy,chromium,mysql_roots if '/.scratch/' in norm(row['path']) else ())
        contexts[ident]=context
        owner=application(row['path'],repo)
        owners[ident]=owner
        apps[owner]['logical_bytes']+=row['own_bytes']
        apps[owner]['files']+=row['own_files']
        category_totals[context.category]['logical_bytes']+=row['own_bytes']
        category_totals[context.category]['files']+=row['own_files']
        if any('cache' in part for part in norm(row['path']).split('/')):
            apps[owner]['cache_name_bytes']+=row['own_bytes']
        if context.category in {'temporary','logs'}:
            apps[owner]['temp_log_directory_bytes']+=row['own_bytes']
    for number,row in enumerate(con.execute('SELECT * FROM files'),1):
        ident=row['directory']
        folder=directories[ident]
        context=contexts[ident]
        owner=owners[ident]
        age=(scan['started_epoch']-row['mtime'])/86400
        types[row['extension'] or '[无扩展名]']['bytes']+=row['bytes']
        types[row['extension'] or '[无扩展名]']['files']+=1
        if age>=policy['aged_review_days']:
            apps[owner]['modified_over_90_days_bytes']+=row['bytes']
        decision,reason=classify_file(context,row['name'],age,policy)
        dispositions[decision]['files']+=1
        dispositions[decision]['bytes']+=row['bytes']
        if (age>=policy['aged_review_days'] and row['bytes']>=policy['large_review_bytes']) or (
            row['extension'] in policy['temporary_extensions'] and age>=policy['temporary_min_days'] and row['bytes']>=1024**2):
            entry={'path':os.path.join(folder['path'],row['name']),'bytes':row['bytes'],'age_days':round(age,1),
                   'app':owner,'decision':decision,'reason':reason}
            if age>=policy['aged_review_days'] and row['bytes']>=policy['large_review_bytes']:
                large_old.append(entry)
            if row['extension'] in policy['temporary_extensions']:
                scattered_temp.append(entry)
        if decision=='candidate':
            repo=repositories[ident]
            path=os.path.join(folder['path'],row['name'])
            if context.category in {'build_binary','test_database'} and not repo:
                dispositions['no_repository_evidence']['bytes']+=row['bytes']
                dispositions['no_repository_evidence']['files']+=1
                continue
            if context.category=='test_database':
                root=by_path[context.scope]
                active=any(inside(context.scope,p) or inside(p,context.scope) for p in environment['active_datadirs'])
                incomplete=bool(environment['unresolved_database_processes'])
                quiet=(scan['started_epoch']-root['newest'])/3600 >= policy['database_quiet_hours']
                if active or incomplete or not quiet or root['errors'] or root['skipped']:
                    dispositions['database_active_recent_or_unverified']['bytes']+=row['bytes']
                    dispositions['database_active_recent_or_unverified']['files']+=1
                    continue
            proposals.append({'drive':drive,'file_id':row['id'],'path':path,'app':owner,
                              'category':context.category,'scope':context.scope,'logical_bytes':row['bytes'],
                              'mtime':row['mtime'],'repository':repo,'reason':reason})
        if time.monotonic()-last_progress>=10:
            last_progress=time.monotonic()
            print(json.dumps({'stage':'classify','drive':drive,'files':number,'potential_files':len(proposals)},ensure_ascii=True),flush=True)
    print(json.dumps({'stage':'git_verification','drive':drive,'potential_files':len(proposals)},ensure_ascii=True),flush=True)
    git_groups=defaultdict(list)
    for row in proposals:
        if row['repository']:
            git_groups[row['repository']].append(row['path'])
    git_states={}
    git_errors=[]
    for index,(repo,paths) in enumerate(git_groups.items(),1):
        states,error=git_filter(repo,paths)
        git_states.update(states)
        if error:
            git_errors.append({'repository':repo,'error':error})
        if index%10==0:
            print(json.dumps({'stage':'git_verification','drive':drive,'repositories_done':index,'repositories_total':len(git_groups)},ensure_ascii=True),flush=True)
    selections=defaultdict(lambda:{'files':0,'estimated_bytes':0,'logical_bytes':0,'scopes':defaultdict(Counter),'types':Counter()})
    verified=0
    for row in proposals:
        git_state=git_states.get(row['path'],'outside_repository' if not row['repository'] else 'git_unverified')
        if git_state not in {'outside_repository','ignored_untracked'}:
            dispositions[git_state]['files']+=1
            dispositions[git_state]['bytes']+=row['logical_bytes']
            continue
        try:
            info=os.stat(native(row['path']),follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                exclusion='live_link_or_nonfile'
            elif info.st_nlink!=1:
                exclusion='multiple_hardlinks'
            elif info.st_size!=row['logical_bytes'] or abs(info.st_mtime-row['mtime'])>0.001:
                exclusion='changed_since_scan'
            else:
                exclusion=''
            if exclusion:
                dispositions[exclusion]['files']+=1
                dispositions[exclusion]['bytes']+=row['logical_bytes']
                continue
            physical=adjusted_size(row['path'],info)
        except OSError:
            dispositions['live_unreadable']['files']+=1
            dispositions['live_unreadable']['bytes']+=row['logical_bytes']
            continue
        group_key='|'.join((drive,row['app'],row['category']))
        value=selections[group_key]
        value['drive'],value['app'],value['category']=drive,row['app'],row['category']
        value['files']+=1
        value['estimated_bytes']+=physical
        value['logical_bytes']+=row['logical_bytes']
        value['scopes'][row['scope']]['files']+=1
        value['scopes'][row['scope']]['estimated_bytes']+=physical
        value['types'][Path(row['path']).suffix.lower() or '[无扩展名]']+=physical
        apps[row['app']]['candidate_bytes']+=physical
        apps[row['app']]['candidate_files']+=1
        manifest.write(json.dumps({**row,'group_key':group_key,'git_state':git_state,'estimated_bytes':physical,
                                   'verified_nlink':info.st_nlink,'verified_at':stamp()},ensure_ascii=False)+'\n')
        verified+=1
        if verified%10000==0:
            manifest.flush()
            print(json.dumps({'stage':'live_verification','drive':drive,'verified_candidates':verified},ensure_ascii=True),flush=True)
    cache_directories=[]
    for ident,row in directories.items():
        name=Path(row['path']).name.lower()
        if any(x in name for x in ('cache','temp','crash','dump')) or name in {'logs','log','tmp'}:
            ctx=contexts[ident]
            cache_directories.append({'path':row['path'],'logical_bytes':row['total_bytes'],'files':row['total_files'],
                                      'category':ctx.category,'reason':ctx.reason,'errors':row['errors'],'skipped':row['skipped']})
    result={'scan':scan,'applications':dict(apps),'categories':dict(category_totals),'dispositions':dict(dispositions),
            'types':dict(types),'git_repositories_discovered':len({p for p in repositories.values() if p}),
            'git_repositories_verified':len(git_groups),'git_errors':git_errors,
            'version_reviews':version_reviews(directories),'large_aged_files':sorted(large_old,key=lambda x:x['bytes'],reverse=True),
            'temporary_extension_files':sorted(scattered_temp,key=lambda x:x['bytes'],reverse=True),
            'cache_directories':sorted(cache_directories,key=lambda x:x['logical_bytes'],reverse=True),
            'mysql_roots':mysql_roots,'analysis_finished_at':stamp(),'analysis_elapsed_seconds':round(time.monotonic()-started)}
    con.close()
    return result,dict(selections)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--policy',type=Path,default=Path(__file__).resolve().parents[1]/'scan_policy.json')
    args=parser.parse_args()
    run=args.run.absolute()
    policy=load_policy(args.policy)
    environment=environment_snapshot()
    write_json(run/'environment.json',environment)
    all_data={}
    all_selections={}
    with (run/'candidate_files.jsonl').open('w',encoding='utf-8') as manifest:
        for drive in ('C','D'):
            result,selections=analyze_drive(run/drive/'inventory.sqlite',policy,environment,manifest)
            write_json(run/drive/'analysis.json',result)
            all_data[drive]=result
            all_selections.update(selections)
    groups=[]
    for index,(key,value) in enumerate(sorted(all_selections.items(),key=lambda x:(x[1]['drive'],-x[1]['estimated_bytes'],x[0])),1):
        groups.append({'id':f'F{index:03d}','group_key':key,**value,'mode':'manifest_files_only',
                       'require_app_closed_and_live_revalidation':True})
    plan={'approved':False,'execution_implemented':False,'generated_at':stamp(),
          'source_inventories':{d:all_data[d]['scan']['finished_at'] for d in all_data},
          'policy_sha256':hashlib.sha256(args.policy.read_bytes()).hexdigest(),
          'manifest':'candidate_files.jsonl','groups':groups,
          'rules':['User selection required. This plan never authorizes whole-directory deletion.',
                   'Recheck Git tracked/ignored state, current processes, path containment, links, types and file locks.',
                   'Skip changed, unreadable, linked or in-use files. Do not stop applications or services automatically.',
                   'Age and older version numbers alone do not make a file disposable.']}
    write_json(run/'cleanup_plan.json',plan)
    print(json.dumps({'complete':True,'groups':len(groups),'candidate_gib':sum(g['estimated_bytes'] for g in groups)/2**30,
                      'manifest_bytes':(run/'candidate_files.jsonl').stat().st_size},ensure_ascii=True),flush=True)


if __name__=='__main__':
    main()
