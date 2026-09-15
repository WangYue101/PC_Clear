import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from pc_clear.analyze import analyze_drive
from pc_clear.evidence import git_filter,git_run
from pc_clear.rules import classify_directory,classify_file,load_policy,norm,policy_digest
from pc_clear.scan import inventory, main as scan_main

POLICY=Path(__file__).resolve().parents[1]/'scan_policy.json'


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.policy=load_policy(POLICY)

    def classify(self,path,name,days=120,chromium=()):
        return classify_file(classify_directory(path,self.policy,chromium),name,days,self.policy)[0]

    def test_age_alone_never_authorizes(self):
        self.assertNotEqual(self.classify('D:/work/files','old.tmp',999),'candidate')
        self.assertNotEqual(self.classify('D:/work/files','old.zip',999),'candidate')
        self.assertEqual(self.classify('C:/Users/demo/AppData/Local/Temp','old.tmp'),'candidate')
        self.assertEqual(self.classify('C:/Users/demo/AppData/Local/Temp','fresh.tmp',1),'recent')

    def test_mixed_cache_profile_preserves_storage(self):
        root='C:/Users/demo/AppData/Roaming/kingsoft/wps/cache'
        self.assertNotEqual(self.classify(root,'unknown.bin'),'candidate')
        self.assertEqual(self.classify(root+'/Cache','data_0',chromium={norm(root+'/Cache')}),'candidate')
        for child in ('IndexedDB','Local Storage','Session Storage','WebStorage'):
            self.assertEqual(self.classify(root+'/'+child,'data.bin',chromium={norm(root)}),'protected')

    def test_source_configuration_and_credentials_preserved(self):
        for name in ('work.py','test.sql','settings.json','.env','private.pem','run.ps1','config.xml'):
            self.assertEqual(self.classify('C:/Users/demo/AppData/Local/Temp',name),'protected')
        self.assertEqual(self.classify('D:/project/node_modules/cache','data_0',chromium={'d:/project/node_modules/cache'}),'protected')
        self.assertNotEqual(self.classify('C:/Users/demo/AppData/Local/Packages/MicrosoftWindows.Client.CBS/Code Cache','data_0'),'candidate')
        self.assertNotEqual(self.classify('C:/Windows/.codex/cache/remote_plugin_catalog','0123456789abcdef.json'),'candidate')

    def test_custom_ignore_protects_but_does_not_hide_inventory(self):
        self.policy['custom_protected_paths']=['d:/keep']
        self.assertEqual(self.classify('D:/keep/Temp','old.tmp'),'protected')
        self.assertEqual(self.policy['scan_excludes'],[])

    def test_ignored_local_policy_is_merged_and_changes_the_binding(self):
        with tempfile.TemporaryDirectory(prefix='pc_clear_test_') as temp:
            base=Path(temp)
            policy=base/'scan_policy.json'
            base_policy=json.loads(POLICY.read_text(encoding='utf-8'))
            base_policy['custom_protected_paths']=['D:/shared']
            base_policy['confirmed_rebuildable_database_roots']=[]
            policy.write_text(json.dumps(base_policy),encoding='utf-8')
            before=policy_digest(policy)
            local=base/'scan_policy.local.json'
            local.write_text(json.dumps({'custom_protected_paths':['D:/private'],
                'confirmed_rebuildable_database_roots':['D:/private/test-db']}),encoding='utf-8')
            merged=load_policy(policy)
            self.assertEqual(merged['custom_protected_paths'],['d:/shared','d:/private'])
            self.assertEqual(merged['confirmed_rebuildable_database_roots'],['d:/private/test-db'])
            self.assertNotEqual(policy_digest(policy),before)

    def test_scan_entry_applies_ignored_local_exclusions(self):
        with tempfile.TemporaryDirectory(prefix='pc_clear_test_') as temp:
            base=Path(temp)
            policy=base/'scan_policy.json'
            policy.write_bytes(POLICY.read_bytes())
            (base/'scan_policy.local.json').write_text(json.dumps({
                'schema_version':1,'scan_excludes':['D:/private-scan-root']}),encoding='utf-8')
            with patch('sys.argv',['scan','--root','D:/','--output',str(base/'out'),
                                   '--policy',str(policy)]), patch('pc_clear.scan.inventory') as run_inventory:
                scan_main()
            exclusions={norm(path) for path in run_inventory.call_args.args[2]}
            self.assertIn('d:/private-scan-root',exclusions)


class EvidenceTests(unittest.TestCase):
    def test_git_tracks_ignored_and_untracked_separately(self):
        with tempfile.TemporaryDirectory(prefix='pc_clear_test_') as temp:
            repo=Path(temp)
            self.assertEqual(repo.resolve().parent,Path(tempfile.gettempdir()).resolve())
            self.assertEqual(git_run(repo,['init','--quiet']).returncode,0)
            (repo/'.gitignore').write_text('cache/\n')
            (repo/'cache').mkdir()
            paths=[repo/'cache/tracked.bin',repo/'cache/ignored.bin',repo/'notes.tmp']
            for p in paths: p.write_bytes(b'x')
            self.assertEqual(git_run(repo,['add','--force','cache/tracked.bin']).returncode,0)
            answer,error=git_filter(repo,[str(p) for p in paths])
            self.assertFalse(error)
            self.assertEqual([answer[str(p)] for p in paths],['tracked','ignored_untracked','untracked_not_ignored'])
            bad,error=git_filter(repo/'missing',[str(paths[0])])
            self.assertEqual(bad[str(paths[0])],'git_unverified')

    def test_inventory_and_live_hardlink_protection(self):
        with tempfile.TemporaryDirectory(prefix='pc_clear_test_') as temp:
            base=Path(temp)
            self.assertEqual(base.resolve().parent,Path(tempfile.gettempdir()).resolve())
            root=base/'input'
            cache=root/'Cache'
            cache.mkdir(parents=True)
            (cache/'index').write_bytes(b'x')
            (cache/'data_0').write_bytes(b'12345')
            (cache/'hard').write_bytes(b'hello world')
            os.link(cache/'hard',root/'other.bin')
            (cache/'keep.py').write_text('source')
            output=root/'reports'
            scan=inventory(root,output)
            self.assertEqual(scan['files'],5)
            self.assertEqual(scan['logical_bytes'],34)
            with sqlite3.connect(output/'inventory.sqlite') as con:
                self.assertEqual(con.execute('select total_bytes,total_files from directories where id=1').fetchone(),(34,5))
            con.close()
            manifest=io.StringIO()
            environment={'active_datadirs':[],'unresolved_database_processes':[]}
            result,groups=analyze_drive(output/'inventory.sqlite',load_policy(POLICY),environment,manifest)
            selected=[json.loads(x) for x in manifest.getvalue().splitlines()]
            self.assertEqual({Path(r['path']).name for r in selected},{'index','data_0'})
            self.assertEqual(sum(g['estimated_bytes'] for g in groups.values()),6)
            self.assertGreater(result['dispositions']['multiple_hardlinks']['bytes'],0)
            with self.assertRaises(FileExistsError): inventory(root,output)


if __name__=='__main__':
    unittest.main()
