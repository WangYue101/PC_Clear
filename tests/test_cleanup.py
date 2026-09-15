import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from pc_clear.analyze import analyze_drive
from pc_clear.cleanup import CleanupSession, digest
from pc_clear.evidence import git_run
from pc_clear.rules import load_policy, policy_digest
from pc_clear.scan import inventory, write_json
from pc_clear.storage import directory_storage, discover_chat_roots, file_storage
from pc_clear.windows_files import delete_verified_file, identity

POLICY = Path(__file__).resolve().parents[1] / 'scan_policy.json'


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pc_clear_test_')
        self.base = Path(self.temp.name).resolve()
        self.assertEqual(self.base.parent, Path(tempfile.gettempdir()).resolve())
        self.root = self.base / 'input'
        self.run = self.base / 'reports'
        self.root.mkdir()
        self.run.mkdir()
        self.process_patch = patch('pc_clear.cleanup.current_processes', return_value=[])
        self.process_patch.start()

    def tearDown(self):
        self.process_patch.stop()
        self.assertEqual(self.base.parent, Path(tempfile.gettempdir()).resolve())
        self.assertTrue(self.base.name.startswith('pc_clear_test_'))
        self.temp.cleanup()

    def file(self, relative, content=b'test data', days=120):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        when = time.time() - days * 86400
        os.utime(path, (when, when))
        return path

    def analyze(self, policy=POLICY):
        inventory(self.root, self.run / 'C')
        manifest = io.StringIO()
        analysis, groups = analyze_drive(self.run / 'C/inventory.sqlite', load_policy(policy),
            {'active_datadirs': [], 'unresolved_database_processes': []}, manifest)
        manifest_path = self.run / 'candidate_files.jsonl'
        manifest_path.write_text(manifest.getvalue(), encoding='utf-8')
        plan_groups = [{'id': f'F{i:03d}', 'group_key': key, **group,
                        'risk': 'personal' if group['category'] == 'chat_media' else 'rebuild'}
                       for i, (key, group) in enumerate(groups.items(), 1)]
        write_json(self.run / 'cleanup_plan.json', {'schema_version': 2, 'approved': False,
            'manifest': manifest_path.name, 'manifest_sha256': digest(manifest_path),
            'policy_sha256': policy_digest(policy), 'groups': plan_groups})
        return analysis, plan_groups, [json.loads(line) for line in manifest.getvalue().splitlines()]

    def cached(self):
        self.file('Cache/index')
        path = self.file('Cache/data_0')
        self.file('Cache/keep.py')
        return path

    def test_preview_never_deletes_and_confirmation_is_required(self):
        path = self.cached()
        _, groups, _ = self.analyze()
        session = CleanupSession(self.run, POLICY)
        with self.assertRaises(ValueError): session.prepare([])
        preview = session.prepare([groups[0]['id']])
        self.assertEqual(preview.summary['ready_files'], 2)
        self.assertTrue(path.exists())
        with self.assertRaises(ValueError): session.execute(preview)
        self.assertTrue(path.exists())
        result = session.execute(preview, confirmation=preview.summary['confirmation'], apps_closed=True)
        self.assertEqual(result.get('deleted_files'), 2, Path(result['log']).read_text(encoding='utf-8'))
        self.assertFalse(path.exists())
        self.assertTrue((self.root/'Cache/keep.py').exists())
        with self.assertRaises(ValueError):
            session.execute(preview, confirmation=preview.summary['confirmation'], apps_closed=True)

    def test_local_policy_change_invalidates_cleanup_plan(self):
        policy = self.base / 'scan_policy.json'
        policy.write_bytes(POLICY.read_bytes())
        local = self.base / 'scan_policy.local.json'
        local.write_text(json.dumps({'schema_version': 1, 'custom_protected_paths': []}), encoding='utf-8')
        self.cached()
        _, groups, _ = self.analyze(policy)
        session = CleanupSession(self.run, policy)
        local.write_text(json.dumps({'schema_version': 1,
            'custom_protected_paths': [str(self.root / 'Cache')]}), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '规则已变化'):
            session.prepare([groups[0]['id']])

    def test_changed_and_locked_files_are_skipped_at_execution(self):
        path = self.cached()
        _, groups, _ = self.analyze()
        session = CleanupSession(self.run, POLICY)
        preview = session.prepare([groups[0]['id']])
        path.write_bytes(b'user changed this file after preview')
        with (self.root/'Cache/index').open('rb'):
            result = session.execute(preview, confirmation=preview.summary['confirmation'], apps_closed=True)
        self.assertEqual(result.get('deleted_files', 0), 0)
        self.assertEqual(result['skipped_files'], 2)
        self.assertTrue(path.exists())

    def test_forged_path_or_manifest_is_not_authorization(self):
        self.cached()
        secret = self.file('notes.txt', b'unrelated work')
        _, groups, _ = self.analyze()
        with (self.run/'candidate_files.jsonl').open('a',encoding='utf-8') as handle:
            handle.write('{}\n')
        session = CleanupSession(self.run, POLICY)
        with self.assertRaises(ValueError): session.prepare([groups[0]['id']])
        self.assertTrue(secret.exists())

    def test_git_tracking_after_preview_prevents_deletion(self):
        self.assertEqual(git_run(self.root,['init','--quiet']).returncode,0)
        self.file('.gitignore', b'Cache/\n')
        path = self.cached()
        _, groups, _ = self.analyze()
        session = CleanupSession(self.run, POLICY)
        preview = session.prepare([groups[0]['id']])
        self.assertEqual(git_run(self.root,['add','--force','Cache/data_0']).returncode,0)
        result = session.execute(preview, confirmation=preview.summary['confirmation'], apps_closed=True)
        self.assertTrue(path.exists())
        self.assertEqual(result['skipped_files'],1)

    def test_added_hardlink_after_preview_is_preserved(self):
        path = self.cached()
        _, groups, _ = self.analyze()
        session = CleanupSession(self.run, POLICY)
        preview = session.prepare([groups[0]['id']])
        os.link(path, self.root/'another-link')
        result = session.execute(preview, confirmation=preview.summary['confirmation'], apps_closed=True)
        self.assertTrue(path.exists())
        self.assertEqual(result['skipped_files'],1)

    def test_directory_junction_swap_cannot_redirect_deletion(self):
        import subprocess
        path = self.cached()
        expected = identity(path.stat())
        original = self.root/'original-cache'
        path.parent.rename(original)
        outside = self.base/'outside'
        outside.mkdir()
        victim = outside/'data_0'
        victim.write_bytes(b'keep outside data')
        link = self.root/'Cache'
        command = "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path '" + str(link).replace("'","''") + "' -Target '" + str(outside).replace("'","''") + "' | Out-Null"
        result = subprocess.run(['powershell.exe','-NoProfile','-Command',command],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        try:
            with self.assertRaises((ValueError,OSError)): delete_verified_file(link/'data_0', expected)
            self.assertEqual(victim.read_bytes(),b'keep outside data')
        finally:
            # Remove only the fixture junction entry, never its target contents.
            self.assertEqual(link.parent.resolve(), self.root.resolve())
            os.rmdir(link)

    def test_codex_and_chat_data_visible_but_personal_media_separately_opt_in(self):
        media = self.file('Documents/xwechat_files/account/msg/video/old.mp4')
        self.file('Documents/xwechat_files/account/db_storage/message/message_0.db')
        self.file('Documents/xwechat_files/account/msg/file/contract.pdf')
        self.file('.codex/cache/remote_plugin_catalog/0123456789abcdef.json', b'{}')
        self.file('.codex/sessions/2026/history.jsonl', b'{"conversation":"valuable"}')
        self.file('.codex/plugins/cache/plugin/tool.dll')
        analysis, groups, rows = self.analyze()
        self.assertEqual({r['path'] for r in rows}, {str(media), str(self.root/'.codex/cache/remote_plugin_catalog/0123456789abcdef.json')})
        kinds = {r['kind'] for r in analysis['storage_groups']}
        self.assertTrue({'chat_database','chat_attachment','chat_media','codex_history','codex_runtime','codex_cache'} <= kinds)
        session = CleanupSession(self.run,POLICY)
        choice = next(g['id'] for g in groups if g['category']=='chat_media')
        with self.assertRaises(ValueError): session.prepare([choice])
        preview = session.prepare([choice],personal=True)
        self.assertEqual(preview.summary['ready_files'],1)
        self.assertTrue(media.exists())
        with patch('pc_clear.cleanup.current_processes',return_value=[{'Name':'Weixin.exe','ProcessId':123}]):
            blocked = session.prepare([choice],personal=True)
        self.assertEqual(blocked.summary['ready_files'],0)

    def test_generated_binary_requires_git_and_preserves_source(self):
        self.assertEqual(git_run(self.root,['init','--quiet']).returncode,0)
        self.file('.gitignore',b'.codex-build/\n')
        binary = self.file('.codex-build/output/App.dll')
        tracked = self.file('.codex-build/output/Tracked.dll')
        self.file('.codex-build/source.py')
        self.file('.codex-build/appsettings.json')
        self.file('.scratch/toolchains/jdk/bin/java.exe')
        self.file('.scratch/models/model.bin')
        self.file('.scratch/customer-export/records.dat')
        self.file('.scratch/downloads/tool.exe')
        self.file('.codex-build/unknown.bin')
        self.assertEqual(git_run(self.root,['add','--force','.codex-build/output/Tracked.dll']).returncode,0)
        _, _, rows = self.analyze()
        self.assertEqual({r['path'] for r in rows},{str(binary)})
        self.assertTrue(tracked.exists())

    def test_renamed_chat_root_is_recognized_by_sibling_layout(self):
        self.file('redirected/account/nt_db/msg.db')
        self.file('redirected/account/nt_data/Pic/pic.jpg')
        analysis, groups, rows = self.analyze()
        self.assertTrue(analysis['chat_roots'])
        self.assertEqual(len(rows),1)
        session=CleanupSession(self.run,POLICY)
        preview=session.prepare([groups[0]['id']],personal=True)
        self.assertEqual(preview.summary['ready_files'],1)
        with patch('pc_clear.cleanup.current_processes',return_value=[{'Name':'QQ.exe','ProcessId':123}]):
            blocked=session.prepare([groups[0]['id']],personal=True)
        self.assertEqual(blocked.summary['ready_files'],0)


if __name__ == '__main__':
    unittest.main()
