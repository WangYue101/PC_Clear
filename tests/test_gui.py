"""Exercise the desktop's analyze-only default and selection invalidation with fixtures."""
import io
import json
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch
import sqlite3

from pc_clear.gui import Application
from pc_clear.scan import write_json


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pc_clear_test_')
        self.base=Path(self.temp.name).resolve()
        self.assertEqual(self.base.parent,Path(tempfile.gettempdir()).resolve())
        self.root=tk.Tk()
        self.root.withdraw()
        self.reports_patch=patch('pc_clear.gui.REPORTS',self.base)
        self.reports_patch.start()
        self.app=Application(self.root)

    def tearDown(self):
        self.reports_patch.stop()
        for ident in self.root.tk.call('after','info'):
            self.root.after_cancel(ident)
        self.root.destroy()
        self.assertEqual(self.base.parent,Path(tempfile.gettempdir()).resolve())
        self.temp.cleanup()

    def wait_done(self):
        deadline=time.monotonic()+10
        while self.app.busy and time.monotonic()<deadline:
            self.root.update()
            time.sleep(.01)
        self.assertFalse(self.app.busy,'UI did not finish the operation')

    def test_default_has_no_selection_and_personal_options_are_hidden(self):
        self.assertFalse(self.app.selected)
        self.assertFalse(self.app.personal.get())
        self.assertEqual(str(self.app.execute_button.cget('state')),'disabled')
        group={'id':'F001','group_key':'C|QQ|chat_media','app':'QQ','drive':'C','category':'chat_media',
               'risk':'personal','estimated_bytes':1024,'files':1,'scopes':{}}
        self.app.plan={'schema_version':2,'groups':[group]}
        self.app.refresh()
        self.assertFalse(self.app.choice_tree.get_children())
        self.app.personal_button.invoke()
        self.assertEqual(self.app.choice_tree.get_children(),('F001',))
        self.assertFalse(self.app.selected)
        self.app.toggle('F001')
        self.assertEqual(self.app.selected,{'F001'})
        self.app.personal_button.invoke()
        self.assertFalse(self.app.selected)
        self.assertEqual(str(self.app.execute_button.cget('state')),'disabled')

    def test_background_work_locks_personal_selection(self):
        import threading
        release=threading.Event()
        self.app.personal_button.invoke()
        try:
            self.app.worker(lambda:release.wait(5),lambda result:None)
            self.assertEqual(str(self.app.personal_button.cget('state')),'disabled')
            self.app.personal_button.invoke()
            self.assertTrue(self.app.personal.get())
        finally:
            release.set()
            self.wait_done()
        self.assertEqual(str(self.app.personal_button.cget('state')),'normal')

    def test_switching_drive_resets_browse_path(self):
        self.app.drive.set('D')
        self.app.drive_combo.event_generate('<<ComboboxSelected>>')
        self.root.update()
        self.assertEqual(self.app.folder.get(),'D:\\')

    def test_folder_search_runs_in_background(self):
        import threading
        started=threading.Event()
        release=threading.Event()
        self.app.run=self.base
        self.app.plan={'schema_version':2,'groups':[]}
        self.app.data={d:{'scan':{'files':1,'logical_bytes':1,'volume_after':{}},
                          'applications':{},'storage_groups':[]} for d in 'CD'}
        def delayed_query(*args):
            started.set()
            release.wait(5)
            return []
        with patch.object(self.app,'query_folder_matches',side_effect=delayed_query,create=True):
            self.app.search.set('Users')
            self.app.search_overview()
            self.assertTrue(started.wait(1))
            self.assertTrue(self.app.busy)
            self.root.update()
            release.set()
            self.wait_done()
        self.assertEqual(self.app.active_query,'users')

    def test_load_existing_snapshot_keeps_analysis_mode(self):
        groups=[{'id':'F001','group_key':'C|QQ|cache','app':'QQ','drive':'C','category':'cache','risk':'rebuild',
                 'estimated_bytes':50,'files':2,'scopes':{}},
                {'id':'F002','group_key':'D|QQ|cache','app':'QQ','drive':'D','category':'cache','risk':'rebuild',
                 'estimated_bytes':25,'files':1,'scopes':{}}]
        write_json(self.base/'cleanup_plan.json',{'schema_version':2,'groups':groups,'approved':False})
        for d in 'CD':
            (self.base/d).mkdir()
            write_json(self.base/d/'analysis.json',{'scan':{'files':17,'logical_bytes':300,'finished_at':'test snapshot',
                'volume_after':{'total':1000,'used':600,'free':400}},
                'applications':{'QQ':{'logical_bytes':300,'files':17,'candidate_bytes':0}},'storage_groups':[
                {'app':'QQ','label':'聊天记录数据库','kind':'chat_database','scope':'D:/test/chat',
                 'logical_bytes':100,'files':1,'action':'保留'}]})
            con=sqlite3.connect(self.base/d/'inventory.sqlite')
            try:
                con.execute('CREATE TABLE directories(id INTEGER PRIMARY KEY,parent INTEGER,path TEXT,total_bytes INTEGER,total_files INTEGER)')
                con.execute('INSERT INTO directories VALUES(1,NULL,?,?,?)',(d+':\\',300,17))
                con.execute('INSERT INTO directories VALUES(2,1,?,?,?)',(d+':\\Users',250,12))
                con.commit()
            finally:
                con.close()
        self.app.load(self.base)
        self.wait_done()
        roots=self.app.usage_tree.get_children()
        self.assertEqual(len(roots),1)
        self.assertEqual(self.app.usage_tree.item(roots[0],'text'),'C + D 盘汇总')
        self.assertEqual(self.app.usage_tree.item(roots[0],'values')[:4],('汇总','1.17 KiB','75 B','34'))
        drives=self.app.usage_tree.get_children(roots[0])
        self.assertEqual([self.app.usage_tree.item(x,'text') for x in drives],['C 盘','D 盘'])
        for drive_node in drives:
            sections=self.app.usage_tree.get_children(drive_node)
            self.assertEqual([self.app.usage_tree.item(x,'text') for x in sections],['按应用','按文件夹'])
            app_section,folder_section=sections
            self.app.expand_overview(app_section)
            app_node=self.app.usage_tree.get_children(app_section)[0]
            self.assertEqual(self.app.usage_tree.item(app_node,'text'),'QQ')
            self.app.expand_overview(app_node)
            detail_node=self.app.usage_tree.get_children(app_node)[0]
            self.assertIn('聊天记录数据库',self.app.usage_tree.item(detail_node,'text'))
            self.app.expand_overview(folder_section)
            self.assertEqual(self.app.usage_tree.item(self.app.usage_tree.get_children(folder_section)[0],'text'),'Users')
        self.assertFalse(self.app.selected)
        self.assertIsNone(self.app.preview)
        self.assertIn('test snapshot',self.app.status.get())


if __name__=='__main__':
    unittest.main()
