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

from pc_clear.gui import Application, latest_scan_run
from pc_clear.scan import write_json
from pc_clear.topology import Partition, PhysicalDisk


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pc_clear_test_')
        self.base=Path(self.temp.name).resolve()
        self.assertEqual(self.base.parent,Path(tempfile.gettempdir()).resolve())
        self.root=tk.Tk()
        self.root.withdraw()
        self.topology=(PhysicalDisk(0,'Example NVMe','NVMe',2048,'Healthy','Online',(
            Partition(1,'',10,'System','','',None,None,''),
            Partition(3,'C',1000,'Basic','NTFS','Windows',1000,400,'Healthy'),
            Partition(4,'D',1000,'Basic','NTFS','',1000,400,'Healthy'),
            Partition(5,'',38,'Recovery','NTFS','WinRE tools',38,2,'Healthy'),
        )),)
        self.reports_patch=patch('pc_clear.gui.REPORTS',self.base)
        self.reports_patch.start()
        self.topology_patch=patch('pc_clear.gui.storage_topology',return_value=self.topology)
        self.topology_patch.start()
        self.app=Application(self.root)
        self.wait_done()

    def tearDown(self):
        self.topology_patch.stop()
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

    def test_automatic_load_ignores_non_scan_preview_reports(self):
        preview=self.base/'ui_preview_fixture'
        preview.mkdir()
        write_json(preview/'cleanup_plan.json',{'schema_version':2,'groups':[]})
        actual=self.base/'full_20260916_120000'
        for drive in 'CD':
            (actual/drive).mkdir(parents=True)
            write_json(actual/drive/'analysis.json',{'scan':{}})
            (actual/drive/'inventory.sqlite').touch()
        write_json(actual/'cleanup_plan.json',{'schema_version':2,'groups':[]})

        self.assertEqual(latest_scan_run(self.base),actual)

    def test_initial_view_reads_live_topology_without_a_scan_report(self):
        self.assertEqual(self.app.topology,self.topology)
        self.assertIsNotNone(self.app.topology_sampled_at)
        self.assertIn('读取于',self.app.topology_title.get())

    def test_refresh_live_topology_replaces_capacity_after_a_cleanup(self):
        updated=(PhysicalDisk(0,'Example NVMe','NVMe',2048,'Healthy','Online',(
            Partition(3,'C',1000,'Basic','NTFS','Windows',1000,700,'Healthy'),
            Partition(4,'D',1000,'Basic','NTFS','',1000,450,'Healthy'),
        )),)
        with patch('pc_clear.gui.storage_topology',return_value=updated):
            self.app.refresh_live_topology()
            self.wait_done()
        self.assertEqual(self.app.topology,updated)
        disk=self.app.topology_tree.get_children()[0]
        c_partition=self.app.topology_tree.get_children(disk)[0]
        self.assertEqual(self.app.topology_tree.item(c_partition,'values')[3],'700 B')

    def test_failed_live_topology_marks_scan_snapshot_as_non_current(self):
        self.app.plan={'schema_version':2,'groups':[]}
        self.app.data={d:{'scan':{'files':1,'logical_bytes':1,'finished_at':'snapshot time',
            'volume_after':{'total':1000,'used':600,'free':400}},'applications':{},'storage_groups':[]} for d in 'CD'}
        with patch('pc_clear.gui.storage_topology',return_value=()):
            self.app.refresh_live_topology()
            self.wait_done()

        self.assertTrue(self.app.topology_read_failed)
        self.assertIn('读取失败',self.app.topology_title.get())
        self.assertEqual(self.app.topology_tree.heading('used')['text'],'扫描时已用')
        root=self.app.topology_tree.get_children()[0]
        self.assertEqual(self.app.topology_tree.item(root,'text'),'实时容量读取失败')
        c_snapshot=self.app.topology_tree.get_children(root)[0]
        self.assertEqual(self.app.topology_tree.item(c_snapshot,'values')[:4],
                         ('扫描快照','1000 B','600 B','400 B'))
        self.assertIn('读取失败',self.app.status.get())

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
        root=self.app.choice_tree.get_children()[0]
        self.assertEqual(self.app.choice_tree.item(root,'text'),'聊天媒体需确认')
        drive=self.app.choice_tree.get_children(root)[0]
        self.assertEqual(self.app.choice_tree.get_children(drive),('F001',))
        self.assertFalse(self.app.selected)
        self.app.toggle('F001')
        self.assertEqual(self.app.selected,{'F001'})
        self.app.personal_button.invoke()
        self.assertFalse(self.app.selected)
        self.assertEqual(str(self.app.execute_button.cget('state')),'disabled')

    def test_cleanup_options_are_grouped_by_safety_before_a_file_can_be_selected(self):
        groups=[
            {'id':'F001','group_key':'C|Codex|cache','app':'Codex','drive':'C','category':'cache',
             'risk':'rebuild','estimated_bytes':2048,'files':2,
             'scopes':{'C:\\CodexCache':{'files':2,'estimated_bytes':2048}}},
            {'id':'F002','group_key':'D|MySQL|test_database','app':'MySQL','drive':'D','category':'test_database',
             'risk':'rebuild','estimated_bytes':4096,'files':1,'scopes':{}},
            {'id':'F003','group_key':'C|QQ|chat_media','app':'QQ','drive':'C','category':'chat_media',
             'risk':'personal','estimated_bytes':1024,'files':1,'scopes':{}},
        ]
        self.app.plan={'schema_version':2,'groups':groups}
        self.app.refresh()

        roots=self.app.choice_tree.get_children()
        self.assertEqual([self.app.choice_tree.item(root,'text') for root in roots],
                         ['可清理内容','需要应用内处理'])
        rebuild=self.app.choice_tree.get_children(roots[0])[0]
        database=self.app.choice_tree.get_children(roots[1])[0]
        self.assertEqual(self.app.choice_tree.get_children(rebuild),('F001',))
        self.assertEqual(self.app.choice_tree.get_children(database),('F002',))
        self.assertFalse(self.app.selected)

        self.app.personal_button.invoke()
        roots=self.app.choice_tree.get_children()
        self.assertEqual(self.app.choice_tree.item(roots[-1],'text'),'聊天媒体需确认')
        personal=self.app.choice_tree.get_children(roots[-1])[0]
        self.assertEqual(self.app.choice_tree.get_children(personal),('F003',))
        self.app.toggle(roots[0])
        self.assertFalse(self.app.selected)

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

        disk=self.app.topology_tree.get_children()[0]
        self.assertIn('磁盘 0',self.app.topology_tree.item(disk,'text'))
        partitions=self.app.topology_tree.get_children(disk)
        self.assertEqual([self.app.topology_tree.item(item,'text') for item in partitions],
                         ['EFI 系统分区','C: Windows','D: 本地磁盘','WinRE tools'])
        self.assertEqual(self.app.topology_tree.item(partitions[1],'values')[:4],
                         ('已扫描分区','1000 B','600 B','400 B'))

        roots=self.app.app_tree.get_children()
        self.assertEqual(len(roots),1)
        self.assertEqual(self.app.app_tree.item(roots[0],'text'),'应用智能分析')
        self.assertEqual(self.app.app_tree.item(roots[0],'values')[:4],('扫描范围','600 B','75 B','34'))
        physical=self.app.app_tree.get_children(roots[0])[0]
        self.assertIn('磁盘 0',self.app.app_tree.item(physical,'text'))
        drives=self.app.app_tree.get_children(physical)
        self.assertEqual([self.app.app_tree.item(x,'text') for x in drives],['C: Windows','D: 本地磁盘'])
        for drive_node in drives:
            app_node=self.app.app_tree.get_children(drive_node)[0]
            self.assertEqual(self.app.app_tree.item(app_node,'text'),'QQ')
            self.app.expand_overview(app_node)
            detail_node=self.app.app_tree.get_children(app_node)[0]
            self.assertIn('聊天记录数据库',self.app.app_tree.item(detail_node,'text'))
        folder_roots=self.app.folder_tree.get_children()
        self.assertEqual(len(folder_roots),1)
        folder_physical=self.app.folder_tree.get_children(folder_roots[0])[0]
        folder_drives=self.app.folder_tree.get_children(folder_physical)
        self.assertEqual([self.app.folder_tree.item(x,'text') for x in folder_drives],['C: Windows','D: 本地磁盘'])
        for drive_node in folder_drives:
            self.assertEqual(self.app.folder_tree.item(self.app.folder_tree.get_children(drive_node)[0],'text'),'Users')
        self.app.app_tree.selection_set(detail_node)
        self.app.app_tree.focus(detail_node)
        self.app.app_tree.event_generate('<<TreeviewSelect>>')
        self.root.update()
        self.assertIn('保留',self.app.overview_detail.get())
        self.assertFalse(self.app.selected)
        self.assertIsNone(self.app.preview)
        self.assertIn('test snapshot',self.app.status.get())

    def test_physical_disk_precedes_partitions_in_both_analysis_trees(self):
        self.app.run=self.base
        self.app.plan={'schema_version':2,'groups':[]}
        self.app.data={d:{'scan':{'files':17,'logical_bytes':300,'finished_at':'test snapshot',
            'volume_after':{'total':1000,'used':600,'free':400}},
            'applications':{'QQ':{'logical_bytes':300,'files':17,'candidate_bytes':0}},
            'storage_groups':[]} for d in 'CD'}
        self.app.topology=(PhysicalDisk(0,'Example NVMe','NVMe',2048,'Healthy','Online',(
            Partition(1,'',10,'System','','',None,None,''),
            Partition(3,'C',1000,'Basic','NTFS','Windows',1000,400,'Healthy'),
            Partition(4,'D',1000,'Basic','NTFS','',1000,400,'Healthy'),
            Partition(5,'',38,'Recovery','NTFS','WinRE tools',38,2,'Healthy'),
        )),)
        for drive in 'CD':
            (self.base/drive).mkdir()
            con=sqlite3.connect(self.base/drive/'inventory.sqlite')
            try:
                con.execute('CREATE TABLE directories(id INTEGER PRIMARY KEY,parent INTEGER,path TEXT,total_bytes INTEGER,total_files INTEGER)')
                con.execute('INSERT INTO directories VALUES(1,NULL,?,?,?)',(drive+':\\',300,17))
                con.execute('INSERT INTO directories VALUES(2,1,?,?,?)',(drive+':\\Users',250,12))
                con.commit()
            finally:
                con.close()
        self.app.refresh()

        disk=self.app.topology_tree.get_children()[0]
        self.assertIn('磁盘 0',self.app.topology_tree.item(disk,'text'))
        self.assertEqual([self.app.topology_tree.item(item,'text') for item in self.app.topology_tree.get_children(disk)],
                         ['EFI 系统分区','C: Windows','D: 本地磁盘','WinRE tools'])
        app_root=self.app.app_tree.get_children()[0]
        app_disk=self.app.app_tree.get_children(app_root)[0]
        self.assertIn('磁盘 0',self.app.app_tree.item(app_disk,'text'))
        self.assertEqual([self.app.app_tree.item(item,'text') for item in self.app.app_tree.get_children(app_disk)],
                         ['C: Windows','D: 本地磁盘'])
        folder_root=self.app.folder_tree.get_children()[0]
        folder_disk=self.app.folder_tree.get_children(folder_root)[0]
        self.assertIn('磁盘 0',self.app.folder_tree.item(folder_disk,'text'))
        self.assertEqual([self.app.folder_tree.item(item,'text') for item in self.app.folder_tree.get_children(folder_disk)],
                         ['C: Windows','D: 本地磁盘'])

    def test_unscanned_data_partition_is_not_labeled_as_a_system_partition(self):
        self.app.run=self.base
        self.app.plan={'schema_version':2,'groups':[]}
        self.app.data={d:{'scan':{'files':1,'logical_bytes':1,'finished_at':'test snapshot',
            'volume_after':{'total':1000,'used':600,'free':400}},'applications':{},'storage_groups':[]} for d in 'CD'}
        self.app.topology=(PhysicalDisk(0,'Example NVMe','NVMe',3100,'Healthy','Online',(
            Partition(3,'C',1000,'Basic','NTFS','Windows',1000,400,'Healthy'),
            Partition(4,'D',1000,'Basic','NTFS','',1000,400,'Healthy'),
            Partition(5,'E',1000,'Basic','NTFS','Archive',1000,300,'Healthy'),
        )),)
        self.app.refresh()

        disk=self.app.topology_tree.get_children()[0]
        e_partition=self.app.topology_tree.get_children(disk)[2]
        self.assertEqual(self.app.topology_tree.item(e_partition,'text'),'E: Archive')
        self.assertEqual(self.app.topology_tree.item(e_partition,'values')[0],'未扫描分区')

    def test_missing_folder_index_is_reported_without_stopping_the_ui(self):
        write_json(self.base/'cleanup_plan.json',{'schema_version':2,'groups':[],'approved':False})
        for drive in 'CD':
            (self.base/drive).mkdir()
            write_json(self.base/drive/'analysis.json',{'scan':{'files':1,'logical_bytes':1,
                'finished_at':'incomplete snapshot','volume_after':{'total':10,'used':5,'free':5}},
                'applications':{},'storage_groups':[]})
        self.app.load(self.base)
        self.wait_done()
        root=self.app.folder_tree.get_children()[0]
        disk=self.app.folder_tree.get_children(root)[0]
        for drive_node in self.app.folder_tree.get_children(disk):
            child=self.app.folder_tree.get_children(drive_node)[0]
            self.assertEqual(self.app.folder_tree.item(child,'text'),'文件夹索引不可用')
        self.assertTrue(self.root.tk.call('after','info'))


if __name__=='__main__':
    unittest.main()
