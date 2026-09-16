"""Keep report wording aligned with the physical-disk UI model."""
import unittest

from pc_clear.report import physical_storage_section
from pc_clear.topology import Partition, PhysicalDisk


class ReportTests(unittest.TestCase):
    def test_physical_storage_section_lists_one_disk_before_its_partitions(self):
        disks=(PhysicalDisk(0,'Example NVMe','NVMe',2048,'Healthy','Online',(
            Partition(1,'',10,'System','','',None,None,''),
            Partition(3,'C',1000,'Basic','NTFS','Windows',1000,400,'Healthy'),
            Partition(4,'D',1000,'Basic','NTFS','',1000,400,'Healthy'),
        )),)

        section='\n'.join(physical_storage_section(disks))

        self.assertIn('当前物理硬盘与分区',section)
        self.assertIn('磁盘 0 · NVMe',section)
        self.assertIn('EFI 系统分区',section)
        self.assertIn('C: Windows',section)
        self.assertIn('D: 本地磁盘',section)
        self.assertIn('本轮已扫描',section)
        self.assertIn('不扫描或清理',section)


if __name__ == '__main__':
    unittest.main()
