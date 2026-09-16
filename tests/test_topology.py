"""Verify the Windows physical-disk view independently from scanned file data."""
import subprocess
import unittest
from unittest.mock import patch

from pc_clear.topology import drive_to_disk, storage_topology


class StorageTopologyTests(unittest.TestCase):
    def test_returns_empty_topology_when_windows_query_times_out(self):
        with patch('pc_clear.topology.powershell_json', side_effect=subprocess.TimeoutExpired('powershell', 60)):
            self.assertEqual(storage_topology(), ())

    def test_groups_mounted_and_recovery_partitions_under_one_physical_disk(self):
        raw = [{
            'Number': 0, 'FriendlyName': 'Example NVMe', 'BusType': 'NVMe',
            'Size': 1024, 'HealthStatus': 'Healthy', 'OperationalStatus': 'Online',
            'Partitions': [
                {'Number': 1, 'DriveLetter': '\x00', 'Size': 10, 'Type': 'System',
                 'FileSystem': None, 'Label': None, 'VolumeSize': None, 'Free': None, 'Health': None},
                {'Number': 3, 'DriveLetter': 'C', 'Size': 500, 'Type': 'Basic',
                 'FileSystem': 'NTFS', 'Label': 'Windows', 'VolumeSize': 498, 'Free': 20, 'Health': 'Healthy'},
                {'Number': 4, 'DriveLetter': 'D', 'Size': 500, 'Type': 'Basic',
                 'FileSystem': 'NTFS', 'Label': '', 'VolumeSize': 498, 'Free': 40, 'Health': 'Healthy'},
                {'Number': 5, 'DriveLetter': '', 'Size': 14, 'Type': 'Recovery',
                 'FileSystem': 'NTFS', 'Label': 'WinRE', 'VolumeSize': 14, 'Free': 1, 'Health': 'Healthy'},
            ],
        }]
        with patch('pc_clear.topology.powershell_json', return_value=raw):
            disks = storage_topology()

        self.assertEqual(len(disks), 1)
        disk = disks[0]
        self.assertEqual((disk.number, disk.name, disk.bus_type, disk.size), (0, 'Example NVMe', 'NVMe', 1024))
        self.assertEqual([(item.number, item.drive_letter, item.partition_type) for item in disk.partitions],
                         [(1, '', 'System'), (3, 'C', 'Basic'), (4, 'D', 'Basic'), (5, '', 'Recovery')])
        self.assertEqual(drive_to_disk(disks)['C'], disk)
        self.assertEqual(drive_to_disk(disks)['D'], disk)


if __name__ == '__main__':
    unittest.main()
