"""Read the live Windows physical-disk and partition topology without changing it."""
from __future__ import annotations

from dataclasses import dataclass
import subprocess

from .evidence import powershell_json


TOPOLOGY_QUERY = r'''
$ErrorActionPreference = 'Stop'
Get-Disk | ForEach-Object {
    $disk = $_
    $partitions = @(
        Get-Partition -DiskNumber $disk.Number | ForEach-Object {
            $partition = $_
            $volume = $partition | Get-Volume -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Number = $partition.PartitionNumber
                DriveLetter = if ($partition.DriveLetter) { [string]$partition.DriveLetter } else { '' }
                Size = $partition.Size
                Type = [string]$partition.Type
                FileSystem = if ($volume) { [string]$volume.FileSystem } else { $null }
                Label = if ($volume) { [string]$volume.FileSystemLabel } else { $null }
                VolumeSize = if ($volume) { $volume.Size } else { $null }
                Free = if ($volume) { $volume.SizeRemaining } else { $null }
                Health = if ($volume) { [string]$volume.HealthStatus } else { $null }
            }
        }
    )
    [PSCustomObject]@{
        Number = $disk.Number
        FriendlyName = [string]$disk.FriendlyName
        BusType = [string]$disk.BusType
        Size = $disk.Size
        HealthStatus = [string]$disk.HealthStatus
        OperationalStatus = [string]$disk.OperationalStatus
        Partitions = $partitions
    }
} | ConvertTo-Json -Depth 6 -Compress
'''


@dataclass(frozen=True)
class Partition:
    number: int
    drive_letter: str
    size: int
    partition_type: str
    file_system: str
    label: str
    volume_size: int | None
    free: int | None
    health: str

    @property
    def used(self):
        if self.volume_size is None or self.free is None:
            return None
        return max(0, self.volume_size - self.free)


@dataclass(frozen=True)
class PhysicalDisk:
    number: int
    name: str
    bus_type: str
    size: int
    health: str
    operational_status: str
    partitions: tuple[Partition, ...]


def list_value(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def text(value):
    return str(value or '').replace('\x00', '').strip()


def integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def storage_topology():
    """Return the current physical disks and their partitions; unavailable data is empty."""
    try:
        raw_disks = powershell_json(TOPOLOGY_QUERY)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        return ()
    disks = []
    for raw_disk in raw_disks:
        partitions = []
        for raw_partition in list_value(raw_disk.get('Partitions')):
            partitions.append(Partition(
                number=integer(raw_partition.get('Number'), 0),
                drive_letter=text(raw_partition.get('DriveLetter')).upper(),
                size=integer(raw_partition.get('Size'), 0),
                partition_type=text(raw_partition.get('Type')),
                file_system=text(raw_partition.get('FileSystem')),
                label=text(raw_partition.get('Label')),
                volume_size=integer(raw_partition.get('VolumeSize')),
                free=integer(raw_partition.get('Free')),
                health=text(raw_partition.get('Health')),
            ))
        disks.append(PhysicalDisk(
            number=integer(raw_disk.get('Number'), 0),
            name=text(raw_disk.get('FriendlyName')),
            bus_type=text(raw_disk.get('BusType')),
            size=integer(raw_disk.get('Size'), 0),
            health=text(raw_disk.get('HealthStatus')),
            operational_status=text(raw_disk.get('OperationalStatus')),
            partitions=tuple(partitions),
        ))
    return tuple(sorted(disks, key=lambda disk: disk.number))


def drive_to_disk(disks):
    """Map each mounted drive letter to the physical disk that contains it."""
    return {
        partition.drive_letter: disk
        for disk in disks
        for partition in disk.partitions
        if partition.drive_letter
    }


def partition_title(partition):
    """Give mounted and unmounted partitions a concise, user-facing name."""
    if partition.drive_letter:
        return f'{partition.drive_letter}: {partition.label or "本地磁盘"}'
    labels = {'System': 'EFI 系统分区', 'Reserved': 'Microsoft 保留分区',
              'Recovery': '恢复分区', 'Basic': '基本数据分区'}
    return partition.label or labels.get(partition.partition_type, partition.partition_type or '未命名分区')
