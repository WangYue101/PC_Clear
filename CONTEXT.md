# PC_Clear

PC_Clear explains Windows storage use and offers deliberately opt-in cleanup of files that can be safely re-created. It distinguishes capacity observed from Windows from the content indexed during a scan.

## Storage topology

**Physical disk**:
A Windows storage device with a hardware capacity and one or more partitions.
_Avoid_: Disk total, C+D disk

**Partition**:
A slice of a physical disk. It may be a mounted volume such as C: or D:, or an unmounted system, reserved, or recovery partition.
_Avoid_: Physical disk, drive

**Scan target**:
A mounted partition whose ordinary files are indexed by a PC_Clear scan. C: and D: are the current scan targets; system and recovery partitions are capacity-only.
_Avoid_: All partitions

**Live capacity**:
The current Windows-reported size, used space, and free space of a physical disk or mounted partition.
_Avoid_: Scan size

**Scan snapshot**:
The point-in-time inventory of accessible files and their logical size. Its free-space reading can differ from live capacity after the scan finishes.
_Avoid_: Current capacity

## Analysis and cleanup

**Application analysis**:
An attribution of indexed files to an installed application, a detected data layout, or a Git project. It explains use and candidate status.
_Avoid_: Folder analysis

**Folder analysis**:
A navigable hierarchy of real directories and their inclusive logical size. Parent and child sizes are not additive.
_Avoid_: Application analysis

**Cleanup candidate**:
A specific, revalidated set of files that appears re-creatable under current rules. It is not deletion authorization.
_Avoid_: Junk file, safe to delete

**Protected data**:
Files that remain visible in analysis but are excluded from cleanup candidates, including source, configuration, user state, chat databases, document attachments, and system-managed storage.
_Avoid_: Hidden data
