# PC_Clear：Windows 磁盘只读分析

扫描 C、D 盘所有可访问的普通文件，按应用、Git 仓库、文件类型、修改年龄与运行状态生成待选清单。**扫描和分析命令不删除文件，不关闭应用，不修改系统权限。**

最新报告：[完整分析结论](reports/full_20260914_1618/完整分析结论.md)。disk_audit_20260914 中的报告是历史快照，旧估算不要与本轮相加。

## 使用

需要 Python 3.12+、Git 和 Windows PowerShell。当前实现使用标准库，无需额外安装第三方库。

从项目根目录运行，为每次扫描选择新的输出目录：

    $auditPython = 'C:\Users\MSI_NB\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    $auditRun = 'D:\I\py\PC_Clear\reports\my-new-scan'
    & $auditPython -m pc_clear.scan --root 'C:\' --output "$auditRun\C" --exclude 'D:\I\py\PC_Clear\reports'
    & $auditPython -m pc_clear.scan --root 'D:\' --output "$auditRun\D" --exclude 'D:\I\py\PC_Clear\reports'
    & $auditPython -m pc_clear.analyze --run $auditRun
    & $auditPython -m pc_clear.report --run $auditRun

两盘扫描可在不同终端同时执行；分析要等两盘均完成。扫描器拒绝覆盖已有 inventory.sqlite。分析/报告命令刷新指定目录中的派生结果，不会重新扫描原盘；重新观察全部文件时必须建立新的扫描目录。

如果运行环境无法读取当前用户目录，应在拥有读取权限的当前用户环境运行。本工具不修改 ACL、夺取所有权或绕过系统保护。

## 文件

- pc_clear/scan.py：SQLite 全量文件/目录索引，无大目录阈值，保留全部扫描缺口。
- pc_clear/rules.py：用途、文件类型、配置与用户数据保护规则。
- pc_clear/evidence.py：只读 Git 查询、安装/运行信息与压缩/稀疏大小检查。
- pc_clear/analyze.py：应用归属、年龄统计、Git 复核、硬链接排除与逐文件候选清单。
- pc_clear/report.py：汇总、全部选项、应用占用、旧版本/旧文件、缓存目录与扫描缺口报告。
- tests/test_audit.py：Git 跟踪/忽略区分、混合数据保护、年龄规则、扫描汇总与硬链接保护。

inventory.sqlite 包含 files、directories、gaps、metadata 表。candidate_files.jsonl 是最终逐文件候选；cleanup_plan.json 的编号通过 group_key 对应清单。计划不是执行脚本，不允许按目录列表直接整删。

## 忽略文件

[.gitignore](.gitignore) 只控制本项目版本管理：

- 忽略 reports 下的私有本机路径清单、数据库、报告和日志。
- 忽略历史审计目录下的 JSON、Markdown、日志等生成产物。
- 保留 Python 源码、测试、README 和 scan_policy.json。
- 忽略 Python 缓存、虚拟环境、工具缓存、构建产物和本机凭据配置。

[scan_policy.json](scan_policy.json) 单独控制分析：

- protected_paths / custom_protected_paths：绝对保护目录，支持 %USERPROFILE% 等环境变量。
- protected_components：备份、Git、安装环境、用户会话等目录名。
- protected_extensions / protected_names：源码、配置、凭据、文档、模型和用户状态文件。
- custom_protected_globs：完整路径 glob；不区分大小写，分隔符可用 /。采用 fnmatch 语义，不支持 Git 的反向忽略语法。
- scan_excludes：真正不遍历的目录，默认空；显式跳过写入 gaps。保护目录仍统计占用。
- temporary_min_days / log_min_days / aged_review_days：临时文件候选、日志候选和旧文件复核阈值。
- confirmed_rebuildable_database_roots：用户确认可重建的测试数据范围，不是删除授权。

Git 查询仅为单次命令指定 safe.directory，不修改全局 Git 配置。仓库候选必须同时未跟踪、被忽略；查询失败则保留。Git 忽略规则不能证明文件无用，也不能覆盖保护规则。

## 计量与边界

- 普通文件只读取元数据。识别测试数据库时，可读取 mysqld 明确指定配置中的数据目录设置；不保存完整命令行或配置内容。
- 修改时间不是最后使用时间。旧版本和旧大文件只是核实线索，不因年龄自动进入清理。
- 浏览器 cache 可能是完整资料容器。仅识别内部资源缓存布局，保留 IndexedDB、会话、登录、配置和离线存储。
- 候选重新获取文件信息，排除多硬链接、重解析点、不可读或扫描后变化的文件；压缩/稀疏文件修正大小。估算不等于实际簇释放量。
- 进程未命中路径不能证明应用未使用。用户选择后仍需关闭相关应用并复核文件锁、Git、路径和数据目录；当前没有删除执行器。
- 完整扫描指遍历所有可访问普通目录，不保证读取系统保护内容、链接目标或云占位内容。扫描是动态观察，逻辑大小可能重复计算硬链接。

## 验证

    python -m unittest discover -s tests -v

测试只创建并清理自行生成的隔离临时目录，不清理用户原有文件。
