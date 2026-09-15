# PC_Clear：Windows 磁盘分析与可选清理

扫描 C、D 盘所有可访问的普通文件，按应用、目录布局、Git 仓库、文件类型、修改年龄与运行状态分析占用。**默认只分析；所有清理项默认未选。** 在界面中选择、预览并明确确认后，才逐文件永久清理。不自动关闭用户应用、不修改系统权限。

最新扫描：[完整分析结论](reports/full_20260915_enhanced/完整分析结论.md)、[智能占用分析](reports/full_20260915_enhanced/智能占用分析.md)。2026-09-15 扫描了 3,832,248 个文件；历史快照不能叠加作为可释放量。

## 使用

需要 Windows、Python 3.12+（包含 Tkinter）、Git 和 Windows PowerShell。当前实现使用标准库，无需额外安装第三方库。

本机已配置 Python 3.13.5 项目虚拟环境：

- 解释器：D:\I\py\PC_Clear\.venv\Scripts\python.exe
- PyCharm 解释器名称：Python 3.13 (PC_Clear)
- 基础 Python：本机 Python313 安装目录；虚拟环境不继承全局第三方包。
- [.python-version](.python-version) 指定 3.13；[requirements.txt](requirements.txt) 记录当前没有第三方依赖。

命令行无需激活虚拟环境，可直接检查或运行：

    .\.venv\Scripts\python.exe main.py --dry-run
    .\.venv\Scripts\python.exe main.py
    .\.venv\Scripts\python.exe main.py --mode full

### 在 PyCharm 直接运行

1. 用 PyCharm 打开本项目目录；本机的项目解释器已配置为 Python 3.13 (PC_Clear)。如果配置时 PyCharm 已经打开，请重启 PyCharm 加载新解释器和项目设置。
2. 选择运行配置“PC_Clear - 分析与清理界面”，或打开根目录 [main.py](main.py)，右键选择 Run 'main'；不需要填写运行参数。
3. 窗口自动载入最近的已有分析，不会自动扫描或清理。点击“完整扫描分析”生成新快照；“重新分析当前清单”复用旧索引，应用新的分析规则。

另有“PC_Clear - 完整扫描”（命令行完整流程）、“PC_Clear - 环境检查”和“PC_Clear - 测试”。配置均指向项目 .venv，固定项目工作目录并使用 UTF-8。配置保存在 [.run](.run)；本机 .idea 和 .venv 继续由 Git 忽略，reports 和 .venv 已从 PyCharm 项目索引中排除。

如果在另一台机器打开项目，请先创建自己的 .venv；现有虚拟环境应选择其 Scripts/python.exe 作为解释器，参见 [PyCharm 官方说明](https://www.jetbrains.com/help/pycharm/configuring-python-interpreter.html)。

入口使用当前解释器。每次完整扫描创建 reports/full_时间戳 目录，不覆盖旧索引；扫描步骤不执行删除。即使 PyCharm 的工作目录在其他位置，入口也会自动定位项目和规则文件。

### 在哪里选择清理

1. **全部占用**：树根先汇总 C+D 的容量、已用、可用、扫描逻辑文件和候选上限；展开后分为 C、D 两盘，每盘再分“按应用”和“按文件夹”。应用可展开到用途/分析路径，文件夹按需逐层加载；双击文件夹进入完整目录浏览。保护内容仍在统计中。
2. **目录与文件**：按盘和路径逐层浏览，也可全盘搜索文件名。单页按大小显示前 1,000 条，完整文件记录均在 SQLite 中。
3. **清理选项**：点击第一列勾选需要处理的组。双击其他列查看精确范围。聊天媒体默认隐藏，只有勾选“显示个人聊天媒体选项”才出现；显示不代表选择。
4. 点击 **预览已选文件**。程序复核 Git、当前规则、文件身份和运行进程，列出可执行文件、跳过原因、估算空间及完整逐文件预览文件。预览不会删除文件。
5. 阅读预览、退出相关应用，在 **执行预览** 页勾选已退出应用，并输入本次预览的确认词，再点击 **永久删除已预览文件**。确认对话框默认选择“否”。

清理是永久删除，不经过回收站。聊天媒体可能失去唯一的原图、视频或语音；聊天数据库、文档附件、配置与会话仍保留。数据库实例使用应用/数据库管理方式整体处理，此入口不部分删除数据库数据文件。

每次预览有效 15 分钟且只能执行一次。改变选择或保护规则、重新分析都会使预览失效。未选择、未预览、未正确确认时均无法执行。可停止扫描或清理；停止清理不会撤销已经删除的文件。执行后查看 cleanup_*.json / *.jsonl，重新扫描更新占用。

### 分析如何判断

- Codex：区分会话/归档、状态数据库、运行环境与插件、目录缓存、浏览器资源缓存；`.codex-tmp`、`.codex-build`、`.scratch`、`.local-work` 等混合任务目录进一步结合 Git 和二进制格式。散列命名的已知目录缓存 JSON 是显式例外，普通 JSON 配置仍保留。
- 微信 / QQ：识别新旧数据目录和账户布局；即使目录改名或迁移，也可通过 `db_storage + msg`、`nt_db + nt_data` 等结构发现，区分数据库、接收文件、媒体、缩略图与状态。不读取、解密或上传聊天内容。
- 其他占用：全量统计压缩/安装包、数据库、模型、虚拟磁盘、源码、文档和音视频；最大文件不设年龄要求。旧文件与未知缓存给出复核线索，不因名称或年龄直接判为垃圾。

这里的“智能分析”是可解释的本地规则与实际证据组合，不依赖云端模型。未知应用格式不会被假定为可删除，所有可访问文件仍可在索引中查到。

可选运行参数：

- --dry-run：只检查环境并显示步骤，适合首次配置检查。
- --mode gui：图形界面，亦为不带参数时的默认行为；可搭配 --run 指定已有报告。
- --mode full：命令行完整扫描与分析，不弹出清理确认、不删除文件。
- --mode analyze --run reports/已有目录：复用已有 C、D 盘清单，重新分析和生成报告。
- --mode report --run reports/已有目录：只重新生成已有分析的报告。

### 分步运行

从项目根目录运行，为每次扫描选择新的输出目录：

    $auditPython = 'D:\I\py\PC_Clear\.venv\Scripts\python.exe'
    $auditRun = 'D:\I\py\PC_Clear\reports\my-new-scan'
    & $auditPython -m pc_clear.scan --root 'C:\' --output "$auditRun\C" --exclude 'D:\I\py\PC_Clear\reports'
    & $auditPython -m pc_clear.scan --root 'D:\' --output "$auditRun\D" --exclude 'D:\I\py\PC_Clear\reports'
    & $auditPython -m pc_clear.analyze --run $auditRun
    & $auditPython -m pc_clear.report --run $auditRun

两盘扫描可在不同终端同时执行；分析要等两盘均完成。扫描器拒绝覆盖已有 inventory.sqlite。分析/报告命令刷新指定目录中的派生结果，不会重新扫描原盘；重新观察全部文件时必须建立新的扫描目录。

如果运行环境无法读取当前用户目录，应在拥有读取权限的当前用户环境运行。本工具不修改 ACL、夺取所有权或绕过系统保护。

## 文件

- main.py：PyCharm 可直接运行的主入口，自动串联完整流程。
- pc_clear/scan.py：SQLite 全量文件/目录索引，无大目录阈值，保留全部扫描缺口。
- pc_clear/rules.py：用途、文件类型、配置与用户数据保护规则。
- pc_clear/evidence.py：只读 Git 查询、安装/运行信息与压缩/稀疏大小检查。
- pc_clear/analyze.py：应用归属、年龄统计、Git 复核、硬链接排除与逐文件候选清单。
- pc_clear/report.py：汇总、全部选项、应用占用、旧版本/旧文件、缓存目录与扫描缺口报告。
- pc_clear/storage.py：聊天数据、Codex 和混合任务目录的用途明细。
- pc_clear/gui.py：扫描、占用浏览、候选选择、预览和清理界面。
- pc_clear/cleanup.py：绑定清单与规则的预览、确认、实时核验和逐文件日志。
- pc_clear/windows_files.py：固定父目录、独占打开普通文件并通过同一 Windows 句柄删除；不递归删目录。
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
- chat_media_min_days：个人聊天媒体选项的最小未修改天数（默认 30 天），不意味着数据已经无用。
- confirmed_rebuildable_database_roots：用户确认可重建的测试数据范围，不是删除授权。

Git 查询仅为单次命令指定 safe.directory，不修改全局 Git 配置。仓库候选必须同时未跟踪、被忽略；查询失败则保留。Git 忽略规则不能证明文件无用，也不能覆盖保护规则。

## 计量与边界

- 普通文件只读取元数据。识别测试数据库时，可读取 mysqld 明确指定配置中的数据目录设置；不保存完整命令行或配置内容。
- 修改时间不是最后使用时间。旧版本和旧大文件只是核实线索，不因年龄自动进入清理。
- 浏览器 cache 可能是完整资料容器。仅识别内部资源缓存布局，保留 IndexedDB、会话、登录、配置和离线存储。
- 候选重新获取文件信息，排除多硬链接、重解析点、不可读或扫描后变化的文件；压缩/稀疏文件修正大小。估算不等于实际簇释放量。
- 进程未命中路径不能证明应用未使用。执行前须退出相关应用；已识别的运行应用会阻止对应文件，独占文件句柄失败则跳过。未知应用的使用状态不能仅靠进程名推断。
- Git 在预览和执行批次前重新核验；多程序并发仍非静态快照，应先结束构建和任务。逐文件绑定卷/文件标识、创建时间、修改时间和大小，跳过被替换、变化、链接或锁定的文件。对路径父目录的句柄防止执行期间被换成目录链接。
- 完整扫描指遍历所有可访问普通目录，不保证读取系统保护内容、链接目标或云占位内容。扫描是动态观察，逻辑大小可能重复计算硬链接。

## 验证

    .\.venv\Scripts\python.exe -m unittest discover -s tests -v

测试只创建并清理自行生成的隔离临时目录，不清理用户原有文件。

句柄删除实现依据 [Microsoft SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)；Windows 创建时间使用明确的 birthtime 字段，参见 [Python os.stat 文档](https://docs.python.org/3.13/library/os.html#os.stat_result)。
