"""Generate reviewable reports and an UNAPPROVED plan; never execute cleanup."""
from collections import defaultdict
import datetime as dt
import json
from pathlib import Path
import shutil

from inspect_projects import DB_EXTENSIONS, BUILD_EXTENSIONS, SCRATCH
from scan_disk import save_json

HERE = Path(__file__).resolve().parent
GIB = 1024 ** 3


def read(name):
    return json.loads((HERE / name).read_text(encoding="utf-8-sig"))


def size(value):
    return f"{value / GIB:.2f} GiB"


def table(headers, rows):
    escape = lambda value: str(value).replace("|", "\\|").replace("\n", " ")
    return "\n".join(["| " + " | ".join(map(escape, headers)) + " |",
                      "| " + " | ".join("---" for _ in headers) + " |"] +
                     ["| " + " | ".join(map(escape, row)) + " |" for row in rows])


def main():
    disks = {"C": read("full_access/inventory_C.json"), "D": read("inventory_D.json")}
    project_data = read("project_candidates.json")
    assert project_data["completed"] == project_data["total"], "Project audit is incomplete"
    projects = project_data["items"]
    caches = read("cache_candidates.json")["items"]
    now = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    volumes = {letter: dict(zip(("total", "used", "free"), shutil.disk_usage(letter + ":\\")))
               for letter in disks}
    save_json(HERE / "volumes_latest.json", {"at": now, "volumes": volumes})
    names = {"D1": "已停止且至少 24 小时无改动的测试数据库文件",
             "D2": "Android 编译中间目录中的生成二进制文件",
             "C1": "Gradle 构建及依赖缓存",
             "C2": "JetBrains / Android Studio 索引和缓存",
             "C3": "Edge / VS Code / Cursor 资源、代码及 GPU 缓存",
             "C4": "超过 7 天的临时文件、日志和崩溃转储（严格类型筛选）"}
    impacts = {"D1": "测试数据库需重新初始化；运行中的 mysql-33479 实例保留",
               "D2": "下次构建会重新编译；源码、配置、正式 outputs 目录保留",
               "C1": "停止 Gradle 构建后处理；下次构建可能重新下载依赖",
               "C2": "退出对应 IDE 后处理；下次打开项目重新索引，保留 LocalHistory",
               "C3": "退出对应应用后处理；网页资源重新加载，保留登录数据库、书签、历史和会话",
               "C4": "仅 .tmp/.temp/.log/.dmp；保留其他类型、Git 仓库、硬链接和无法访问项"}
    groups = []
    for group in ("D1", "D2", "C1", "C2", "C3", "C4"):
        if group.startswith("D"):
            kind = "mysql_test_data" if group == "D1" else "android_build_binary"
            items = [x for x in projects if x["kind"] == kind and x["status"] == "candidate" and x["eligible_adjusted_bytes"] > 0]
            targets = [{"path": x["path"], "bytes": x["eligible_adjusted_bytes"],
                        "files": x["eligible_files"], "git_rule": x["git"]["rule"],
                        "repository": x["repository"], "newest_file_age_hours": x["newest_file_age_hours"]} for x in items]
            policy = {"mode": "selected_files_only", "minimum_quiet_hours": 24,
                      "require_git_ignored": True, "exclude_git_tracked": True,
                      "extensions": sorted(DB_EXTENSIONS if group == "D1" else BUILD_EXTENSIONS),
                      "extra_name_rules": "inspect_projects.eligible_type" if group == "D1" else None}
        else:
            items = [x for x in caches if x["group"] == group and x["candidate_bytes"] > 0]
            targets = [{"path": x["path"], "bytes": x["candidate_bytes"], "files": x["candidate_files"],
                        "mode": x["mode"], "errors": x["errors"], "git_status": x["git_status"]} for x in items]
            policy = {"mode": "explicit_application_cache_contents" if group != "C4" else "old_temp_types_only",
                      "require_application_idle": True, "exclude_git_tracked": True,
                      "keep_nested_git_repositories": True,
                      "minimum_file_age_days": 7 if group == "C4" else None}
        groups.append({"id": group, "drive": group[0], "name": names[group],
                       "estimated_bytes": sum(x["bytes"] for x in targets),
                       "target_count": len(targets), "impact": impacts[group], "policy": policy,
                       "targets": targets})
    if (HERE / "cache_additional_plan.json").exists():
        additions = read("cache_additional_plan.json")
        assert additions["approved"] is False and additions["execution_implemented"] is False
        assert all(g["id"] in {"C5", "C6"} for g in additions["groups"])
        groups.extend(additions["groups"])
    # Groups contain only disjoint absolute roots. A future cleaner must recheck live state.
    all_paths = [Path(x["path"]) for g in groups for x in g["targets"]]
    assert len(set(str(p).lower() for p in all_paths)) == len(all_paths)
    for p in all_paths:
        assert p.is_absolute() and str(p) not in {"C:\\", "D:\\"}
        assert not any(p != q and p.is_relative_to(q) for q in all_paths)
    plan = {"schema_version": 1, "generated_at": now, "approved": False,
            "execution_implemented": False, "groups": groups,
            "conditions": ["Wait for the user's explicit group selection.",
                           "Refresh Git tracked/ignored state, process/service datadirs, and file ages before cleanup.",
                           "Resolve each selected absolute target and ensure containment; reject reparse points and path changes.",
                           "Preserve tracked files, unapproved types, hard links and locked/in-use files. Do not stop databases.",
                           "Do not delete source trees, test SQL, configurations, credentials, build outputs or the whole .scratch directory.",
                           "If a database has changed since inspection or is locked/running, skip the entire instance.",
                           "Log actions and compare actual free space before/after. Never interpret a failed read as permission to delete."]}
    save_json(HERE / "cleanup_plan.json", plan)
    lookup = {g["id"]: g for g in groups}
    total = sum(g["estimated_bytes"] for g in groups)
    lines = ["# C、D 盘空间分析与待选择清理项", "", f"生成时间：{now}。目前未删除任何文件。所有 Python 脚本均为只读分析，计划尚未批准。", "",
             "## 结论", "",
             f"按已核实的目录、Git 状态、文件类型、修改时间和进程情况，{len(groups)} 组候选合计约 {size(total)}。这是估算值，清理时仍需复查正在使用的文件。", "",
             "D 盘最值得处理的是 imp 项目留下的独立测试 MySQL 实例。用户已确认这些数据是可重建的临时测试数据；这不等于允许删除整个 .scratch。C 盘以 Gradle 和 IDE 缓存、索引为主要候选。", "",
             table(["磁盘", "容量", "当前已用", "当前可用", "可用比例"],
                   [[k + ":", size(v["total"]), size(v["used"]), size(v["free"]), f"{v['free']/v['total']:.2%}"] for k,v in volumes.items()]), "",
             "磁盘空间会随其他应用写入而变化；扫描前后的变化不代表本次已进行清理。单位 GiB = 1024³ 字节。", "",
             "C 盘 cache 目录已增加专项分析，含 `.cache` 内部运行环境/模型、通用 Qt 缓存、安装修复缓存，以及新增 C5/C6。详见 [C盘cache补充分析.md](C盘cache补充分析.md) 和 [C盘cache目录全表.md](C盘cache目录全表.md)。", "",
             "## 可选择的清理项", "",
             table(["编号", "内容", "估计可释放", "范围数量", "影响 / 前提"],
                   [[g["id"], g["name"], size(g["estimated_bytes"]), g["target_count"], g["impact"]] for g in groups]), "",
             "可以按编号选择，例如 D1+C1+C2。选择前可查看下面的依据与精确目录；本报告与 JSON 计划均不会执行删除。", "",
             "## D1：测试数据库核验", "",
             f"候选为 {lookup['D1']['target_count']} 个明确的 MySQL data 目录，筛选后的数据文件约 {size(lookup['D1']['estimated_bytes'])}。这些目录都有 ibdata1 等 MySQL 布局标记，均被 Git 忽略；筛选未发现 Git 跟踪文件。", "",
             "清理类型限定为 .ibd、.dblwr、.sdi、.ibt 等数据库生成文件，以及命名明确的 ibdata、undo、redo、binlog 系统文件。保留 .sql、.cnf、.pem、.pid、普通日志和未识别类型，不清理源码、导出备份或凭据。数据目录外的工具链、脚本、测试证据与其他文件均保留。", "",
             "Git 依据：imp 仓库的 `.gitignore:13:/.scratch/`；检查方式为 `git ls-files --cached` 与 `git check-ignore -v`，未运行 git clean、reset 或修改全局 Git 配置。文件类型按扩展名、固定名称与生成目录结构判定，未逐一读取数据库内容。", "",
             "已识别并排除在运行的 `D:\\Work\\Gitlab\\imp\\.scratch\\tms-credentials\\mysql-33479\\data`。系统 MySQL80 服务的数据目录位于 C:\\ProgramData\\MySQL\\MySQL Server 8.0\\Data，另一个 DecorationQuotation-2 测试实例位于不同项目，均不在候选范围。执行前必须重新检查全部实例及文件锁。", ""]
    grouped_db = defaultdict(lambda: [0, 0])
    for x in lookup["D1"]["targets"]:
        category = Path(x["path"]).relative_to(SCRATCH).parts[0]
        grouped_db[category][0] += 1
        grouped_db[category][1] += x["bytes"]
    lines += [table([".scratch 内的测试组", "候选实例数", "候选文件大小"],
                    [[k, v[0], size(v[1])] for k, v in sorted(grouped_db.items(), key=lambda item:item[1][1], reverse=True)]), "",
              "## D2：编译中间文件核验", "",
              "仅选取带 build.gradle / build.gradle.kts 的 Android 模块，且 Git 确认忽略的 intermediates、.transforms、kotlin、snapshot、tmp 子目录中的生成二进制文件。主要类型为 .so、.dex、.a、.jar、.bin、.flat、.class。保留 Java/Kotlin/C++ 源码、JSON/XML/SQL/配置文件、未知类型、正式 outputs 目录和有多个硬链接的文件。", "",
              "未发现候选目录中有 Git 跟踪文件；无 Git 仓库证据的归档项目不进入清理计划。至少 24 小时无文件修改只是额外筛选条件，不能单独证明文件无用。", ""]
    grouped_build = defaultdict(int)
    for x in lookup["D2"]["targets"]:
        grouped_build[x["repository"]] += x["bytes"]
    lines += [table(["项目仓库", "候选二进制大小"], [[k,size(v)] for k,v in sorted(grouped_build.items(), key=lambda item:item[1],reverse=True)]), "",
              "## C 盘缓存范围", "",
              "以下为应用已知缓存目录，通常位于 Git 仓库之外；依据是对应软件的缓存职责和实际文件类型，不能由目录名里有 cache 就推广到整个上级目录。共享硬链接、Git 跟踪文件、重解析点与无法读取的文件均不计入估算。", "",
              table(["编号", "精确目录", "候选大小"], [[g["id"], x["path"], size(x["bytes"])] for g in groups if g["drive"]=="C" for x in g["targets"]]), "",
              "Gradle 仅包括 `.gradle\\caches`，保留 gradle.properties、init.d、wrapper、JDK。缓存包含构建转换结果和下载依赖；后续可能重建或下载。[Gradle 官方目录说明](https://docs.gradle.org/current/userguide/directory_layout.html)", "",
              "IDE 仅包括上表中的 caches 与 index，不含 LocalHistory、配置、插件或 SDK。清理后项目会重新索引；Local History 应保留。[JetBrains 官方缓存说明](https://www.jetbrains.com/help/idea/invalidate-caches.html)", "",
              "浏览器 / 编辑器只选 Cache、Code Cache、GPUCache 等资源缓存；不选 Cookies、History、Login Data、Local Storage、IndexedDB、Service Worker 离线存储、用户配置和会话。", "",
              "Temp 总体约 6.18 GiB，其中约 1.81 GiB 的文件超过 7 天未修改；但这不是全部可删的证据。严格筛选后仅把超过 7 天的 .tmp/.temp/.log/.dmp 列入 C4，保留其余内容。", "",
              "## 大但未列入本次清理的内容", "",
              table(["对象", "目录逻辑大小", "判断"], [
                  [r"C:\Users\MSI_NB\.nuget\packages", "20.97 GiB", "项目直接引用的全局包目录；需确认包源与还原能力，暂不列入推荐"],
                  [r"C:\Users\MSI_NB\.lldb\module_cache", "2.05 GiB", "涉及硬链接，保守排除，不把目录大小当作可释放空间"],
                  [r"D:\.pnpm-store 等包存储", "根目录约 1.32 GiB", "存在引用/硬链接，应使用 pnpm store prune；尚未计算可修剪部分"],
                  [r"D:\安装包", "40.20 GiB", "安装包、ISO 等用户下载文件，另行按保留需求选择"],
                  [r"D:\VM", "60.88 GiB", "虚拟机数据，不作为缓存删除"],
                  [r"D:\Work\NavTalk_LocalDeployment\python.zip 与 D:\Test\python.zip", "合计 27.57 GiB", "仅观察到两个较大压缩包，未确认内容相同或不再需要"],
                  [r"C:\hiberfil.sys / D:\pagefile.sys", "12.71 / 18.00 GiB", "系统休眠 / 分页文件，未调整"],
                  ["源码、.git、虚拟环境、node_modules、AI 模型、聊天附件、笔记和文档", "—", "保留；不根据名称或修改日期批量删除"],
                  ["Windows、WinSxS、Installer、Package Cache、系统 MySQL 数据", "—", "不直接删除；系统缓存应走 Windows 自带清理入口"]]), "",
              "NuGet 全局包目录中的包会被项目直接使用，清理后须重新还原；不把整个目录认定为无需保留的下载缓存。[Microsoft NuGet 说明](https://learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders)", "",
              "pnpm 的 prune 用于删除不再被引用的包；这里没有执行修剪，也没有将包存储总大小算入释放量。[pnpm 官方说明](https://pnpm.io/cli/store)", "",
              "Windows 临时系统文件宜使用系统的清理建议或磁盘清理。[Microsoft 清理说明](https://support.microsoft.com/en-gb/windows/free-up-drive-space-in-windows-85529ccb-c365-490d-b548-831022bc9b32)", "",
              "## 扫描覆盖与误差", "",
              table(["磁盘", "文件数", "目录数", "读取失败数", "跳过重解析点数", "扫描完成时间"],
                    [[k, d["files_scanned"], d["directories_scanned"], d["errors_count"], d["reparse_skipped_count"], d["scanned_at"]] for k,d in disks.items()]), "",
              "C 盘首次在受限环境中扫描，随后完成沙箱外只读补扫；仍有系统受保护路径无法读取。D 盘回收站与 System Volume Information 无法完整读取，未计入清理候选。具体错误和跳过路径保存在原始 JSON 中。", "",
              "目录排行使用逻辑字节，可能受 NTFS 硬链接、稀疏/压缩文件影响，不能直接相加当作物理占用。候选估算针对稀疏/压缩文件调用 Windows 大小接口，并保守排除多硬链接文件；仍不包含簇分配、目录元数据、运行中写入及文件锁的影响。清理后的实际空闲空间增量才是最终释放量。", "",
              "## 文件与复用", "",
              "- `scan_disk.py`：只读扫描 C、D 盘，统计目录、文件大小、修改时间与权限缺口。",
              "- `inspect_projects.py`：Git、数据库/构建文件类型、稀疏文件、硬链接及进程关联核验。",
              "- `inspect_caches.py`：已知应用缓存目录与严格临时文件筛选。",
              "- `cache_supplement.py` / `make_cache_report.py`：重新核验较大 cache 目录、逐项分类并生成补充报告和 C5/C6 待选范围。",
              "- `C盘cache补充分析.md` / `C盘cache目录全表.md`：cache 子目录用途、保留原因及完整名称匹配清单。",
              "- `make_report.py`：生成本报告和待选择计划。",
              "- `cleanup_plan.json`：按编号列出所有精确目录、筛选规则与估算；approved=false。",
              "- `project_candidates.json` / `cache_candidates.json`：文件类型统计、保留原因、Git 规则和逐目录数据。",
              "- `清理目录明细.md`：适合人工查看的完整候选目录。",
              "- `database_processes.json` / `database_services.json`：只读进程、服务与数据目录快照。", "",
              "代码使用已有 Python 3.12 和标准库，无需安装第三方依赖。脚本均未实现删除函数。重复分析前应重新采集进程快照，并刷新两盘原始清单；不要直接把历史报告作为后续删除依据。", ""]
    (HERE / "分析结论.md").write_text("\n".join(lines), encoding="utf-8")
    detail = ["# 清理目录明细（尚未执行）", "", "按文件筛选，不表示可以整目录删除；请同时查看分析结论和 cleanup_plan.json。", ""]
    for g in groups:
        detail += [f"## {g['id']} · {g['name']} · {size(g['estimated_bytes'])}", "", g["impact"], "",
                   table(["精确目录", "候选大小", "候选文件数", "Git / 规则依据"],
                         [[x["path"],size(x["bytes"]),x["files"],x.get("git_rule",x.get("git_status",""))] for x in g["targets"]]), ""]
    (HERE / "清理目录明细.md").write_text("\n".join(detail), encoding="utf-8")
    print(json.dumps({"groups": [{"id": g["id"], "gib": round(g["estimated_bytes"]/GIB,3), "targets":g["target_count"]} for g in groups],
                      "total_gib":round(total/GIB,3), "volumes":volumes, "approved":False}, ensure_ascii=True))


if __name__ == "__main__":
    main()
