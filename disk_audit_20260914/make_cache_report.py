"""Explain all C-drive cache-name matches and emit an unapproved supplement."""
from collections import Counter, defaultdict
import json
from pathlib import Path

from inspect_projects import inside, key
from make_report import table
from scan_disk import save_json

HERE = Path(__file__).resolve().parent
PROFILE = Path(r"C:\Users\MSI_NB")
LOCAL = PROFILE / "AppData/Local"
ROAMING = PROFILE / "AppData/Roaming"


def human(value):
    if value >= 1024**3:
        return f"{value/1024**3:.2f} GiB"
    if value >= 1024**2:
        return f"{value/1024**2:.2f} MiB"
    if value >= 1024:
        return f"{value/1024:.2f} KiB"
    return f"{value} B"


def classify(path):
    p = Path(path)
    text = str(p).lower()
    name = p.name.lower()
    if inside(p,PROFILE / ".cache/codex-runtimes") or inside(p,PROFILE / ".codex/plugins/cache"):
        return "运行环境/已装插件：保留", "目录含执行中的 Python/Node、依赖或插件代码；不作为普通缓存整删", None
    if p == PROFILE / ".cache":
        return "混合缓存根目录：分子项判断", "运行环境、模型、工具元数据并存，详见子目录表", None
    if inside(p, PROFILE / ".cache/torch") or inside(p, PROFILE / ".cache/huggingface"):
        return "模型缓存：单独选择", "删除会影响本地模型使用，需确认不用或可重新下载；未默认列入", None
    if inside(p, PROFILE / ".codex/cache"):
        return "当前应用目录元数据：暂保留", "主要是目录/工具清单 JSON，体积小，当前应用正在使用", None
    if inside(p,PROFILE / ".lldb/module_cache"):
        return "调试模块缓存：硬链接单列", ".so/.oat/.odex；同一文件有多个路径，目录总大小不等于可释放量", None
    if any("backup" in part.lower() or ".bak" in part.lower() or "corrupt" in part.lower() for part in p.parts):
        return "备份中的缓存：保留", "属于备份/故障留档，未确认备份用途，不能只因包含 cache 就清理", None
    if any(part in {"package cache","installer cache","$patchcache$","product cache","update cache","msecache"} for part in text.split("\\")):
        return "安装/修复缓存：由安装器管理", "发现 MSI/CAB/MSP 或安装程序；不直接删除整个目录", None
    if inside(p,Path(r"C:\ProgramData\LogiOptionsPlus\cache")) or inside(p,Path(r"C:\ProgramData\LGHUB\cache")):
        return "罗技应用缓存：待核实更新用途", "无扩展名散列文件，部分格式未识别，更新状态未核实；未计入新增可清理量", None
    if inside(p, LOCAL / "NetEase/CloudMusic/Cache") or "subscriptionplaycache" in text:
        return "音乐播放缓存：建议应用内清理", "发现 .uc/.idx 或 .m4p 音频缓存；可能影响离线播放，单独选择", None
    if inside(p,PROFILE / "Documents/xwechat_files"):
        return "微信文件缓存：建议应用内清理", "涉及用户文件/消息相关数据，不能仅凭忽略规则或 cache 名称批量删除", None
    if name == "localcache":
        return "应用数据容器：不整清", "可包含程序、用户数据和配置；LocalCache 不表示所有内容都可丢弃", None
    if "\\service worker\\" in text or "cachestorage" in name or "\\webstorage\\" in text:
        return "网页离线缓存：单独选择", "可能影响离线网页/应用资源；未与普通资源缓存合并", None
    if name in {"jcef_cache","cef_cache","webview2cache","cefcache"} or name.startswith("cef_cache_"):
        return "嵌入浏览器数据容器：分子项判断", "可能包含登录、数据库和组件；仅资源缓存子目录可能适合清理", None
    wps_profile_roots = [ROAMING / "kingsoft/wps/addons/data/win-i386" / suffix
                         for suffix in ("cef/1/cache", "promeapps/cache", "promebrowser/cache")]
    if p in wps_profile_roots:
        return "WPS 浏览器数据容器：不整清", "名为 cache 的上层容器包含网页配置目录；部分含 IndexedDB、Local Storage 和会话，仅资源缓存子项可能适合清理", None
    if "\\codex\\" in text or "\\packages\\openai.codex_" in text:
        return "当前应用缓存/数据：暂保留", "当前分析所在应用可能正在使用；不直接清空其缓存或用户数据容器", None
    if inside(p,PROFILE / ".gradle/caches"):
        return "已有 C1：Gradle 缓存", "构建结果与依赖缓存；结束构建后可重建/重下载，保留配置", None
    if ("\\jetbrains\\" in text or "\\google\\androidstudio" in text) and name == "caches":
        return "已有 C2：IDE 缓存", "可重建的 IDE 缓存；保留 LocalHistory 和设置", None
    if inside(p,LOCAL / "npm-cache") or inside(p,LOCAL / "pnpm-cache") or inside(p,PROFILE / "go/pkg/mod/cache"):
        return "包管理器缓存：按子项/工具管理", "可能包括 dlx/npx 正在使用的程序、包元数据或模块下载；未整目录加入", None
    if name == "__pycache__":
        return "Python 字节码：低优先级", ".pyc 可再生成；保留源 .py，安装目录由软件管理，不按目录名泛化", None
    if any(part in {".git","node_modules","site-packages","src","source","include","headers"} for part in text.split("\\")):
        return "源码/依赖内部同名目录：保留", "可能是名为 cache 的模块或库代码；是否被 Git 忽略不能证明可删", None
    if text.startswith("c:\\windows\\") or "\\packages\\microsoft" in text:
        return "系统组件缓存：由系统管理", "系统或商店组件数据，当前未规划直接删除", None
    if text.startswith("c:\\program files") or text.startswith("c:\\programdata\\microsoft\\visualstudio\\packages\\"):
        return "软件安装目录：保留/由安装器管理", "安装内容与更新缓存可能混合，不能只按名称删除", None
    if p == LOCAL / "cache" or "qtshadercache" in name:
        return "Qt 着色器缓存：可选", "共享着色器缓存，只有约 133 KiB；未列入大空间方案", None
    allowed_names = {"cache","cache_data","code cache","gpucache","cacheddata","component_crx_cache"}
    if inside(p,LOCAL / "Microsoft/VisualStudio") and name in allowed_names:
        return "新增 C5：Visual Studio 缓存", "Designer/Roslyn 或 WebTools 资源/组件缓存；退出 VS 后重建，保留配置和项目", "C5"
    prefixes = [ROAMING/"QQ",ROAMING/"DingTalk",ROAMING/"LarkShell",ROAMING/"Tencent/xwechat/radium",
                ROAMING/"kingsoft/wps/addons",ROAMING/"Code",ROAMING/"Cursor",
                LOCAL/"Microsoft/Edge/User Data",LOCAL/"ima.copilot/User Data",LOCAL/"微信开发者工具/User Data"]
    known_application = any(inside(p,q) for q in prefixes) or "\\appdata\\local\\dingtalk_" in text
    if known_application and name in allowed_names:
        return "新增 C6：其他应用资源缓存", "仅 Chromium 资源、代码或组件缓存；退出对应应用，保留登录、消息、离线存储和配置", "C6"
    if inside(p,LOCAL / "Temp"):
        return "临时目录缓存：按类型与年龄核验", "Temp 可含项目副本和在用工具；不能整目录清理", None
    return "用途尚未充分确认：保留待核实", "记录占用与文件类型；没有足够证据认定可删除", None


def main():
    data = json.loads((HERE/"cache_supplement.json").read_text(encoding="utf-8"))
    assert data["progress"]["completed"] == data["progress"]["total"]
    original_plan = json.loads((HERE/"cleanup_plan.json").read_text(encoding="utf-8"))
    old_targets = [(g["id"],t["path"]) for g in original_plan["groups"] if g["id"] in {"C1","C2","C3","C4"} for t in g["targets"]]
    fresh = data["fresh_roots"]
    fresh_lookup = {key(x["path"]):x for x in fresh}
    groups = {"C5":[],"C6":[]}
    detailed = []
    for row in fresh:
        label, reason, proposed = classify(row["path"])
        m = row.get("metrics",{})
        overlaps = [gid for gid,p in old_targets if inside(row["path"],p) or inside(p,row["path"])]
        if overlaps and proposed:
            label, reason, proposed = "已有方案："+"/".join(sorted(set(overlaps))), "与前一轮清理范围重合，不重复计入新增量", None
        eligible = (row["status"] == "measured" and not m.get("errors",0)
                    and not m.get("reparse_skipped",0) and not m.get("tracked_files",0)
                    and not m.get("nested_git_repositories",0) and row.get("repository") is None)
        if proposed and eligible:
            amount = m.get("single_link_untracked_bytes",0)
            if amount:
                groups[proposed].append({"path":row["path"],"bytes":amount,
                                        "files":m.get("files",0)-m.get("multiple_link_files",0),
                                        "mode":"explicit_application_cache_contents","errors":0,
                                        "git_status":"已检查 Git 跟踪文件；未检测到仓库或跟踪文件，依据已知应用缓存位置及实际格式",
                                        "format_evidence":[x["type"] for x in row.get("types",[])[:5]]})
        elif proposed:
            label, reason = "核验不完整：暂不列入", "存在读取、链接或 Git 仓库核验限制，未计入新增可清理量"
        detailed.append({**row,"decision":label,"reason":reason,"old_plan_overlap":overlaps})
    definitions = {"C5":("Visual Studio Designer / Roslyn / WebTools 缓存","退出 Visual Studio 与相关 ServiceHub/WebView 后处理；索引/资源可能重建或重新下载"),
                   "C6":("钉钉、飞书、QQ、微信等应用的资源/代码缓存","退出相关应用后处理；保留消息文件、登录数据库、配置、Service Worker 离线存储和备份")}
    additions=[]
    for gid,targets in groups.items():
        additions.append({"id":gid,"drive":"C","name":definitions[gid][0],"impact":definitions[gid][1],
                          "estimated_bytes":sum(t["bytes"] for t in targets),"target_count":len(targets),"targets":targets,
                          "policy":{"mode":"explicit_application_cache_contents","require_application_idle":True,
                                    "exclude_git_tracked":True,"keep_nested_git_repositories":True,
                                    "exclude_reparse_points_and_multiple_hardlinks":True,"revalidate_before_cleanup":True}})
    for g in additions:
        for t in g["targets"]:
            assert not any(inside(t["path"],p) or inside(p,t["path"]) for _,p in old_targets)
    save_json(HERE/"cache_additional_plan.json",{"approved":False,"execution_implemented":False,
              "generated_at":data["generated_at"],"groups":additions})
    detailed_lookup = {key(x["path"]):x for x in detailed}
    def decision_for(path):
        old_groups = [gid for gid,p in old_targets if inside(path,p)]
        if old_groups:
            return "已有方案："+"/".join(sorted(set(old_groups))), "处于原方案范围内，仍按原方案的文件筛选规则处理，不重复计量"
        if key(path) in detailed_lookup:
            row = detailed_lookup[key(path)]
            return row["decision"], row["reason"]
        new_groups = [g["id"] for g in additions for t in g["targets"] if inside(path,t["path"])]
        if new_groups:
            return "新增方案子目录："+"/".join(sorted(set(new_groups))), "已包含在上级精确缓存范围中，不单独相加"
        label, reason, proposed = classify(path)
        if proposed:
            return "缓存位置：尚未加入新增方案", "此路径未独立完成本次候选核验；不计入新增释放量"
        return label, reason
    save_json(HERE/"cache_classified.json",{"generated_at":data["generated_at"],"fresh_roots":detailed,
              "all_name_matches":[{**x,"decision":decision_for(x["path"])[0],"reason":decision_for(x["path"])[1]} for x in data["snapshot_matches"]]})
    root_cache=fresh_lookup[key(PROFILE/".cache")]
    generic=fresh_lookup[key(LOCAL/"cache")]
    notes={"codex-runtimes":"正在使用的 Python/Node、库和程序；保留。当前扫描 Python 位于此目录。",
           "torch":"s3fd-619a316812.pth 模型权重；需确认不用或可以重新下载后单独选择。",
           "huggingface":"此次只发现很小的下载元数据等文件，没有大模型权重占用。",
           "tooling":"工具元数据，小于 1 MiB；收益很小，暂保留。","pkg":"工具数据，小于 1 MiB；收益很小，暂保留。",
           ".jsontokotlin":"未统计到文件字节，空目录没有实质清理收益。","mim":"未统计到文件字节，空目录没有实质清理收益。"}
    lines=["# C 盘 cache 专项补充分析", "", f"补查时间：{data['generated_at']}。本轮仍未删除文件。", "",
           "上一轮全盘统计包含这些目录，但报告只展开了部分候选；此次补充目录内部内容、用途和保留理由。", "",
           "## 你提到的 cache 目录", "",
           f"`C:\\Users\\MSI_NB\\.cache` 实测 {human(root_cache['metrics']['logical_bytes'])}，具体如下：", "",
           table(["子目录","文件字节","判断"],[[x["name"],human(x.get("logical_bytes",0)),notes.get(x["name"],"待核实")] for x in root_cache["immediate_children"]]),"",
           "这里大部分是 .dll/.exe/.node/.py 等运行文件。没有 Git 仓库不意味着它们是垃圾；用途和实际文件类型更关键。当前分析使用的 Python 也位于 codex-runtimes 中，因此没有把它纳入清理。", "",
           "Torch Hub 会将模型权重保存在缓存目录，目录名为 cache 也可能意味着下一次运行模型仍然需要这些文件。[PyTorch 官方说明](https://docs.pytorch.org/docs/2.14/hub.html#where-are-my-downloaded-models-saved)", "",
           f"`C:\\Users\\MSI_NB\\AppData\\Local\\cache` 实测 **{human(generic['metrics']['logical_bytes'])}**，共 {generic['metrics']['files']} 个文件，均位于 `qtshadercache-x86_64-little_endian-llp64`。可以作为可再生成的着色器缓存单独选择，但释放空间很小。[Qt 缓存路径说明](https://doc.qt.io/qt-6/qstandardpaths.html)","",
           "`C:\\cache` 与 `C:\\.cache` 此次检查均不存在；不要与用户目录下的 `.cache` 混淆。", "",
           "## 新增可选缓存", "",
           "以下范围与原来的 C1–C4 去重；只作为待选择方案，没有执行删除。占用中的应用要先退出，清理前还会复查 Git、链接、文件锁和路径。", "",
           table(["编号","内容","估计释放上限","目录数","影响"],[[g["id"],g["name"],human(g["estimated_bytes"]),g["target_count"],g["impact"]] for g in additions]), "",
           "C5 中 Roslyn 缓存确实包含 .ide/.ide-wal SQLite 文件；数据库格式本身既不代表重要数据，也不代表可以删除，此处结合了 Roslyn 生成缓存的位置判断。WebTools 的部分无扩展名文件经文件头采样确认是 CRX 组件包。", "",
           "C5 的 Designer\\Cache 包含 .dll/.pdb/.xml/.xaml 等设计器缓存副本，不能把这套判断应用到项目源码或原始库文件。", "",
           "C6 仅选明确资源/代码缓存位置。微信聊天附件、音乐离线资源、Service Worker CacheStorage、用户配置与备份没有合并进来。WPS 的 cef\\1\\cache、promeapps\\cache、promebrowser\\cache 是上层数据容器，复核发现其中部分有 IndexedDB、Local Storage 和会话；这三个混合根目录未加入 C6。部分活动应用的缓存文件头不可读，因此清理前需要先退出应用并再次核查。", ""]
    for g in additions:
        types = Counter()
        for target in g["targets"]:
            for item in fresh_lookup[key(target["path"])].get("types", []):
                types[item["type"]] += item["bytes"]
        lines += [f"### {g['id']} 文件类型与精确范围", "",
                  table(["主要文件类型", "类型统计字节"], [[kind, human(amount)] for kind,amount in types.most_common(6)]), "",
                  table(["目录","估计上限"],[[t["path"],human(t["bytes"])] for t in g["targets"]]), ""]
    notable=[]
    for x in detailed:
        if x.get("metrics",{}).get("logical_bytes",0)>=100*1024**2 and not x["decision"].startswith(("已有","新增")):
            notable.append([x["path"],human(x["metrics"]["logical_bytes"]),x["decision"],x["reason"]])
    lines += ["## 其他较大 cache：已经分析，但不能直接按大小算作可清理", "",table(["目录","逻辑大小","结论","理由"],notable), "",
              "`LocalCache` 是应用数据容器，可能含浏览器程序、日志、会话或数据库；它的系统定义并不保证所有数据都可丢弃。[Microsoft LocalCache 说明](https://learn.microsoft.com/en-us/uwp/api/windows.storage.applicationdata.localcachefolder?view=winrt-26100)", "",
              "安装包缓存包含 .msi/.cab/.msp 等修复介质。若要处理 Visual Studio 的安装缓存，应走安装器管理入口，避免直接整删。[Microsoft 安装缓存说明](https://learn.microsoft.com/en-us/visualstudio/install/disable-or-move-the-package-cache?view=visualstudio)", "",
              "## 覆盖范围与计量", "",
              f"基于 {data['source_scanned_at']} 的 C 盘完整扫描清单，共找到 {data['matched_directory_count']} 个目录名包含 cache 的项目，包括 __pycache__、源码中的同名模块、父子缓存目录。合并父子关系后有 {data['maximal_root_count']} 个最外层匹配目录。", "",
              f"此次对大于等于 8 MiB 的最外层目录及显式通用缓存路径重新分析，共请求 {len(fresh)} 个路径，其中 {sum(x['status']=='missing' for x in fresh)} 个不存在。较小目录沿用全盘扫描时的元数据；目录全表标明计量时间来源。它不是一次新的全盘扫描，也不能保证捕获之后新建的其他缓存路径。", "",
              "父子目录不能相加，Cache 与 Cache_Data 不重复计量。单个根目录内部按 NTFS 文件标识去重，另记录硬链接；不同应用路径仍可能引用同一物理内容，所以未把全部 cache 占用加成一个可释放总数。新增 C5/C6 按单链接、未跟踪的文件估算，排除与原方案重叠范围；最终释放量以实际清理后空闲空间变化为准。", "",
              "Git 查询为只读。文件类型统计使用扩展名和已知应用布局，对每个目录最多 8 个大文件读取最多 16 字节格式签名；没有打开完整数据库、模型或聊天内容，没有上传本地文件内容。无法确定用途的目录明确标为待核实。", "",
              "完整路径、大小及判断见 `C盘cache目录全表.md`；新扫描的文件类型、子目录、样本格式和错误见 `cache_supplement.json`；分类见 `cache_classified.json`。原来的 D 盘分析及选择仍保留。", ""]
    (HERE/"C盘cache补充分析.md").write_text("\n".join(lines),encoding="utf-8")
    full=["# C 盘名称含 cache 的目录全表", "", "下表每行不一定都是缓存，更不表示允许删除。父子目录和链接不能简单相加。", "",
          "只有“本次重测”的行重新测量了该根目录；其余沿用原全盘快照大小。判断来自应用路径、类型与 Git 语境；未知项保留。", "",
          table(["完整路径","大小","计量来源","分类","理由"],
                [[x["path"],human(fresh_lookup[key(x["path"])]["metrics"].get("logical_bytes",0)) if key(x["path"]) in fresh_lookup and "metrics" in fresh_lookup[key(x["path"])] else human(x["bytes"]),
                  "本次重测" if key(x["path"]) in fresh_lookup else "原全盘快照",decision_for(x["path"])[0],decision_for(x["path"])[1]]
                 for x in sorted(data["snapshot_matches"],key=lambda row:row["bytes"],reverse=True)]), ""]
    (HERE/"C盘cache目录全表.md").write_text("\n".join(full),encoding="utf-8")
    print(json.dumps({"new_groups":[{"id":g["id"],"gib":round(g["estimated_bytes"]/1024**3,3),"targets":g["target_count"]} for g in additions],
                      "profile_cache_bytes":root_cache["metrics"]["logical_bytes"],"generic_cache_bytes":generic["metrics"]["logical_bytes"],
                      "fresh_paths":len(fresh),"matched_directory_count":data["matched_directory_count"]},ensure_ascii=True))


if __name__=="__main__":
    main()
