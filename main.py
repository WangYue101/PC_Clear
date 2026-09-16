"""PyCharm entry point: open the analysis UI; CLI scans remain read-only."""
from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys

from pc_clear.evidence import git_executable

PROJECT = Path(__file__).resolve().parent
REPORTS = PROJECT / 'reports'
POLICY = PROJECT / 'scan_policy.json'


def main(argv=None):
    # Keep the parent and module subprocesses consistent in Windows/IDE consoles.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if callable(reconfigure):
            reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser(description='默认打开磁盘分析与清理界面。所有可清理项默认关闭；命令行扫描和分析不删除文件。')
    parser.add_argument('--mode', choices=('gui', 'full', 'analyze', 'report'),
                        help='gui：图形界面（默认）；full：完整扫描；analyze：重新分析；report：生成报告')
    parser.add_argument('--run', type=Path, help='报告目录；已有清单模式必须填写，相对路径以项目根目录为准')
    parser.add_argument('--dry-run', action='store_true', help='仅检查环境并显示执行步骤，不运行扫描或写入报告')
    args = parser.parse_args(argv)
    args.mode = args.mode or ('full' if args.dry_run else 'gui')

    if os.name != 'nt' or sys.version_info < (3, 12):
        parser.error('请使用 Windows 上的 Python 3.12 或更新版本。')
    if args.mode == 'gui':
        if args.dry_run:
            import tkinter
            print(f'界面依赖可用：Tk {tkinter.TkVersion}，Python {sys.executable}。未打开界面、未扫描或清理。')
            return 0
        from pc_clear.gui import launch
        run = args.run
        if run is not None and not run.is_absolute(): run = PROJECT / run
        launch(run)
        return 0
    if args.mode != 'full' and args.run is None:
        parser.error('analyze / report 模式需要 --run 指定已有报告目录。')
    run = args.run or REPORTS / ('full_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    if not run.is_absolute():
        run = PROJECT / run
    run = run.resolve()
    policy_args = ['--policy', str(POLICY)]
    stages = []
    if args.mode == 'full':
        for drive in ('C', 'D'):
            if not Path(drive + ':\\').is_dir():
                parser.error(f'{drive} 盘不存在或无法访问。')
            if (run / drive / 'inventory.sqlite').exists():
                parser.error(f'{run} 已有扫描清单，请选择新目录或使用 --mode analyze。')
            stages.append((f'扫描 {drive} 盘', 'pc_clear.scan',
                           ['--root', drive + ':\\', '--output', str(run / drive),
                            '--exclude', str(REPORTS), '--exclude', str(run), *policy_args]))
    if args.mode in ('full', 'analyze'):
        try:
            git_executable()
        except FileNotFoundError as error:
            parser.error(str(error) + '；请安装 Git 并加入 PATH。')
        if not shutil.which('powershell.exe'):
            parser.error('未找到 Windows PowerShell，请检查 PATH。')
        if args.mode == 'analyze':
            for drive in ('C', 'D'):
                if not (run / drive / 'inventory.sqlite').is_file():
                    parser.error(f'缺少 {drive} 盘扫描清单：{run / drive / "inventory.sqlite"}')
        stages.append(('分析应用、Git 和文件类型', 'pc_clear.analyze', ['--run', str(run), *policy_args]))
    if args.mode == 'report':
        required = [run / 'cleanup_plan.json', run / 'candidate_files.jsonl', run / 'environment.json']
        required += [run / d / name for d in ('C', 'D') for name in ('analysis.json', 'inventory.sqlite')]
        missing = [p for p in required if not p.is_file()]
        if missing:
            parser.error('已有分析不完整，缺少：' + str(missing[0]))
    if not POLICY.is_file():
        parser.error(f'找不到保护规则：{POLICY}')
    stages.append(('生成中文报告', 'pc_clear.report', ['--run', str(run)]))

    print(f'Python：{sys.executable}', flush=True)
    print(f'报告目录：{run}', flush=True)
    print('本程序只做扫描和分析，不删除原有文件。', flush=True)
    environment = os.environ.copy()
    environment.update(PYTHONUTF8='1', PYTHONUNBUFFERED='1')
    for index, (title, module, arguments) in enumerate(stages, 1):
        command = [sys.executable, '-u', '-m', module, *arguments]
        print(f'\n[{index}/{len(stages)}] {title}', flush=True)
        if args.dry_run:
            print(subprocess.list2cmdline(command), flush=True)
            continue
        try:
            subprocess.run(command, cwd=PROJECT, env=environment, check=True)
        except subprocess.CalledProcessError as error:
            print(f'\n步骤失败：{title}。退出码 {error.returncode}，请查看上方错误信息。', file=sys.stderr)
            return error.returncode or 1
        except OSError as error:
            print(f'\n无法启动步骤：{error}', file=sys.stderr)
            return 1
    if args.dry_run:
        print('\n环境与命令检查完成，未运行扫描或写入报告。')
    else:
        report = run / '完整分析结论.md'
        if not report.is_file():
            print(f'未找到预期报告：{report}', file=sys.stderr)
            return 1
        print(f'\n完成。请打开报告：\n{report}', flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\n已中断。已完成的扫描结果保留在报告目录中。', file=sys.stderr)
        raise SystemExit(130)
