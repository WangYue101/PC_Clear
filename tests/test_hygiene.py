"""Prevent machine-specific reports from entering version control."""
from pathlib import Path
import subprocess
import unittest

from pc_clear.evidence import git_executable


PROJECT = Path(__file__).resolve().parents[1]


class GitIgnoreTests(unittest.TestCase):
    def test_user_selected_report_outputs_are_ignored(self):
        outputs=(
            'scratch-run/environment.json', 'scratch-run/volumes_latest.json',
            'scratch-run/C/analysis.json', 'scratch-run/C/summary.json', 'scratch-run/C/progress.json',
            'scratch-run/完整分析结论.md', 'scratch-run/全部清理选项.md', 'scratch-run/全部可清理项.md',
            'scratch-run/智能占用分析.md', 'scratch-run/应用占用全表.md',
            'scratch-run/缓存临时目录全表.md', 'scratch-run/旧版本与旧文件.md',
            'scratch-run/扫描缺口全表.md',
        )
        for output in outputs:
            result=subprocess.run([git_executable(), '-C', str(PROJECT), 'check-ignore', '--no-index', '-q', output],
                                  capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, output)


if __name__ == '__main__':
    unittest.main()
