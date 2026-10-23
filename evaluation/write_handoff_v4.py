"""Capture final branch log/stat after committing, without a self-referential commit."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def git(*args):
    return subprocess.check_output(['git', '--no-pager', *args], cwd=ROOT, text=True, encoding='utf-8')


def main():
    log = git('log', '--reverse', '--format=%h %s', 'main..HEAD')
    stat = git('diff', '--stat=120', 'main', 'HEAD')
    check = subprocess.run(['git', 'diff', '--check', 'main', 'HEAD'], cwd=ROOT, capture_output=True,
                           text=True, encoding='utf-8')
    report = {'branch': git('branch', '--show-current').strip(), 'head': git('rev-parse', 'HEAD').strip(),
              'git_log_main_to_head': log, 'git_diff_stat_main_to_head': stat,
              'status_short': git('status', '--short'), 'diff_check_exit': check.returncode,
              'diff_check_output': check.stdout + check.stderr,
              'test_results': json.loads((OUT / 'final_checks.json').read_text()),
              'summary': json.loads((OUT / 'summary.json').read_text()),
              'push_performed': False, 'history_rewritten': False}
    (OUT / 'handoff.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    text = '# Final local handover\n\nBranch: `' + report['branch'] + '`\n\n## Branch log\n\n```text\n' + log + '```\n\n'
    text += '## git diff --stat main HEAD\n\n```text\n' + stat + '```\n\n'
    text += 'Final checks and all measured results: [REPORT.md](REPORT.md), [final_checks.json](final_checks.json).\n\n'
    text += 'Suggested PR description: [PR_DESCRIPTION.md](PR_DESCRIPTION.md).\n\nNo push or history rewrite performed.\n'
    (OUT / 'HANDOFF.md').write_text(text, encoding='utf-8')
    print(log)
    print(stat)
    print('Status: ' + (report['status_short'] or 'clean'))
    print('Diff check: ' + str(check.returncode))
    if report['status_short'] or check.returncode:
        raise SystemExit('Handover contains an uncommitted change or whitespace error')


if __name__ == '__main__':
    main()
