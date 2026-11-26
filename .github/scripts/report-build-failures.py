"""Create/update one automated issue per failed mv2build target."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def failures(text):
    result = {}
    versions = {}
    current = None
    for line in text.splitlines():
        download = re.match(r'^DOWNLOAD ([\w-]+): (.+)$', line)
        failed = re.match(r'^FAILED ([\w-]+): (.*)$', line)
        if download:
            versions[download[1]] = download[2]
        if failed:
            current = failed[1]
            result[current] = {'version': versions.get(current, 'unresolved'), 'error': failed[2]}
        elif re.match(r'^(DOWNLOAD |BUILT |SKIP |WORK |Summary:)', line):
            current = None
        elif current:
            result[current]['error'] += '\n' + line
    return result


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def main():
    output = Path(os.environ['RUNNER_TEMP']) / 'mv2-release'
    log = output / 'build.log'
    failed = failures(log.read_text(errors='replace') if log.exists() else '')
    # Also report setup, unexpected crashes, asset verification and upload errors.
    if not failed or os.environ.get('WORKFLOW_FAILED') == 'true':
        failed['workflow'] = {
            'version': 'not applicable',
            'error': 'A workflow step failed. Open the Actions run below for the failing step and full error.',
        }
    issues = json.loads(gh('api', '--paginate', '--slurp',
                           'repos/{owner}/{repo}/issues?state=open&per_page=100'))
    issues = [issue for page in issues for issue in page if 'pull_request' not in issue]
    run = (f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"
           f"/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}")
    for target, detail in failed.items():
        marker = f'<!-- mv2build-failure:{target} -->'
        title = f'[mv2build] Build failed: {target}'
        # Indentation prevents upstream diagnostics from breaking Markdown fences.
        error = '\n'.join('    ' + line for line in detail['error'][-16000:].splitlines())
        body = (
            f'{marker}\n'
            f'Target: `{target}`\n\nVersion: `{detail["version"]}`\n\n'
            f'Release date: `{os.environ.get("RELEASE_TAG", "unknown")}`\n\n'
            f'Commit: `{os.environ["GITHUB_SHA"]}`\n\n'
            f'[Actions run and logs]({run})\n\n'
            'Full diagnostics: download the `mv2-build-logs-*` artifact from this run '
            '(retained for 14 days).\n\nLatest error:\n\n' + error + '\n'
        )
        existing = next((issue for issue in issues
                         if marker in (issue.get('body') or '')
                         and issue.get('user', {}).get('login') == 'github-actions[bot]'), None)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'issue.md'
            path.write_text(body)
            if existing:
                print(gh('issue', 'edit', str(existing['number']), '--body-file', str(path)))
            else:
                print(gh('issue', 'create', '--title', title, '--body-file', str(path)))


if __name__ == '__main__':
    main()
