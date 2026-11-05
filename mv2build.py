#!/usr/bin/env python3
"""Download, patch, verify and package current Chromium browsers on Linux.

Run without arguments to build all targets. See --help and README.md.
No browser or installer is executed. Python 3.12+ is required for safe tar extraction.
"""
from __future__ import annotations

import argparse
import dataclasses
import fcntl
import functools
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
CHANNELS = ('stable', 'beta', 'dev', 'canary')
TARGETS = (tuple(f'chrome-linux-{c}' for c in CHANNELS)
           + tuple(f'chrome-win64-{c}' for c in CHANNELS[:3])
           + tuple(f'chrome-testing-{p}-{c}' for p in ('linux', 'win64') for c in CHANNELS)
           + ('chromium-arch', 'chromium-snapshot-linux'))
DEFAULT_TARGETS = TARGETS
TARGETS += ('chromium-universal', 'chromium-universal-glibc')
GOOGLE_DEB = 'https://dl.google.com/linux/chrome/deb/'
CFT = 'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json'
SNAPSHOTS = 'https://storage.googleapis.com/chromium-browser-snapshots/Linux_x64/'
APPIDS = dict(zip(CHANNELS, (
    '8A69D345-D564-463C-AFF1-A69D9E530F96',
    '8237E44A-0054-442C-B6B6-EA0509993955',
    '401C381F-E0DE-4B85-8BD8-3F3F14FBDA57')))


class BuildError(Exception):
    pass


def log(message):
    print(message, flush=True)


def request(url, data=None):
    if not url.startswith('https://'):
        raise BuildError(f'Refusing non-HTTPS URL: {url}')
    headers = {'User-Agent': 'mv2build/1.0'}
    if data is not None:
        headers['Content-Type'] = 'text/xml'
    return urllib.request.Request(url, data=data, headers=headers)


def fetch(url, data=None, destination=None):
    """Retry transient network failures; never leave a partial destination."""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request(url, data), timeout=120) as response:
                if not response.url.startswith('https://'):
                    raise BuildError('Refusing insecure redirect')
                expected = response.headers.get('Content-Length')
                if destination is None:
                    result = response.read()
                    size = len(result)
                else:
                    with open(destination, 'wb') as out:
                        shutil.copyfileobj(response, out, 4 << 20)
                    size = destination.stat().st_size
                    result = None
                if expected and size != int(expected):
                    raise OSError(f'Incomplete download: {size}/{expected} bytes')
                return result
        except (OSError, urllib.error.URLError):
            if destination is not None:
                destination.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(1 + attempt)


@functools.lru_cache(maxsize=None)
def metadata(url):
    return fetch(url)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(4 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(value):
    if not re.fullmatch(r'[A-Za-z0-9_.+-]+', value) or value in ('.', '..'):
        raise BuildError(f'Unsafe filename/version in metadata: {value!r}')
    return value


@dataclasses.dataclass(frozen=True)
class Release:
    target: str
    version: str
    url: str
    kind: str
    filename: str
    checksum: str = ''
    revision: str = ''


def resolve(target):
    if target.startswith('chrome-linux-'):
        channel = target.removeprefix('chrome-linux-')
        package = 'google-chrome-' + ('unstable' if channel == 'dev' else channel)
        text = gzip.decompress(metadata(GOOGLE_DEB + 'dists/stable/main/binary-amd64/Packages.gz')).decode()
        for paragraph in text.split('\n\n'):
            fields = dict(line.split(': ', 1) for line in paragraph.splitlines() if ': ' in line and not line.startswith(' '))
            if fields.get('Package') == package and fields.get('Architecture') == 'amd64':
                version = safe_name(fields['Version'].split('-')[0])
                return Release(target, version, urllib.parse.urljoin(GOOGLE_DEB, fields['Filename']),
                               'deb', f'chrome-{channel}-{version}.tar.zst', fields['SHA256'])
        raise BuildError(f'{package} not found in official amd64 package index')
    if target.startswith('chrome-testing-'):
        platform, channel = target.removeprefix('chrome-testing-').split('-')
        record = json.loads(metadata(CFT))['channels'][channel.title()]
        version = safe_name(record['version'])
        download = next(d for d in record['downloads']['chrome']
                        if d['platform'] == ('linux64' if platform == 'linux' else 'win64'))
        filename = (f'chrome-{channel}-{version}-testing.tar.zst' if platform == 'linux'
                    else f'chrome-win64-{version}-{channel}-testing.tar.zst')
        return Release(target, version, download['url'], 'zip', filename)
    if target.startswith('chrome-win64-'):
        channel = target.removeprefix('chrome-win64-')
        body = (f'<request protocol="3.0" updater="Omaha" updaterversion="1.3.36.372" ismachine="0">'
                f'<os platform="win" version="10.0" arch="x64"/>'
                f'<app appid="{{{APPIDS[channel]}}}" version="0.0.0.0" ap="x64-{channel}">'
                '<updatecheck/></app></request>').encode()
        root = ET.fromstring(fetch('https://tools.google.com/service/update2', body))
        update = root.find('./app/updatecheck')
        if update is None or update.get('status') != 'ok':
            raise BuildError(f'Omaha returned no full installer for {target}')
        manifest = update.find('manifest')
        version = safe_name(manifest.attrib['version'])
        packages = manifest.findall('./packages/package')
        if len(packages) != 1:
            raise BuildError('Expected a single full Windows installer')
        package = packages[0]
        base = next(u.attrib['codebase'] for u in update.findall('./urls/url')
                    if u.attrib['codebase'].startswith('https://dl.google.com/'))
        url = urllib.parse.urljoin(base, safe_name(package.attrib['name']))
        return Release(target, version, url, 'exe', f'chrome-win64-{version}-{channel}.tar.zst',
                       package.attrib['hash_sha256'])
    if target == 'chromium-arch':
        candidates = []
        for repo in ('extra', 'extra-testing'):
            try:
                info = json.loads(metadata(f'https://archlinux.org/packages/{repo}/x86_64/chromium/json/'))
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    continue
                raise
            candidates.append(info)
        if not candidates:
            raise BuildError('Chromium absent from both Arch repositories')
        # Chromium pkgver is numeric; compare epoch, all version components and pkgrel.
        def version_key(info):
            return (int(info['epoch']), tuple(int(n) for n in info['pkgver'].split('.')),
                    tuple(int(n) for n in str(info['pkgrel']).split('.')))
        info = max(candidates, key=version_key)
        filename = safe_name(info['filename'])
        version = safe_name(f"{info['pkgver']}-{info['pkgrel']}")
        repo = info['repo']
        database = metadata(f'https://geo.mirror.pkgbuild.com/{repo}/os/x86_64/{repo}.db')
        checksum = ''
        with tarfile.open(fileobj=io.BytesIO(database), mode='r:*') as archive:
            for member in archive:
                if member.name.startswith('chromium-') and member.name.endswith('/desc'):
                    fields = archive.extractfile(member).read().decode()
                    if f'%FILENAME%\n{filename}\n' in fields:
                        checksum = re.search(r'%SHA256SUM%\n([a-f0-9]{64})\n', fields)[1]
                        break
        if not checksum:
            raise BuildError('Arch mirror and package API disagree; retry after mirror synchronization')
        return Release(target, version,
                       f"https://geo.mirror.pkgbuild.com/{repo}/os/x86_64/{filename}",
                       'arch', filename, checksum)
    if target == 'chromium-snapshot-linux':
        revision = metadata(SNAPSHOTS + 'LAST_CHANGE').decode().strip()
        if not revision.isdigit():
            raise BuildError('Invalid snapshot revision')
        # Read VERSION from the exact source revision, without executing the browser.
        import base64
        revisions = json.loads(metadata(SNAPSHOTS + revision + '/REVISIONS'))
        commit = revisions['got_revision']
        if not re.fullmatch(r'[a-f0-9]{40}', commit):
            raise BuildError('Invalid snapshot source commit')
        raw = metadata(f'https://chromium.googlesource.com/chromium/src/+/{commit}/chrome/VERSION?format=TEXT')
        fields = dict(line.split('=', 1) for line in base64.b64decode(raw).decode().splitlines() if '=' in line)
        version = safe_name('.'.join(fields[k] for k in ('MAJOR', 'MINOR', 'BUILD', 'PATCH')))
        return Release(target, version, SNAPSHOTS + revision + '/chrome-linux.zip', 'zip',
                       f'chromium-snapshot-{version}-r{revision}.tar.zst', revision=revision)
    raise BuildError(f'Unknown target: {target}')


def run(argv, **kwargs):
    result = subprocess.run([str(a) for a in argv], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        detail = result.stderr.decode(errors='replace')[-4000:]
        raise BuildError(f'Command failed ({result.returncode}): {argv[0]}\n{detail}')
    return result.stdout


def extract_tar(source, destination, browser_only=False, selector=None):
    with tarfile.open(source, 'r:*') as archive:
        # Reject absolute paths as well as traversal; data_filter checks symlink targets,
        # hard links, special files, and permissions at extraction time.
        def filter_member(member, path):
            if selector is not None and not selector(member):
                return None
            if PurePosixPath(member.name).is_absolute():
                raise BuildError(f'Absolute archive path: {member.name}')
            if browser_only:
                parts = PurePosixPath(member.name).parts
                if (len(parts) < 3 or parts[:2] != ('opt', 'google')
                        or parts[2] not in ('chrome', 'chrome-beta', 'chrome-unstable', 'chrome-canary')):
                    return None
                if '..' in parts:
                    raise BuildError(f'Unsafe browser archive path: {member.name}')
                if member.issym():
                    browser_root = PurePosixPath('/', *parts[:3])
                    parent = PurePosixPath('/', *parts[:-1])
                    target = PurePosixPath(posixpath.normpath(posixpath.join(str(parent), member.linkname)))
                    if not target.is_relative_to(browser_root):
                        raise BuildError(f'Browser symlink escapes its directory: {member.name} -> {member.linkname}')
                    # DEBs use absolute aliases inside /opt/google/chrome-*. Make
                    # them portable while retaining data_filter's escape checks.
                    member = member.replace(linkname=posixpath.relpath(str(target), str(parent)))
            filtered = tarfile.data_filter(member, path)
            # Keep Chrome's packaged sandbox mode for extraction by root on the
            # destination machine; no privileged file is executed by this builder.
            if filtered is not None and member.isfile() and PurePosixPath(member.name).name == 'chrome-sandbox':
                filtered.mode = member.mode & 0o7777
            return filtered
        archive.extractall(destination, filter=filter_member)


def extract_zip(source, destination):
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in info.filename:
                raise BuildError(f'Unsafe ZIP member: {info.filename}')
            mode = info.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise BuildError(f'Unexpected ZIP symlink: {info.filename}')
            path = Path(archive.extract(info, destination))
            if not info.is_dir() and mode & 0o111:
                path.chmod(0o755)


def extract_deb(source, destination, work, browser_only=True, selector=None):
    # Read the ar envelope ourselves; no dpkg installation or maintainer scripts.
    with open(source, 'rb') as stream:
        if stream.read(8) != b'!<arch>\n':
            raise BuildError('Invalid Debian ar header')
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b'`\n':
                raise BuildError('Invalid Debian ar member')
            name = header[:16].decode().strip().rstrip('/')
            size = int(header[48:58])
            if name.startswith('data.tar'):
                payload = work / safe_name(name)
                with open(payload, 'wb') as out:
                    remaining = size
                    while remaining:
                        chunk = stream.read(min(4 << 20, remaining))
                        if not chunk:
                            raise BuildError('Truncated Debian payload')
                        out.write(chunk)
                        remaining -= len(chunk)
                if name.endswith('.zst'):
                    unpacked = work / 'data.tar'
                    run(['zstd', '-d', '-q', payload, '-o', unpacked])
                    payload = unpacked
                # System integration files include absolute symlinks and cron jobs;
                # only the self-contained /opt/google/chrome* payload is needed.
                extract_tar(payload, destination, browser_only=browser_only, selector=selector)
                return
            stream.seek(size + size % 2, 1)
    raise BuildError('Debian archive has no data.tar payload')


def extract_installer(source, destination, work):
    # Select a single embedded archive, extracting it to stdout (no installer paths).
    # Force PE inspection: 7z otherwise transparently opens the nested archive,
    # listing its resource twice and hiding the installer envelope.
    listing = run(['7z', 'l', '-slt', '-tPE', source]).decode(errors='replace')
    paths = re.findall(r'^Path = (.+)$', listing, re.MULTILINE)[1:]
    candidates = [p for p in paths if p.lower().endswith(('chrome.7z', 'chrome.packed.7z'))]
    if not candidates:
        candidates = [p for p in paths if p.replace('\\', '/').endswith('/B7')]
    if len(candidates) != 1:
        raise BuildError('Cannot locate unique Chrome payload in Windows installer')
    embedded = work / 'chrome.7z'
    with open(embedded, 'wb') as out:
        proc = subprocess.run(['7z', 'e', '-tPE', '-so', str(source), candidates[0]], stdout=out,
                              stderr=subprocess.PIPE)
    if proc.returncode:
        raise BuildError('Cannot extract embedded Chrome archive')
    # bsdtar supports 7zip and secure extraction of the full browser directory.
    run(['bsdtar', '-xf', embedded, '-C', destination, '--no-same-owner'])
    if not list(destination.rglob('chrome.dll')):
        raise BuildError('Installer payload is packed/delta or contains no chrome.dll')


def unpack(release, source, destination, work):
    destination.mkdir()
    if release.kind == 'deb':
        extract_deb(source, destination, work)
    elif release.kind == 'zip':
        extract_zip(source, destination)
    elif release.kind == 'exe':
        extract_installer(source, destination, work)
    else:
        unpacked = work / 'package.tar'
        run(['zstd', '-d', '-q', source, '-o', unpacked])
        extract_tar(unpacked, destination)
    if release.kind == 'arch':
        binary = destination / 'usr/lib/chromium/chromium'
        if not binary.is_file():
            raise BuildError('Arch package has no usr/lib/chromium/chromium')
        return destination, binary
    windows = 'win64' in release.target
    name = 'chrome.dll' if windows else 'chrome'
    binaries = [p for p in destination.rglob(name) if p.is_file() and not p.is_symlink()]
    if len(binaries) != 1:
        raise BuildError(f'Expected one {name}; found {len(binaries)}')
    binary = binaries[0]
    # Windows mini-installer stores chrome.exe beside a version directory.
    root = binary.parent
    if windows and not (root / 'chrome.exe').is_file() and (root.parent / 'chrome.exe').is_file():
        root = root.parent
    return root, binary


def patch(binary, logfile):
    # Use the existing copy-and-self-check workflow, avoiding backups in output packages.
    replacement = binary.with_name(binary.name + '.mv2build')
    argv = [sys.executable, str(HERE / 'mv2ctl.py'), 'test-apply', str(binary), '--output', str(replacement)]
    with open(logfile, 'w') as out:
        result = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT)
    if result.returncode or not replacement.is_file():
        raise BuildError(f'Patch/profile verification failed; see {logfile}')
    os.replace(replacement, binary)


def refresh_mtree(root):
    if not (root / '.PKGINFO').is_file():
        raise BuildError('Arch package is missing .PKGINFO')
    (root / '.MTREE').unlink(missing_ok=True)
    entries = sorted(p.name for p in root.iterdir())
    # Record root ownership to match the final package, not the builder's user ID.
    mtree = run(['bsdtar', '-c', '--format=mtree', '--options=mtree:all,mtree:!device,mtree:!flags',
                 '--uid', '0', '--gid', '0', '-C', root, *entries])
    with open(root / '.MTREE', 'wb') as out:
        out.write(gzip.compress(mtree, mtime=0))


def verify_arch_package(path):
    names = run(['bsdtar', '-tf', path]).decode().splitlines()
    for required in ('.PKGINFO', '.MTREE'):
        if names.count(required) != 1:
            raise BuildError(f'Arch archive must contain exactly one root {required}, without ./ prefix')
    if any(name.startswith('./') for name in names):
        raise BuildError('Arch archive contains ./-prefixed paths')
    if shutil.which('pacman'):
        # Read package metadata through libalpm; this does not install anything.
        run(['pacman', '-Qip', path])


def pack(root, destination, arch=False):
    # GNU tar preserves executable modes and links. Arch packages keep metadata at root.
    argv = ['tar', '--zstd', '--numeric-owner', '--owner=0', '--group=0', '-cf', str(destination)]
    if arch:
        # libalpm requires the literal name .PKGINFO, not ./.PKGINFO.
        # Explicit root entries avoid tar's ./ prefix for every package path.
        entries = ['.PKGINFO', *sorted(p.name for p in root.iterdir() if p.name != '.PKGINFO')]
        argv += ['-C', str(root), '--', *entries]
    else:
        argv += ['-C', str(root.parent), root.name]
    run(argv)
    run(['zstd', '-t', '-q', destination])
    if arch:
        verify_arch_package(destination)


def builder_fingerprint():
    digest = hashlib.sha256()
    for name in ('mv2build.py', 'mv2ctl.py', 'mv2profiles.py', 'mv2universal.py', 'mv2glibc.py'):
        digest.update((HERE / name).read_bytes())
    return digest.hexdigest()


def build(release, args):
    final = args.output / release.filename
    manifest_path = final.with_name(final.name + '.json')
    identity = {'release': dataclasses.asdict(release), 'builder_sha256': builder_fingerprint()}
    if not args.force and final.is_file() and manifest_path.is_file():
        try:
            saved = json.loads(manifest_path.read_text())
            if all(saved.get(k) == v for k, v in identity.items()) and saved.get('archive_sha256') == sha256(final):
                log(f'SKIP {release.target}: {final.name}')
                return 'skipped'
        except (ValueError, OSError):
            pass
    work = Path(tempfile.mkdtemp(prefix=release.target + '-', dir=args.work_dir))
    partial = None
    try:
        source = work / ('download.' + {'deb': 'deb', 'zip': 'zip', 'exe': 'exe', 'arch': 'tar.zst'}[release.kind])
        log(f'DOWNLOAD {release.target}: {release.version}')
        fetch(release.url, destination=source)
        source_hash = sha256(source)
        if release.checksum and source_hash.lower() != release.checksum.lower():
            raise BuildError('Upstream SHA256 mismatch')
        root, binary = unpack(release, source, work / 'unpacked', work)
        patch(binary, args.output / 'logs' / f'{release.target}-{release.version}.log')
        if release.kind == 'arch':
            refresh_mtree(root)
        fd, temporary = tempfile.mkstemp(prefix='.' + final.name + '.', suffix='.partial', dir=args.output)
        os.close(fd)
        partial = Path(temporary)
        pack(root, partial, arch=release.kind == 'arch')
        identity.update(source_sha256=source_hash, archive_sha256=sha256(partial),
                        binary_sha256=sha256(binary), patch_status='patched')
        # Publish only a complete, verified archive. Sidecar is the cache commit marker.
        os.replace(partial, final)
        manifest_tmp = work / 'manifest.json'
        manifest_tmp.write_text(json.dumps(identity, indent=2) + '\n')
        # Work directory can be on another filesystem, so write sidecar locally.
        fd, sidecar = tempfile.mkstemp(prefix='.' + final.name, suffix='.json.tmp', dir=args.output)
        try:
            with os.fdopen(fd, 'w') as out:
                out.write(manifest_tmp.read_text())
            os.replace(sidecar, manifest_path)
        finally:
            Path(sidecar).unlink(missing_ok=True)
        log(f'BUILT {final}')
        return 'built'
    finally:
        if partial:
            partial.unlink(missing_ok=True)
        if args.keep_work:
            log(f'WORK {work}')
        else:
            shutil.rmtree(work)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', action='append', choices=TARGETS, help='Repeat to select targets; default: all')
    parser.add_argument('--list', action='store_true', help='List available targets without network access')
    parser.add_argument('--dry-run', action='store_true', help='Resolve latest versions/URLs; do not download builds')
    parser.add_argument('--output', type=Path, default=HERE / 'builds', help='Archive/log directory (default: ./builds beside script)')
    parser.add_argument('--work-dir', type=Path, help='Temporary extraction directory (default: system temporary directory)')
    parser.add_argument('--keep-work', action='store_true', help='Keep downloaded/extracted files for diagnostics')
    parser.add_argument('--force', action='store_true', help='Rebuild even if verified output already exists')
    parser.add_argument('--chromium-universal', action='store_true',
                        help='Build Arch, DEB and RPM packages from the latest Debian 12 Chromium; alone selects only this target')
    parser.add_argument('--chromium-universal-glibc', action='store_true',
                        help='Opt-in Arch/DEB/RPM variant with private glibc, ld-linux, libgcc and libstdc++; excluded from default builds')
    args = parser.parse_args(argv)
    if args.list:
        print('\n'.join(TARGETS))
        return 0
    if sys.version_info < (3, 12):
        parser.error('mv2build requires Python 3.12+ (safe tar extraction)')
    explicit_universal = args.chromium_universal or args.chromium_universal_glibc
    selected = list(dict.fromkeys(args.target or ([] if explicit_universal else DEFAULT_TARGETS)))
    if args.chromium_universal and 'chromium-universal' not in selected:
        selected.append('chromium-universal')
    if args.chromium_universal_glibc and 'chromium-universal-glibc' not in selected:
        selected.append('chromium-universal-glibc')
    if not args.dry_run:
        needed = ['tar', 'zstd']
        if any(t in selected for t in ('chromium-arch', 'chromium-universal', 'chromium-universal-glibc')) or any(t.startswith('chrome-win64-') for t in selected):
            needed.append('bsdtar')
        if any(t.startswith('chrome-win64-') for t in selected):
            needed.append('7z')
        if any(t in selected for t in ('chromium-universal', 'chromium-universal-glibc')):
            needed += ['ar', 'xz', 'readelf', 'rpmbuild', 'rpm']
        if 'chromium-universal-glibc' in selected:
            needed.append('patchelf')
        missing = [tool for tool in needed if not shutil.which(tool)]
        if missing:
            parser.error('Install required tools: ' + ', '.join(missing))
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.work_dir:
        args.work_dir = args.work_dir.resolve()
        args.work_dir.mkdir(parents=True, exist_ok=True)
    (args.output / 'logs').mkdir(exist_ok=True)
    counts = {'built': 0, 'skipped': 0, 'resolved': 0, 'failed': 0}
    # Prevent overlapping scheduled runs from publishing to the same directory.
    with open(args.output / '.mv2build.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log('Another builder is already using this output directory.')
            return 1
        for target in selected:
            try:
                if target in ('chromium-universal', 'chromium-universal-glibc'):
                    import mv2universal
                    if target == 'chromium-universal-glibc':
                        import mv2glibc
                        release = mv2glibc.resolve()
                    else:
                        release = mv2universal.resolve()
                    if args.dry_run:
                        log(mv2universal.describe(release))
                        counts['resolved'] += 1
                    else:
                        counts[mv2universal.build(release, args)] += 1
                    continue
                release = resolve(target)
                if args.dry_run:
                    log(f'{target}: {release.version}\n  {release.url}\n  -> {release.filename}')
                    counts['resolved'] += 1
                else:
                    counts[build(release, args)] += 1
            except (BuildError, OSError, ValueError, KeyError, StopIteration, ET.ParseError, tarfile.TarError, zipfile.BadZipFile) as error:
                log(f'FAILED {target}: {error}')
                counts['failed'] += 1
        log('Summary: ' + ', '.join(f'{key}={value}' for key, value in counts.items()))
    return 1 if counts['failed'] else 0


if __name__ == '__main__':
    # The optional universal helper imports this module for the shared builder
    # APIs and exception type; keep one instance when running as a script.
    sys.modules['mv2build'] = sys.modules[__name__]
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log('Interrupted; no incomplete archive was published.')
        raise SystemExit(130)
