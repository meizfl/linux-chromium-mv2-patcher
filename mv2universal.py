"""Debian 12 Chromium repackaging for mv2build --chromium-universal.

Build native packages without installing software or running upstream maintainer
scripts. Browser and private libraries come only from Bookworm repositories.
"""
from __future__ import annotations

from functools import cmp_to_key
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile
import time

import mv2build as b

REPOS = (
    ('https://deb.debian.org/debian/', 'bookworm'),
    ('https://deb.debian.org/debian/', 'bookworm-updates'),
    ('https://security.debian.org/debian-security/', 'bookworm-security'),
)
NAME = 'chromium-universal'
PACKAGING_REVISION = 4
# glibc and the hardware-facing graphics/device stack must come from the host.
HOST_PACKAGES = {'libc6', 'libc-bin', 'libgcc-s1', 'libstdc++6', 'libgbm1', 'libudev1',
                 'libgl1', 'libegl1', 'libglx0', 'libglvnd0', 'libgles2', 'libvulkan1',
                 'libglapi-mesa', 'libegl-mesa0', 'libglx-mesa0'}


def version_compare(left, right):
    """Debian epoch/upstream/revision ordering, including tilde and digit runs."""
    def split(value):
        epoch, separator, rest = value.partition(':')
        if not separator:
            epoch, rest = '0', value
        upstream, separator, revision = rest.rpartition('-')
        return int(epoch), upstream if separator else rest, revision if separator else '0'
    def order(char):
        return -1 if char == '~' else 0 if not char else ord(char) if char.isalpha() else ord(char) + 256
    def compare(a, c):
        while a or c:
            while (a and not a[0].isdigit()) or (c and not c[0].isdigit()):
                x = a[0] if a and not a[0].isdigit() else ''
                y = c[0] if c and not c[0].isdigit() else ''
                if order(x) != order(y):
                    return 1 if order(x) > order(y) else -1
                if x: a = a[1:]
                if y: c = c[1:]
            ma, mc = re.match(r'\d*', a)[0], re.match(r'\d*', c)[0]
            da, dc = ma.lstrip('0'), mc.lstrip('0')
            if len(da) != len(dc):
                return 1 if len(da) > len(dc) else -1
            if da != dc:
                return 1 if da > dc else -1
            a, c = a[len(ma):], c[len(mc):]
        return 0
    a, c = split(left), split(right)
    if a[0] != c[0]:
        return 1 if a[0] > c[0] else -1
    return compare(a[1], c[1]) or compare(a[2], c[2])


def parse_index(text):
    for paragraph in text.split('\n\n'):
        fields, key = {}, None
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')) and key:
                fields[key] += ' ' + line.strip()
            elif ': ' in line:
                key, value = line.split(': ', 1)
                fields[key] = value
        if fields.get('Architecture') in ('amd64', 'all') and 'SHA256' in fields:
            yield fields


def resolve(*, bundled_host_packages=(), bundle_hardware=False, extra_repos=()):
    host_packages = HOST_PACKAGES.difference(bundled_host_packages)
    index = {}
    for base, suite in (*REPOS, *extra_repos):
        b.log(f'RESOLVE {NAME}: {suite}')
        url = f'{base}dists/{suite}/main/binary-amd64/Packages.xz'
        for fields in parse_index(lzma.decompress(b.metadata(url)).decode()):
            fields = dict(fields, URL=base + fields['Filename'], Suite=suite)
            index.setdefault(fields['Package'], []).append(fields)
    def latest(name, version=None):
        candidates = [p for p in index.get(name, []) if version is None or p['Version'] == version]
        if not candidates:
            raise b.BuildError(f'Debian 12 package unavailable: {name}' + (f' = {version}' if version else ''))
        return max(candidates, key=cmp_to_key(lambda x, y: version_compare(x['Version'], y['Version'])))
    browser = latest('chromium')
    version = browser['Version']
    selected = {name: latest(name, version) for name in ('chromium', 'chromium-common', 'chromium-sandbox')}
    for name in bundled_host_packages:
        selected[name] = latest(name)
    if any(p['Version'] == version for p in index.get('chromium-l10n', [])):
        selected['chromium-l10n'] = latest('chromium-l10n', version)
    # Bundle the library dependency closure, never a random set from the build host.
    pending = list(selected.values())
    while pending:
        package = pending.pop()
        for group in (package.get('Pre-Depends', '') + ',' + package.get('Depends', '')).split(','):
            alternatives = [re.match(r'\s*([a-z0-9][a-z0-9+.-]*)(?::\w+)?(?:\s*\((>=|<=|=|>>|<<)\s*([^ )]+)\))?', alt)
                            for alt in group.split('|')]
            choices = [m for m in alternatives if m and m[1] in index]
            if not choices:
                continue
            match = choices[0]
            name, operator, minimum = match.groups()
            if name in host_packages or (name.startswith('libdrm') and not bundle_hardware):
                continue
            if name in selected or not (name.startswith('lib') or name == 'zlib1g'):
                continue
            candidate = latest(name, minimum if operator == '=' else None)
            if operator and operator != '=':
                relation = version_compare(candidate['Version'], minimum)
                if not {'>=': relation >= 0, '<=': relation <= 0, '>>': relation > 0, '<<': relation < 0}[operator]:
                    raise b.BuildError(f'Unsatisfied Debian library dependency: {group}')
            selected[name] = candidate
            pending.append(candidate)
    packages = [{'name': name, 'version': p['Version'], 'url': p['URL'], 'sha256': p['SHA256'],
                 'suite': p['Suite']} for name, p in sorted(selected.items())]
    upstream = version.split(':')[-1].split('-')[0]
    b.safe_name(upstream)
    # Preserve Debian rebuild/security revision in native package versions.
    revision = re.sub(r'[^a-zA-Z0-9.]', '.', version.split('-', 1)[1])
    return {'version': version, 'upstream': upstream, 'revision': f'{PACKAGING_REVISION}.' + revision, 'packages': packages}


def filenames(release):
    name = release.get('name', NAME)
    v, r = release['upstream'], release['revision']
    return (f'{name}-{v}-{r}-x86_64.pkg.tar.zst',
            f'{name}_{v}-{r}_amd64.deb', f'{name}-{v}-{r}.x86_64.rpm')


def describe(release):
    name = release.get('name', NAME)
    runtime = [*release.get('runtime', []), *release.get('desktop_runtime', [])]
    details = '\n'.join(f"  runtime: {p['name']} {p['version']}" for p in runtime)
    return (f"{name}: Debian 12 {release['version']} ({len(release['packages'])} source packages)\n"
            + (details + '\n' if details else '')
            + '\n'.join('  -> ' + name for name in filenames(release)))


def select_member(member):
    path = member.name.removeprefix('./')
    if not member.isfile():
        return (member.islnk() or member.issym()) and path.startswith(('lib/', 'usr/lib/')) and '/dri/' in path
    return (path.startswith('usr/lib/chromium/') or
            (path.startswith(('lib/', 'usr/lib/')) and ('.so' in Path(path).name or '/gconv/' in path or path.startswith('usr/lib/locale/'))) or
            (path.startswith('usr/share/doc/') and path.endswith('/copyright')) or
            path.startswith('usr/share/icons/'))


def copy_library(source, destination):
    with source.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            return
    target = destination / source.name
    if target.exists() and b.sha256(target) != b.sha256(source):
        raise b.BuildError(f'Conflicting private library: {source.name}')
    shutil.copy2(source, target)
    dynamic = b.run(['readelf', '-d', source]).decode(errors='replace')
    match = re.search(r'\(SONAME\).*\[([^]]+)\]', dynamic)
    if match and match[1] != source.name:
        soname = b.safe_name(match[1])
        alias = destination / soname
        if alias.is_symlink() and alias.readlink() == Path(source.name):
            return
        if alias.exists() or alias.is_symlink():
            raise b.BuildError(f'Conflicting private SONAME: {soname}')
        alias.symlink_to(source.name)


def write_file(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def launcher_script(browser_home='/opt/chromium-universal', name=NAME, bundled_glibc=False):
    body = '''
# Prefer the native desktop/driver ABI. Debian libraries only fill missing
# SONAMEs (e.g. older codecs); loading private GLib/Wayland/XCB first breaks
# system Mesa drivers and prevents GIO from finding the native dconf backend.
SYSTEM_LIBRARY_PATH=
for library_dir in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu /usr/lib64 /lib64 /usr/lib /lib; do
    if [ -d "$library_dir" ]; then
        SYSTEM_LIBRARY_PATH="${SYSTEM_LIBRARY_PATH:+$SYSTEM_LIBRARY_PATH:}$library_dir"
    fi
done
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}${SYSTEM_LIBRARY_PATH:+$SYSTEM_LIBRARY_PATH:}$CHROMIUM_HOME/lib"
export CHROME_DEVEL_SANDBOX="$CHROMIUM_HOME/chrome-sandbox"
export CHROME_WRAPPER=/usr/bin/chromium-universal
# Match both Wayland app_id and X11 WM_CLASS to our installed desktop entry.
export CHROME_DESKTOP=chromium-universal.desktop
# User-supplied OAuth defaults. Preserve explicit overrides, including empty
# values used to opt out. These are runtime settings, not binary patch sites.
export GOOGLE_DEFAULT_CLIENT_ID="${GOOGLE_DEFAULT_CLIENT_ID-77185425430.apps.googleusercontent.com}"
export GOOGLE_DEFAULT_CLIENT_SECRET="${GOOGLE_DEFAULT_CLIENT_SECRET-OTJgUOQcT7lO7GsGZq2G4IlT}"
exec "$CHROMIUM_HOME/chromium" --user-data-dir="${XDG_CONFIG_HOME:-$HOME/.config}/chromium-universal" --class=chromium-universal "$@"
'''
    if bundled_glibc:
        body = body.replace('export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}${SYSTEM_LIBRARY_PATH:+$SYSTEM_LIBRARY_PATH:}$CHROMIUM_HOME/lib"',
                            '# Private core libraries are selected by ELF interpreter/RPATH, not\n'
                            '# inherited by unrelated programs launched from this browser.\n'
                            'unset LD_LIBRARY_PATH\n'
                            'export GCONV_PATH="$CHROMIUM_HOME/runtime/gconv"\n'
                            'export LIBGL_DRIVERS_PATH="${LIBGL_DRIVERS_PATH-$CHROMIUM_HOME/lib/dri}"\n'
                            'export __EGL_VENDOR_LIBRARY_FILENAMES="${__EGL_VENDOR_LIBRARY_FILENAMES-$CHROMIUM_HOME/egl_vendor.d/50_mesa.json}"')
    return '#!/bin/sh\nCHROMIUM_HOME=' + shlex.quote(str(browser_home)) + body.replace(NAME, name)


def desktop_entry(name=NAME):
    entry = '''[Desktop Entry]
Type=Application
Name=Chromium Universal (MV2)
Comment=Chromium with the verified Manifest V2 patch
Exec=/usr/bin/chromium-universal %U
Icon=chromium-universal
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;
StartupWMClass=chromium-universal
StartupNotify=true
'''
    if name != NAME:
        entry = entry.replace('Name=Chromium Universal (MV2)', 'Name=Chromium Universal glibc (MV2)')
    return entry.replace(NAME, name)


def prepare_payload(release, work):
    name = release.get('name', NAME)
    root = work / 'payload'
    browser = root / 'opt' / name
    libraries = browser / 'lib'
    libraries.mkdir(parents=True)
    core_names = {p['name'] for p in release.get('runtime', [])}
    runtime = browser / 'runtime'
    if core_names:
        runtime.mkdir()
    source_files = []
    for package in release['packages']:
        b.log(f"DOWNLOAD {name}: {package['name']} {package['version']}")
        package_work = work / package['name']
        package_work.mkdir()
        source = package_work / 'download.deb'
        b.fetch(package['url'], destination=source)
        if b.sha256(source) != package['sha256']:
            raise b.BuildError(f"Upstream SHA256 mismatch: {package['name']}")
        extracted = package_work / 'unpacked'
        extracted.mkdir()
        b.extract_deb(source, extracted, package_work, browser_only=False, selector=select_member)
        browser_source = extracted / 'usr/lib/chromium'
        if browser_source.is_dir():
            shutil.copytree(browser_source, browser, dirs_exist_ok=True)
        for prefix in ('lib', 'usr/lib'):
            directory = extracted / prefix
            if directory.is_dir():
                dri_files = {}
                for library in sorted(directory.rglob('*')):
                    if library.is_symlink() and 'dri' in library.parts:
                        destination = libraries / 'dri'
                        destination.mkdir(exist_ok=True)
                        target = library.readlink()
                        # Mesa backports use DRI aliases into a shared gallium
                        # library supplied by a separate package. Keep those
                        # relative references after flattening the library path.
                        alias = Path(target.name) if target.parent == Path('.') else Path('..') / target.name
                        (destination / library.name).symlink_to(alias)
                        continue
                    if library.is_file() and '.so' in library.name and browser_source not in library.parents:
                        if 'gconv' in library.parts:
                            continue
                        destination = runtime if package['name'] in core_names else libraries
                        if 'dri' in library.parts:
                            destination = libraries / 'dri'
                        destination.mkdir(exist_ok=True)
                        inode = (library.stat().st_dev, library.stat().st_ino)
                        if destination.name == 'dri' and inode in dri_files:
                            (destination / library.name).symlink_to(dri_files[inode])
                        else:
                            copy_library(library, destination)
                            if destination.name == 'dri':
                                dri_files[inode] = library.name
                if package['name'] in core_names:
                    for modules in directory.rglob('gconv'):
                        if modules.is_dir():
                            shutil.copytree(modules, runtime / 'gconv', dirs_exist_ok=True)
                    if (directory / 'locale').is_dir():
                        shutil.copytree(directory / 'locale', runtime / 'locale', dirs_exist_ok=True)
        for copyright_file in extracted.glob('usr/share/doc/*/copyright'):
            target = root / 'usr/share/licenses' / name / copyright_file.parent.name / 'copyright'
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(copyright_file, target)
        for icon in extracted.glob('usr/share/icons/**/chromium.png'):
            relative = icon.relative_to(extracted / 'usr/share/icons').with_name(name + '.png')
            target = root / 'usr/share/icons' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(icon, target)
        source_files.append(package)
        shutil.rmtree(package_work)
    binary = browser / 'chromium'
    if not binary.is_file() or not (browser / 'resources.pak').is_file() or not (browser / 'chrome-sandbox').is_file():
        raise b.BuildError('Debian browser/common/sandbox payload is incomplete')
    (browser / 'chrome-sandbox').chmod(0o4755)
    write_file(root / 'usr/bin' / name, launcher_script('/opt/' + name, name, bool(release.get('runtime'))), 0o755)
    write_file(root / 'usr/share/applications' / (name + '.desktop'), desktop_entry(name))
    write_file(root / 'usr/share/doc' / name / 'sources.json', json.dumps(source_files, indent=2) + '\n')
    return root, binary


def make_deb(root, output, release, work):
    name = release.get('name', NAME)
    core_dependencies = '' if release.get('runtime') else 'libc6 (>= 2.36), libgcc-s1, libstdc++6 (>= 12), '
    graphics_dependencies = '' if release.get('bundled_graphics') else 'libudev1, libgl1, libegl1, '
    gbm_dependencies = '' if release.get('bundled_mesa') else 'libgbm1, '
    control = work / 'deb-control'
    control.mkdir()
    size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink()) // 1024
    write_file(control / 'control', f'''Package: {name}
Version: {release['upstream']}-{release['revision']}
Architecture: amd64
Maintainer: Local MV2 builder <mv2build@localhost>
Section: web
Priority: optional
Installed-Size: {size}
Depends: {core_dependencies}{gbm_dependencies}{graphics_dependencies}ca-certificates, xdg-utils
Description: Debian 12 Chromium with verified MV2 patch and private runtime libraries
 Coexists with the system browser and uses a separate default profile.
''')
    b.run(['tar', '--numeric-owner', '--owner=0', '--group=0', '-czf', work / 'control.tar.gz', '-C', control, '.'])
    b.run(['tar', '--numeric-owner', '--owner=0', '--group=0', '-cJf', work / 'data.tar.xz', '-C', root, '.'])
    (work / 'debian-binary').write_text('2.0\n')
    b.run(['ar', 'rcD', output, 'debian-binary', 'control.tar.gz', 'data.tar.xz'], cwd=work)
    names = b.run(['ar', 't', output]).decode().splitlines()
    if names != ['debian-binary', 'control.tar.gz', 'data.tar.xz']:
        raise b.BuildError('Invalid Debian package envelope')
    if shutil.which('dpkg-deb'):
        b.run(['dpkg-deb', '--info', output])


def make_rpm(root, output, release, work):
    name = release.get('name', NAME)
    core_dependencies = '' if release.get('runtime') else 'glibc >= 2.36, libgcc, libstdc++ >= 12, '
    graphics_dependencies = '' if release.get('bundled_graphics') else 'systemd-libs, libglvnd-glx, libglvnd-egl, '
    gbm_dependencies = '' if release.get('bundled_mesa') else 'mesa-libgbm, '
    top = work / 'rpm'
    top.mkdir()
    (top / 'tmp').mkdir()
    # Disable stripping, debug splitting, shebang rewriting, and host-derived
    # dependencies: these would alter the verified binary/private library payload.
    spec = f'''Name: {name}
Version: {release['upstream']}
Release: {release['revision']}
Summary: Debian 12 Chromium with verified MV2 patch
License: BSD-3-Clause AND LicenseRef-Chromium-Third-Party
URL: https://www.chromium.org/
BuildArch: x86_64
AutoReqProv: no
Requires: {core_dependencies}{gbm_dependencies}{graphics_dependencies}ca-certificates, xdg-utils
%description
Chromium with private Debian 12 runtime libraries and verified MV2 patch.
Uses a separate default profile and coexists with the system browser.
%install
mkdir -p "%{{buildroot}}"
cp -a {shlex.quote(str(root))}/. "%{{buildroot}}/"
%files
%defattr(-,root,root,-)
/opt/{name}
%attr(4755,root,root) /opt/{name}/chrome-sandbox
/usr/bin/{name}
/usr/share/applications/{name}.desktop
/usr/share/icons/hicolor/*/apps/{name}.png
/usr/share/licenses/{name}
/usr/share/doc/{name}
'''
    specfile = work / (name + '.spec')
    specfile.write_text(spec)
    b.run(['rpmbuild', '-bb', '--nodeps', '--target', 'x86_64', '--define', f'_topdir {top}',
           '--define', f'_tmppath {top / "tmp"}',
           '--define', '_rpmformat 4',
           '--define', '_build_id_links none', '--define', '__os_install_post %{nil}',
           '--define', 'debug_package %{nil}', '--define', '_binary_payload w3.xzdio', specfile])
    built = list(top.glob('RPMS/x86_64/*.rpm'))
    if len(built) != 1:
        raise b.BuildError('Expected one RPM output')
    shutil.move(built[0], output)
    b.run(['rpm', '-K', '--nosignature', output])
    b.run(['rpm', '-qip', output])


def make_arch(root, output, release, work):
    name = release.get('name', NAME)
    core_dependencies = '' if release.get('runtime') else 'depend = glibc>=2.36\ndepend = libgcc\ndepend = libstdc++\n'
    graphics_dependencies = '' if release.get('bundled_graphics') else 'depend = libglvnd\ndepend = systemd-libs\n'
    gbm_dependencies = '' if release.get('bundled_mesa') else 'depend = mesa\n'
    archroot = work / 'arch-root'
    shutil.copytree(root, archroot, symlinks=True)
    size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())
    write_file(archroot / '.PKGINFO', f'''pkgname = {name}
pkgbase = {name}
pkgver = {release['upstream']}-{release['revision']}
pkgdesc = Debian 12 Chromium with verified MV2 patch and private runtime
url = https://www.chromium.org/
builddate = {int(time.time())}
packager = Local MV2 builder
size = {size}
arch = x86_64
license = BSD-3-Clause
license = LicenseRef-Chromium-Third-Party
{core_dependencies}{graphics_dependencies}{gbm_dependencies}depend = ca-certificates
depend = xdg-utils
''')
    b.refresh_mtree(archroot)
    b.pack(archroot, output, arch=True)


def build(release, args):
    name = release.get('name', NAME)
    identity = {'release': release, 'builder_sha256': b.builder_fingerprint()}
    names = filenames(release)
    marker = args.output / (name + '.json')
    if not args.force and marker.is_file():
        try:
            saved = json.loads(marker.read_text())
            if (all(saved.get(k) == v for k, v in identity.items()) and
                    all((args.output / n).is_file() and saved['outputs'][n] == b.sha256(args.output / n) for n in names)):
                b.log(f'SKIP {name}: all three packages verified')
                return 'skipped'
        except (OSError, ValueError, KeyError):
            pass
    work = Path(tempfile.mkdtemp(prefix=name + '-', dir=args.work_dir))
    stage = Path(tempfile.mkdtemp(prefix='.' + name + '-', dir=args.output))
    try:
        if release.get('runtime'):
            import mv2glibc
            root, binary = mv2glibc.prepare_payload(release, work)
        else:
            root, binary = prepare_payload(release, work)
        b.patch(binary, args.output / 'logs' / f"{name}-{release['upstream']}.log")
        if release.get('runtime'):
            mv2glibc.finalize_payload(root, binary, release)
        binary_hash = b.sha256(binary)
        for index, (packer, name) in enumerate(zip((make_arch, make_deb, make_rpm), names)):
            b.log(f'PACK {name}')
            package_work = work / f'package-{index}'
            package_work.mkdir()
            try:
                packer(root, stage / name, release, package_work)
            finally:
                # Only one format's temporary payload/compression files are
                # needed at once, particularly when /tmp is RAM-backed.
                shutil.rmtree(package_work)
            if b.sha256(binary) != binary_hash:
                raise b.BuildError('Packaging modified the verified source binary')
        identity.update(binary_sha256=binary_hash, patch_status='patched',
                        outputs={n: b.sha256(stage / n) for n in names})
        (stage / marker.name).write_text(json.dumps(identity, indent=2) + '\n')
        # All formats must succeed before any final output is replaced. The marker
        # is the commit record; a crash during publication causes a rebuild.
        marker.unlink(missing_ok=True)
        for name in names:
            os.replace(stage / name, args.output / name)
            b.log('BUILT ' + str(args.output / name))
        os.replace(stage / marker.name, marker)
        return 'built'
    finally:
        shutil.rmtree(stage)
        if args.keep_work:
            b.log(f'WORK {work}')
        else:
            shutil.rmtree(work)
