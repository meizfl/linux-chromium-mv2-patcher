"""Opt-in Chromium native packages with a private C/C++ runtime.

The browser, glibc/ld-linux, GCC runtime and Mesa/application libraries all
come from the same checksum-verified Debian 12 repositories.
No runtime library is installed into system library directories.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import struct

import mv2build as b
import mv2universal as u

NAME = 'chromium-universal-glibc'
CORE_NAMES = ('libc6', 'libgcc-s1', 'libstdc++6')
PRIVATE_PACKAGING_REVISION = 5
CORE_FILES = ('ld-linux-x86-64.so.2', 'libc.so.6', 'libgcc_s.so.1', 'libstdc++.so.6')
BUNDLED_GRAPHICS = ('libudev1', 'libgl1', 'libegl1', 'libglx0', 'libglvnd0', 'libgles2')
GRAPHICS_FILES = ('libudev.so.1', 'libGL.so.1', 'libEGL.so.1', 'libGLX.so.0', 'libGLdispatch.so.0', 'libGLESv2.so.2')
WAYLAND_FILES = ('libwayland-client.so.0', 'libwayland-server.so.0', 'libwayland-cursor.so.0', 'libwayland-egl.so.1')
# Keep NSS and its NSPR dependency family together. An existing SONAME does not
# imply that an old host library exports Chromium's required symbol versions.
COMPAT_FILES = ('libnss3.so', 'libsmime3.so', 'libssl3.so', 'libnssutil3.so',
                'libnspr4.so', 'libplc4.so', 'libplds4.so', 'libz.so.1', 'libdbus-1.so.3')
NSS_MODULES = ('libnssckbi.so', 'libnssdbm3.so', 'libsoftokn3.so', 'libfreebl3.so', 'libfreeblpriv3.so')
SYSTEM_DIRS = ('/usr/lib/x86_64-linux-gnu', '/lib/x86_64-linux-gnu', '/usr/lib64', '/lib64', '/usr/lib', '/lib')


RUNTIME_ROOTS = (*CORE_NAMES, *BUNDLED_GRAPHICS, 'libgbm1', 'libegl-mesa0',
                 'libglx-mesa0', 'libglapi-mesa', 'libgl1-mesa-dri', 'mesa-libgallium',
                 'libpci3', 'libva2', 'libva-drm2', 'libva-x11-2', 'libvulkan1')
BACKPORT_REPOS = (('https://deb.debian.org/debian/', 'bookworm-backports'),)


def resolve():
    release = u.resolve(bundled_host_packages=RUNTIME_ROOTS, bundle_hardware=True, extra_repos=BACKPORT_REPOS)
    packages = {p['name']: p for p in release['packages']}
    try:
        runtime = [packages[name] for name in CORE_NAMES]
        mesa = packages['libegl-mesa0']
    except KeyError as error:
        raise b.BuildError(f'Debian 12 runtime source missing: {error.args[0]}') from error
    if runtime[1]['version'] != runtime[2]['version']:
        raise b.BuildError('Debian libgcc-s1 and libstdc++6 are not from the same GCC build')
    def component(value):
        return re.sub(r'[^A-Za-z0-9.]', '.', value)
    release.update(name=NAME, runtime=runtime, bundled_graphics=list(BUNDLED_GRAPHICS), bundled_mesa=True)
    # Version the private packaging separately; switching back to Debian glibc
    # must still upgrade packages that previously used a higher Arch glibc.
    release['revision'] = str(PRIVATE_PACKAGING_REVISION) + '.' + release['revision'].split('.', 1)[1]
    release['revision'] += '.glibc' + component(runtime[0]['version']) + '.gcc' + component(runtime[1]['version'])
    release['revision'] += '.mesa' + component(mesa['version'])
    return release


def prepare_payload(release, work):
    if release.get('name') != NAME or {p['name'] for p in release['runtime']} != set(CORE_NAMES):
        raise b.BuildError('The glibc variant requires Debian libc6, libgcc-s1 and libstdc++6 sources')
    packages = {p['name']: p for p in release['packages']}
    if any(packages.get(p['name']) != p for p in release['runtime']):
        raise b.BuildError('Private core runtime must come from the same Debian 12 source set')
    root, binary = u.prepare_payload(release, work)
    runtime = binary.parent / 'runtime'
    missing = [name for name in CORE_FILES if not (runtime / name).is_file()]
    if missing:
        raise b.BuildError('Private runtime is incomplete: ' + ', '.join(missing))
    required = (*GRAPHICS_FILES, 'libgbm.so.1', 'libEGL_mesa.so.0', 'libGLX_mesa.so.0', 'libfreetype.so.6', 'libharfbuzz.so.0')
    missing = [name for name in required if not (binary.parent / 'lib' / name).is_file()]
    if missing or not any(path.is_file() for path in (binary.parent / 'lib/dri').glob('*_dri.so')):
        raise b.BuildError('Private Debian graphics/font runtime is incomplete: ' + ', '.join(missing))
    # The vendor library basename is resolved through our private ELF RPATH.
    u.write_file(binary.parent / 'egl_vendor.d/50_mesa.json', json.dumps({
        'file_format_version': '1.0.0', 'ICD': {'library_path': 'libEGL_mesa.so.0'}}, indent=2) + '\n')
    u.write_file(root / 'usr/share/doc' / NAME / 'runtime-sources.json', json.dumps(release['runtime'], indent=2) + '\n')
    return root, binary


def has_interpreter(path):
    """Recognize PT_INTERP in ELF64 without executing the binary."""
    with open(path, 'rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
            return False
        offset = struct.unpack_from('<Q', header, 32)[0]
        size, count = struct.unpack_from('<HH', header, 54)
        if size < 4 or count > 4096:
            raise b.BuildError(f'Invalid ELF program headers: {path}')
        for index in range(count):
            stream.seek(offset + size * index)
            data = stream.read(4)
            if len(data) != 4:
                raise b.BuildError(f'Truncated ELF program headers: {path}')
            if struct.unpack('<I', data)[0] == 3:
                return True
    return False


def runtime_paths(name=NAME):
    home = '/opt/' + name
    interpreter = home + '/runtime/ld-linux-x86-64.so.2'
    # RPATH applies transitively and is local to these ELF images. Exporting
    # private libc through LD_LIBRARY_PATH would break host programs launched
    # by Chromium. Absolute paths also work for the root-owned setuid helper.
    # Prefer the entire bundled application ABI, not individual libraries only:
    # an old host FreeType/GLib/etc. can otherwise intercept a newer dependency.
    rpath = ':'.join((home + '/runtime', home + '/compat', home + '/lib', home, *SYSTEM_DIRS))
    return interpreter, rpath


def library_dependencies(path):
    with path.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise b.BuildError(f'Private compatibility library is not ELF: {path}')
    dynamic = b.run(['readelf', '-d', path]).decode(errors='replace')
    return re.findall(r'\(NEEDED\).*\[([^]]+)\]', dynamic)


def prepare_compat(browser):
    """Record the pinned browser support dependency closure."""
    missing = [name for name in COMPAT_FILES if not (browser / 'lib' / name).is_file()]
    if missing:
        raise b.BuildError('Private compatibility libraries are incomplete: ' + ', '.join(missing))
    compat = browser / 'compat'
    compat.mkdir(exist_ok=True)
    selected = [*COMPAT_FILES, *(name for name in NSS_MODULES if (browser / 'lib' / name).is_file())]
    # A pinned library must not pick an incompatible host dependency. Resolve the
    # complete DT_NEEDED closure from verified payload files, including libdbus ->
    # libsystemd -> libgcrypt -> libgpg-error and compression dependencies.
    seen = set(selected)
    for name in selected:
        for dependency in library_dependencies(browser / 'lib' / name):
            b.safe_name(dependency)
            if dependency in seen or (browser / 'runtime' / dependency).is_file():
                continue
            if (browser / 'lib' / dependency).is_file():
                seen.add(dependency)
                selected.append(dependency)
    for name in selected:
        link = compat / name
        target = Path('../lib') / name
        if link.is_symlink() and link.readlink() == target:
            continue
        if link.exists() or link.is_symlink():
            raise b.BuildError(f'Conflicting private compatibility library: {name}')
        link.symlink_to(target)
    return selected


def finalize_payload(root, binary, release):
    if release.get('name') != NAME:
        raise b.BuildError('Refusing to rewrite runtime paths in the regular universal variant')
    interpreter, rpath = runtime_paths()
    compatibility = prepare_compat(binary.parent)
    runtime = binary.parent / 'runtime'
    changed = []
    for path in binary.parent.rglob('*'):
        if not path.is_file() or path.is_symlink() or runtime in path.parents:
            continue
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        command = ['patchelf', '--force-rpath', '--set-rpath', rpath]
        executable = has_interpreter(path)
        if executable:
            command += ['--set-interpreter', interpreter]
        command.append(path)
        mode = path.stat().st_mode & 0o7777
        b.run(command)
        path.chmod(mode)
        if b.run(['patchelf', '--print-rpath', path]).decode().strip() != rpath:
            raise b.BuildError(f'Private runtime RPATH verification failed: {path}')
        if executable and b.run(['patchelf', '--print-interpreter', path]).decode().strip() != interpreter:
            raise b.BuildError(f'Private interpreter verification failed: {path}')
        changed.append(str(path.relative_to(binary.parent)))
    if 'chromium' not in changed or 'chrome-sandbox' not in changed:
        raise b.BuildError('Browser and sandbox must both use the private interpreter')
    import mv2ctl
    if mv2ctl.analyze(binary, verbose=False, with_discovery=False)[1] != 'patched':
        raise b.BuildError('MV2 verification failed after rewriting the ELF runtime paths')
    u.write_file(root / 'usr/share/doc' / NAME / 'runtime-layout.json', json.dumps({
        'interpreter': interpreter, 'rpath': rpath, 'rewritten_elf_files': changed,
        'compatibility_libraries': compatibility,
        'core_sha256': {name: b.sha256(runtime / name) for name in CORE_FILES},
    }, indent=2) + '\n')
