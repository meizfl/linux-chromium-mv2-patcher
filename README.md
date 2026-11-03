# Chromium MV2 patcher (Linux patch profiles)

This project ports the Windows tool's supported Linux workflow to Linux x86-64 and recognizes the independently verified Chromium 158 x86-64 Mach-O framework layout. It patches the executable image on disk, so no helper stays resident. The GTK 4 desktop app and CLI share the same fail-closed patcher and profile repair logic.

Binary patching supports the validated Linux x86-64 ELF profiles below, Chromium 158.0.8115.0 x86-64 Mach-O frameworks, and Windows PE x86-64 `chrome.dll` profiles. The Windows Chrome 152/155/157/158 profiles validate the complete family of MV2 gates, including split extension checkers, the integer overload, install/disable/re-enable policy clones, and the startup disable loop. macOS arm64 binaries are identified and rejected before any write because their code layout has not been validated. If a macOS app bundle is signed, modifying its framework invalidates that signature; verify and re-sign it on macOS before launch. The desktop UI currently requires GTK 4 / PyGObject and is Linux-oriented.

The binary rules in `mv2ctl.py` currently have independently validated ELF profiles:

- Arch Chromium 154.0.8037.97 and Chromium 155.0.8059.79 with the same ELF layout, including the impact-checker/startup sites and Linux-specific disable-reason and `UserMayLoad` helpers. The 155 distro build has alternate compiler shapes for two sites; both targets are validated.
- Chromium distro ELF layout from the supplied `chromium-browser` binary: four extension-object checks, one integer checker, manifest gate, `MustRemainDisabled` clone, `UserMayLoad`, and read-only signed-resource hash filter. Its disable-reason call uses an alternate unprefixed `E8` encoding; all branch targets are validated.
- Another Chromium distro ELF layout, identified from `/home/meizfl/Downloads/chromium/chromium`: four extension-object checks, one clear-result path, and the startup disable-list gate. Its profile-ready MV2 metric callback is verified and counted read-only; it is not treated as a `MustRemainDisabled` patch site. `test-apply` verified six unique edits on a separate binary copy.
- Chrome for testing 155.0.8059.79, 156.0.8078.12 and 157.0.8102.0. The 155/156 layouts include the `UserMayInstall` gate; Canary 157 does not. All three profiles validate the scalar `IsExtensionAffected` path and recognize the content-hash helper as read-only.
- Chromium 158.0.8105.0 centralizes the MV2 impact decision in two `manifest_v2_util::IsExtensionAffected` overloads. Both the extension-object and scalar paths are counted, and their safe return destinations are validated. The profile also preserves the signed-resource hash filter.
- Google Chrome for Testing 158.0.8113.0 Linux x86-64 uses a separate ELF layout with two extension-object checks, the `MustRemainDisabled` helper, integer and scalar checks, and the startup version gate. The signed-resource hash filter is recognized as read-only.
- Google Chrome 155.0.8059.79 Linux x86-64 uses an ELF layout with four extension-object checks, the manifest gate, and validated alternate disable-list, `MustRemainDisabled`, and `UserMayLoad` branches. Its startup check shares a branch with one extension-object checker, so that instruction is patched once through the checker profile.
- Windows `chrome.dll` and macOS Intel `Chromium Framework` 158.0.8115.0 each validate the extension-object and scalar `IsExtensionAffected` paths against platform-specific PE/Mach-O instruction layouts and checked return destinations. The arm64 Mac build is not yet supported.
- Google Chrome 152 Windows x86-64 validates the v5 checker and policy-clone family, including a second checker copy with a different register allocation. An on-disk apply and post-write self-check completed on the supplied 297 MB `chrome.dll`.
- Chrome 155 Windows x86-64 validates the full v7/v8 gate family and the resource-8129 unsupported-manifest path. An on-disk apply and post-write self-check completed on Chrome 155.0.8059.85 `chrome.dll`.
- Google Chrome for Testing 157.0.8103.6 Windows x86-64 validates the same gate family with its distinct resource-8130 unsupported-manifest path. An on-disk apply and post-write self-check completed on the supplied `chrome.dll`.
- Google Chrome for Testing 158.0.8113.0, 8116.0, and 8117.2 Windows x86-64 validate the changed extension-version filter, startup disable loop (including the 8116.0 reason-object layout), and their matching unsupported-manifest resource paths. An on-disk apply and post-write self-check completed on the supplied 8113.0 `chrome.dll`.
- Chrome 159.0.8130.0 Windows x86-64 validates the 159 startup-disable reason loop and resource-8331 (`0x208B`) `UserMayInstall` path; its test copy passed post-write analysis.
- Chromium 158.0.8120.0 Windows x86-64 validates the standalone extension-overload and scalar `IsExtensionAffected` checks; both branches were applied and verified on a test copy.
- Google Chrome for Testing 158.0.8106.0 Windows x86-64 validates the extension-overload checker, startup disable branch, and resource-8183 (`0x1FF7`) unsupported-manifest path.
- Google Chrome for Testing 156.0.8078.48 Windows x86-64 validates the same gate family with its resource-8122 (`0x1FBA`) `UserMayInstall` path.

`ContentHash::ShouldComputeHashesForResource` is never patched: for signed hashes it intentionally selects only resources with a signed tree-hash root. If an older patch changed this gate, analysis rejects the binary; restore from its verified `.mv2orig` and apply the current patcher again.

Each profile has its own expected site counts and checks branch destinations before editing. Unknown or mixed layouts fail closed. Other builds, including later Canary versions, are not automatically assumed compatible; run `analyze` after each browser update and add a profile only after validating its control flow.

On an unknown or partly recognized build, `analyze` also runs an instruction-level semantic scan when Capstone is installed (`python3 -m pip install -r requirements.txt`). It searches decoded x86-64 instructions for manifest-version comparisons and nearby MV2 dataflow landmarks while tolerating register allocation and branch-encoding differences. Rejected signature anchors are decoded directly as well, so their control flow and rejection reason remain visible even when a linear sweep loses instruction alignment. These candidates are diagnostic only; applying still requires a validated profile and verified control-flow targets. This keeps unfamiliar distro builds fail-closed while making profile development less dependent on exact byte strings.

The binary signatures and expected site counts are kept in [mv2profiles.py](./mv2profiles.py), separate from the patching logic in `mv2ctl.py`. Add a new build there only after confirming every candidate and branch destination.

## Requirements

- Linux x86-64, Python 3.10 or newer, for binary patching.
- The Chromium binary and its matching `resources.pak`.
- Root privileges only for replacing a system-installed binary. Profile repair should run as the profile owner.
- Fully close Chromium before `apply`, `restore`, or profile repair.
- GTK 4 / PyGObject for the desktop interface; `pkexec` is used to request administrator privileges for system-browser patching.

## Commands

Create a patched test copy and verify it without changing the source binary or creating a backup:

```sh
python3 ./mv2ctl.py test-apply /path/to/chromium
# Or choose an output path:
python3 ./mv2ctl.py test-apply /path/to/chromium --output /tmp/chromium-mv2-test
```

The command requires a fully recognized profile, patches a separate copy, and confirms that the normal analyzer reports it as patched. It does not launch Chromium or verify extension behavior; use the printed copy path for an isolated manual browser test. Unknown or partly recognized builds are refused.

Inspect the installed binary without changing it:

```sh
python3 ./mv2ctl.py analyze /usr/lib/chromium/chromium
```

Patch it and retain an original backup next to the binary:

```sh
sudo python3 ./mv2ctl.py apply /usr/lib/chromium/chromium
```

Repair the persisted MV2-only disabled reason for the default profile, if present:

```sh
python3 ./mv2ctl.py repair-profile
```

For a different profile or resources file:

```sh
python3 ./mv2ctl.py repair-profile \
  "$HOME/.config/chromium/Profile 1" \
  --resources /usr/lib/chromium/resources.pak
```

Launch the patched browser, forwarding optional Chromium arguments after `--`:

```sh
python3 ./mv2ctl.py launch /usr/lib/chromium/chromium -- --user-data-dir="$HOME/.config/chromium-mv2" https://example.org
```

The launcher refuses unknown, original, mixed, or partially patched binaries. Chromium's normal process model reuses an existing session for the same user-data directory.

Check the binary patch state:

```sh
python3 ./mv2ctl.py status /usr/lib/chromium/chromium
```

Restore the original executable from `.mv2orig`:

```sh
sudo python3 ./mv2ctl.py restore /usr/lib/chromium/chromium
```

The profile command edits only the MV2 disable bit (`0x800000`), preserves other disable reasons, validates Chromium's preference HMAC seed against an existing protected entry, and writes a one-time `Secure Preferences.mv2ctl.bak`. It refuses to edit if the seed cannot be verified. Linux Chromium's deterministic device-ID hook is unimplemented in the upstream source used by this build, so the port uses an empty device ID and validates the resulting seed against the profile before changing anything. Linux has no Windows Registry mirror to update.

`status` checks only the executable bytes. After patching, fully exit Chromium and launch it again. Then check the extension toggle and its status at `chrome://extensions`. Chromium package upgrades may replace the patched executable; run `analyze` again after an upgrade. The browser itself remains unmodified upstream, and this local patch may be incompatible with future releases.

## Port notes

The Windows build's in-memory `chrome.dll` patcher, process-memory verification/reuse, consent-bound restart of unrelated browser sessions, and WinUI-specific update installer do not have a direct Linux equivalent in this port. This Linux build follows the project's disk-patch workflow: it validates the ELF binary, atomically installs verified edits, then launches through Chromium normally. It does not terminate or rewrite an already-running process. Profile repair is available as a separate explicit action.

The Windows release feed currently publishes a Windows GUI ZIP; it does not provide a Linux application asset, so the Windows self-updater has no Linux package to install. The Linux source remains directly runnable with the system Python and GTK 4. A functional MV2 extension check should be performed manually with the installed browser version after patching; do not infer compatibility for an unrecognized build.

## Scheduled browser builds (`mv2build.py`)

`mv2build.py` is a separate, non-interactive Linux build script. It resolves the latest
upstream releases, downloads and extracts them without running installers, calls
`mv2ctl.py test-apply`, verifies the patched copy, and publishes a `.tar.zst` only
after successful verification. It never patches an installed browser.

Requirements: Python **3.12+**, GNU `tar`, `zstd`; additionally `7z` and `bsdtar`
for regular Windows Chrome, and `bsdtar` for Arch package metadata. On Arch these
commands are supplied by `tar`, `zstd`, `7zip`, and `libarchive`. On Debian/Ubuntu,
install `tar`, `zstd`, `7zip` (or `p7zip-full`), and `libarchive-tools`.
Keep several GB free for temporary files; targets build sequentially and temporary
files are removed after each target unless `--keep-work` is set.

```sh
# Build every target; output defaults to builds/ beside the script.
python3 ./mv2build.py

# Inspect available targets or current upstream versions without downloading browsers.
python3 ./mv2build.py --list
python3 ./mv2build.py --dry-run

# Select one or several targets.
python3 ./mv2build.py \
  --target chrome-linux-canary \
  --target chromium-arch \
  --target chrome-testing-win64-stable \
  --output /srv/browser-builds
```

Default targets and archive names:

| Builds | Target names | Archive names |
| --- | --- | --- |
| Chrome Linux x64, Stable/Beta/Dev/Canary | `chrome-linux-{channel}` | `chrome-{channel}-{version}.tar.zst` |
| Chrome Windows x64, Stable/Beta/Dev | `chrome-win64-{channel}` | `chrome-win64-{version}-{channel}.tar.zst` |
| Chrome for Testing Linux x64, all four channels | `chrome-testing-linux-{channel}` | `chrome-{channel}-{version}-testing.tar.zst` |
| Chrome for Testing Windows x64, all four channels | `chrome-testing-win64-{channel}` | `chrome-win64-{version}-{channel}-testing.tar.zst` |
| Arch Chromium, newest version from extra/extra-testing | `chromium-arch` | Original name, e.g. `chromium-156.0.8078.79-1-x86_64.pkg.tar.zst` |
| Chromium snapshot Linux x64, latest completed revision | `chromium-snapshot-linux` | `chromium-snapshot-{version}-r{revision}.tar.zst` |

For example: `chrome-canary-159.0.8139.2.tar.zst` and
`chrome-win64-156.0.8078.80-stable-testing.tar.zst`. Windows Testing builds are
included alongside the requested Linux Testing channels. Testing archives have
an explicit suffix to avoid collisions with regular Chrome. Snapshot names
include the revision because several snapshots can share the same browser version.

Chrome Linux downloads come from Google's amd64 DEB repository (Dev is named
`google-chrome-unstable` upstream). Windows Chrome uses the full x64 installer
from Google's Omaha update service. Testing builds use the official
[Chrome for Testing JSON API](https://github.com/GoogleChromeLabs/chrome-for-testing#json-api-endpoints).
Snapshots use `LAST_CHANGE`, `REVISIONS`, and the exact commit's `chrome/VERSION`
from the [official snapshot source](https://www.chromium.org/getting-involved/download-chromium/).
Arch compares numeric package versions, releases, and epochs across both
repositories; a missing extra-testing package is normal. Other repository errors
fail the target rather than silently assuming extra is newer. Arch mirror metadata
must match the selected package before downloading it.

Google DEB, Omaha installer, and Arch downloads are checked against upstream
SHA256 metadata. Testing/snapshot feeds do not supply SHA256 checksums; these
use HTTPS, ZIP CRC validation, and the patcher's binary verification. Each output
gets a `.json` sidecar recording the source URL/version, source and output hashes,
and the builder/patcher fingerprint. A repeat run skips output only when the
metadata, code fingerprint, and archive checksum match. Use `--force` to rebuild.
Replacing an existing archive happens only after a new verified archive is ready.

Linux archives contain the complete browser directory, including resources and
helper programs. Extract and run `chrome` from it; they use the host's system
libraries. Windows archives retain `chrome.exe`, `chrome.dll`, and the rest of
the browser payload. Arch output retains `.PKGINFO`, `.BUILDINFO`, dependencies,
links and package layout, and regenerates `.MTREE` with the patched file hashes
and root ownership. The modified Arch package is unsigned; the upstream package
signature no longer applies. Install it according to your local pacman package
signature policy or sign it with your own trusted key.

Unknown or incompatible binary layouts **fail closed**. Automatic downloading does
not add patch profiles for new browser versions. Failed targets produce no new
archive, log their patch analysis in `builds/logs/`, and do not stop other targets.
The script exits with status **1** if any target failed, **0** otherwise (including
when everything was already built). `--keep-work` preserves downloads/extracted
files for diagnostics; `--work-dir /path` selects a filesystem with enough space.
The output-directory lock prevents overlapping scheduled runs using that directory.

For an unattended run approximately every two days, use a systemd user timer.
Replace the paths below with your absolute checkout and output paths. Do not use
root: downloads and packaging do not require it.

`~/.config/systemd/user/mv2build.service`:

```ini
[Unit]
Description=Download and build patched Chrome/Chromium packages

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /absolute/path/linux-chromium-mv2-patcher/mv2build.py --output /absolute/path/browser-builds
```

`~/.config/systemd/user/mv2build.timer`:

```ini
[Unit]
Description=Build patched browsers every two days

[Timer]
OnStartupSec=5min
OnUnitActiveSec=2d

[Install]
WantedBy=timers.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now mv2build.timer
journalctl --user -u mv2build.service
```

The user timer runs while the user's systemd manager is active; a server can use
the same service/timer as system units with an explicit unprivileged `User=`.
This repository does not install or enable a timer automatically.

Builder regression checks:

```sh
python3 -m unittest discover -s tests -v
```
