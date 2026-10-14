# Linux Chromium MV2 patcher

This project ports the Windows tool's supported Linux workflow to Linux x86-64. Linux uses ELF program headers and file offsets instead of PE sections/RVAs and a live `chrome.dll`; it patches the installed Chromium executable on disk, so no helper stays resident.

The binary rules in `mv2ctl.py` currently have independently validated ELF profiles:

- Arch Chromium 154.0.8037.97 and Chromium 155.0.8059.79 with the same ELF layout, including the impact-checker/startup sites and Linux-specific disable-reason and `UserMayLoad` helpers. The 155 distro build has alternate compiler shapes for two sites; both targets are validated.
- Chrome for testing 155.0.8059.79, 156.0.8078.12 and 157.0.8102.0. The 155/156 layouts include the `UserMayInstall` gate; Canary 157 does not. All three profiles validate the scalar `IsExtensionAffected` path and recognize the content-hash helper as read-only.
- Chromium 158.0.8105.0 centralizes the MV2 impact decision in two `manifest_v2_util::IsExtensionAffected` overloads. Both the extension-object and scalar paths are counted, and their safe return destinations are validated. The profile also preserves the signed-resource hash filter.

`ContentHash::ShouldComputeHashesForResource` is never patched: for signed hashes it intentionally selects only resources with a signed tree-hash root. If an older patch changed this gate, analysis rejects the binary; restore from its verified `.mv2orig` and apply the current patcher again.

Each profile has its own expected site counts and checks branch destinations before editing. Unknown or mixed layouts fail closed. Other builds, including later Canary versions, are not automatically assumed compatible; run `analyze` after each browser update and add a profile only after validating its control flow.

## Requirements

- Linux x86-64, Python 3.10 or newer.
- The Chromium binary and its matching `resources.pak`.
- Root privileges only for replacing a system-installed binary. Profile repair should run as the profile owner.
- Fully close Chromium before `apply`, `restore`, or profile repair.

## Commands

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
