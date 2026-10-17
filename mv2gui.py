#!/usr/bin/env python3
"""GTK 4 front end for mv2ctl.py. Requires PyGObject with Gtk 4."""
import os
import subprocess
import shlex
import sys
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

HERE = os.path.dirname(os.path.realpath(__file__))
CTL = os.path.join(HERE, "mv2ctl.py")


def detect_browser():
    for candidate in ("/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser",
                      "/opt/google/chrome/chrome", "/usr/bin/chromium", "/usr/bin/google-chrome"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    return ""


class App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.mv2ctl.Launcher")

    def do_activate(self):
        win = Gtk.ApplicationWindow(application=self, title="Chromium MV2 Launcher")
        win.set_default_size(700, 510)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(18); box.set_margin_bottom(18); box.set_margin_start(18); box.set_margin_end(18)
        win.set_child(box)
        box.append(Gtk.Label(label="Linux Chromium Manifest V2 launcher", xalign=0))
        pathrow = Gtk.Box(spacing=8)
        pathrow.append(Gtk.Label(label="Browser binary", xalign=0))
        self.path = Gtk.Entry(); self.path.set_hexpand(True); self.path.set_text(detect_browser())
        pathrow.append(self.path); box.append(pathrow)
        self.args = Gtk.Entry(placeholder_text="Optional Chromium arguments, e.g. --user-data-dir=/path")
        box.append(self.args)
        row = Gtk.Box(spacing=8)
        for label, callback in (("Analyze", self.analyze), ("Apply patch", self.apply_patch),
                                ("Launch patched", self.launch), ("Launch normally", self.launch_normal), ("Install shortcut", self.shortcut),
                                ("Repair profile", self.repair)):
            button = Gtk.Button(label=label); button.connect("clicked", callback); row.append(button)
        box.append(row)
        self.status = Gtk.Label(label="Select a Chromium executable and analyze it.", xalign=0)
        self.status.set_wrap(True); box.append(self.status)
        scroll = Gtk.ScrolledWindow(); scroll.set_vexpand(True)
        self.output = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        scroll.set_child(self.output); box.append(scroll)
        box.append(Gtk.Label(label="Apply changes the executable on disk. Close Chromium first. System binaries require administrator access.", xalign=0))
        win.present()

    def run_ctl(self, command, args=(), elevated=False, done=None):
        binary = self.path.get_text().strip()
        argv = [sys.executable, CTL, command]
        if command != "repair-profile" and binary: argv.append(binary)
        if command == "launch":
            extras = self.args.get_text().strip()
            if extras: argv += ["--", *shlex.split(extras)]
        elif args:
            argv += list(args)
        if elevated and os.geteuid() != 0:
            argv = ["pkexec", *argv]
        def worker():
            try:
                result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
                output = result.stdout or ("Command completed." if result.returncode == 0 else "Command failed.")
                GLib.idle_add(self.show_result, output, done, result.returncode)
            except Exception as error:
                GLib.idle_add(self.show_result, str(error), done, 1)
        threading.Thread(target=worker, daemon=True).start()
        self.status.set_text("Working…")

    def show_result(self, output, done, code):
        self.output.get_buffer().set_text(output)
        self.status.set_text("Completed." if code == 0 else "Failed. See details below.")
        if done: done(code)
        return False

    def analyze(self, *_): self.run_ctl("analyze")
    def apply_patch(self, *_): self.run_ctl("apply", ("--yes",), elevated=True)
    def shortcut(self, *_): self.run_ctl("install-shortcut")
    def repair(self, *_):
        profile = os.path.expanduser("~/.config/chromium/Default")
        self.run_ctl("repair-profile", (profile,))
    def launch_normal(self, *_):
        binary = self.path.get_text().strip()
        if not binary:
            self.status.set_text("Select a browser executable first.")
            return
        argv = [binary, *shlex.split(self.args.get_text().strip())]
        try:
            subprocess.Popen(argv, start_new_session=True)
            self.status.set_text("Normal Chromium launch requested.")
        except Exception as error:
            self.status.set_text(str(error))

    def launch(self, *_):
        binary = self.path.get_text().strip()
        if not binary:
            self.status.set_text("Select a browser executable first.")
            return
        argv = [sys.executable, CTL, "launch", binary]
        extras = self.args.get_text().strip()
        if extras: argv += ["--", *shlex.split(extras)]
        try:
            subprocess.Popen(argv, start_new_session=True)
            self.status.set_text("Chromium launch requested. The launcher verifies the patch before starting it.")
        except Exception as error:
            self.status.set_text(str(error))


if __name__ == "__main__":
    raise SystemExit(App().run(sys.argv))
