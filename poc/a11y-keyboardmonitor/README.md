# a11y-keyboardmonitor

Unprivileged keylogging on Wayland via the D-Bus accessibility KeyboardMonitor interface.

Confirmed on KDE Plasma / KWin 6.3.90+ and GNOME / Mutter 48.0+.

Full writeup: [Hello, my name is Orca](https://linnemanlabs.com/posts/hello-my-name-is-orca/)

## Contents

- [a11y-keyboardmonitor-poc.py](a11y-keyboardmonitor-poc.py) - Standalone PoC. Claims the Orca bus name, calls WatchKeyboard, prints captured keystrokes.
- [eclipse-plugin/](eclipse-plugin/) - Eclipse IDE plugin PoC demonstrating host keylogging from inside a Flatpak sandbox.

## Quick test

```bash
python3 a11y-keyboardmonitor-poc.py
```

Type in any window. Keystrokes appear in the terminal. Ctrl+C to stop.
