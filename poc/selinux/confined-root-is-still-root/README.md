# Confined Root Is Still Root

Code to support the write-up at [https://linnemanlabs.com/posts/confined-root-is-still-root/](https://linnemanlabs.com/posts/confined-root-is-still-root/)

## Proofs of Concept

| Technique | PoC | Works from |
| --- | --- | --- |
| [PackageKit](https://linnemanlabs.com/posts/confined-root-is-still-root/#packagekit) | [packagekit.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/packagekit.sh) | Any uid-0 daemon reaching the D-Bus fleet (297 confined daemons) |
| [KAuth helpers](https://linnemanlabs.com/posts/confined-root-is-still-root/#19-kde-entry-points) | [kauthclient](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/kauthclient/) | Same fleet on systems with KAuth (KDE) |
| [kpmcore](https://linnemanlabs.com/posts/confined-root-is-still-root/#kpmcore) | [kpmcore.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/kpmcore.sh) | Same fleet, on systems with kpmcore (KDE) |
| [kio.admin](https://linnemanlabs.com/posts/confined-root-is-still-root/#kioadmin) | [kioadmin.py](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/kioadmin.py) | Same fleet, on systems with kio-admin (KDE) |
| [Blivet mount](https://linnemanlabs.com/posts/confined-root-is-still-root/#blivet) | [blivet-mount.py](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/blivet-mount.py) | Same fleet |
| [UDisks overlay](https://linnemanlabs.com/posts/confined-root-is-still-root/#udisks2) | [udisks-overlay.py](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/udisks-overlay.py) | Same fleet on systems with UDisks2 |
| [systemd activation pull](https://linnemanlabs.com/posts/confined-root-is-still-root/#want-link-enable) | [activation-pull.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/activation-pull.sh) | Same fleet, needs eligible pivot service |
| [environment poisoning](https://linnemanlabs.com/posts/confined-root-is-still-root/#env-poisoning) | [env-poison.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/env-poison.sh) | Domains with `system:reload` (31) |
| [sysext overlay](https://linnemanlabs.com/posts/confined-root-is-still-root/#sysext-overlay) | [sysext](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/sysext/) | uid-0 that can create the search dir (206) |
| [UserDatabase](https://linnemanlabs.com/posts/confined-root-is-still-root/#userdatabase) | [varlink-userdatabase.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/varlink-userdatabase.sh) | Any uid-0 daemon reaching the userdb varlink (612) |
| [Repart](https://linnemanlabs.com/posts/confined-root-is-still-root/#repart) | [repart-read.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/repart-read.sh) | Any uid-0 daemon reaching the Repart varlink (586) |
| [startx](https://linnemanlabs.com/posts/confined-root-is-still-root/#startx) | [startx.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/startx.sh) | `logrotate_t`, `NetworkManager_t` (+ startx installed) |

## Supporting Tools

Tools to support the above PoCs.

| Tool | Purpose |
| --- | --- |
| [cold-activatable-services.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/cold-activatable-services.sh) | Enumerate what systemd units a confined daemon can reach over D-Bus to activate. Used when creating new systemd units (link our unit as a dependency) or for the environment poisoning technique. |

Use the cold-activatable-services.sh to enumerate what services the confined domain can pivot to. I baked several in that work from bluetooth_t on Fedora that should be relatively portable, but enumerate them yourself if none work on your system.

## Notes

Read and understand the scripts before you run them. Disposable VMs are recommended.

Most are not destructive. They may leave suid binaries, cron jobs, fstab entries, crafted images, overlay mounts, systemd unit dependencies, etc. Some replace existing files like /etc/cron.d/0hourly or leave entries in  your /etc/fstab. 

If writing to a namespaced mount reachable from init's view, like a PrivateTmp location, stage the file yourself and pass the full init mount path to the file - e.g. /tmp/systemd-private-deadbeef-x.service-xyz/tmp/x.unit. You can retrieve that full path from /proc/self/mountinfo. Run the cmds from the script manually in that case. May update scripts in the future to support that.
