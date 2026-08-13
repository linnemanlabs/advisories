#!/usr/bin/env bash
#
# LinnemanLabs - build minimal KAuth KF6 client (KDE helpers)
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# Needs: kf6-kauth-devel kf6-kcoreaddons-devel qt6-qtbase-devel extra-cmake-modules gcc-c++
#
set -e
cd "$( dirname "$0" )"
KFINC=$( ls -d /usr/include/KF6/*/ 2>/dev/null | sed 's/^/-I/' | tr '\n' ' ' )
QTC=$( pkg-config --cflags Qt6Core Qt6DBus );QTL=$(pkg-config --libs Qt6Core Qt6DBus )
g++ -fPIC -std=c++17 main.cpp -o kauthclient $QTC -I/usr/include/KF6 $KFINC $QTL -lKF6AuthCore -lKF6CoreAddons
echo "built ./kauthclient - to run from a confined uid0 domain, label it bin_t (sudo chcon -t bin_t kauthclient)"
