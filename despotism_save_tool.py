#!/usr/bin/env python3
"""
Usage :
  python despotism_save_tool.py decrypt gamesave_XXXX.dat out.json
  python despotism_save_tool.py encrypt out.json gamesave_XXXX.dat
"""
import sys, os, json, base64, hashlib
PW = "path=basePath+.dat;"

def _xt(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a
def _mul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = _xt(a); b >>= 1
    return r
SBOX = [0]*256; INV = [0]*256
def _init():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff
        if q & 0x80: q ^= 0x09
        x = (q ^ ((q<<1|q>>7)&0xff) ^ ((q<<2|q>>6)&0xff) ^ ((q<<3|q>>5)&0xff) ^ ((q<<4|q>>4)&0xff) ^ 0x63) & 0xff
        SBOX[p] = x; INV[x] = p
        if p == 1: break
    SBOX[0] = 0x63; INV[0x63] = 0
_init()
NB = 8; NK = 8; NR = 14; SHIFT = (0, 1, 3, 4)
M = {k: [_mul(i, k) for i in range(256)] for k in (2, 3, 9, 11, 13, 14)}

def expand(key):
    w = [list(key[4*i:4*i+4]) for i in range(NK)]; rc = 1
    for i in range(NK, NB*(NR+1)):
        t = list(w[i-1])
        if i % NK == 0:
            t = [SBOX[b] for b in t[1:]+t[:1]]; t[0] ^= rc; rc = _xt(rc)
        elif i % NK == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-NK][j] ^ t[j] for j in range(4)])
    return [sum(w[r*NB:(r+1)*NB], []) for r in range(NR+1)]

def _add(s, k): return [a ^ b for a, b in zip(s, k)]
def _shift(s):
    o = [0]*32
    for c in range(NB):
        for r in range(4): o[c*4+r] = s[((c+SHIFT[r]) % NB)*4+r]
    return o
def _ishift(s):
    o = [0]*32
    for c in range(NB):
        for r in range(4): o[((c+SHIFT[r]) % NB)*4+r] = s[c*4+r]
    return o
def _mix(s):
    o = []
    for c in range(NB):
        a = s[c*4:c*4+4]
        o += [M[2][a[0]]^M[3][a[1]]^a[2]^a[3], a[0]^M[2][a[1]]^M[3][a[2]]^a[3],
              a[0]^a[1]^M[2][a[2]]^M[3][a[3]], M[3][a[0]]^a[1]^a[2]^M[2][a[3]]]
    return o
def _imix(s):
    o = []
    for c in range(NB):
        a = s[c*4:c*4+4]
        o += [M[14][a[0]]^M[11][a[1]]^M[13][a[2]]^M[9][a[3]], M[9][a[0]]^M[14][a[1]]^M[11][a[2]]^M[13][a[3]],
              M[13][a[0]]^M[9][a[1]]^M[14][a[2]]^M[11][a[3]], M[11][a[0]]^M[13][a[1]]^M[9][a[2]]^M[14][a[3]]]
    return o
def enc_block(b, rk):
    s = _add(list(b), rk[0])
    for r in range(1, NR): s = _add(_mix(_shift([SBOX[x] for x in s])), rk[r])
    return bytes(_add(_shift([SBOX[x] for x in s]), rk[NR]))
def dec_block(b, rk):
    s = _add(list(b), rk[NR])
    for r in range(NR-1, 0, -1): s = _imix(_add([INV[x] for x in _ishift(s)], rk[r]))
    return bytes(_add([INV[x] for x in _ishift(s)], rk[0]))

def _key(salt): return hashlib.pbkdf2_hmac("sha1", PW.encode(), salt, 1000, 32)

def decrypt(b64):
    raw = base64.b64decode(b64); salt, iv, ct = raw[:32], raw[32:64], raw[64:]
    rk = expand(_key(salt)); out = b""; prev = iv
    for i in range(0, len(ct), 32):
        blk = ct[i:i+32]; out += bytes(a ^ b for a, b in zip(dec_block(blk, rk), prev)); prev = blk
    n = out[-1]
    if not 1 <= n <= 32 or out[-n:] != bytes([n])*n: raise ValueError("padding invalide")
    return out[:-n]

def encrypt(plain):
    salt, iv = os.urandom(32), os.urandom(32)
    rk = expand(_key(salt)); pad = 32 - len(plain) % 32; plain += bytes([pad])*pad
    out = b""; prev = iv
    for i in range(0, len(plain), 32):
        prev = enc_block(bytes(a ^ b for a, b in zip(plain[i:i+32], prev)), rk); out += prev
    return base64.b64encode(salt + iv + out)

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("decrypt", "encrypt"):
        sys.exit(__doc__)
    cmd, src, dst = sys.argv[1:]
    data = open(src, "rb").read().strip()
    if cmd == "decrypt":
        j = json.loads(decrypt(data).decode("utf-8"))
        open(dst, "w", encoding="utf-8").write(json.dumps(j, indent=1, ensure_ascii=False))
    else:
        j = json.loads(data.decode("utf-8"))   # vérifie que le JSON est valide
        open(dst, "wb").write(encrypt(json.dumps(j, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    print("OK:", dst)
