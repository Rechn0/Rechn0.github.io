import base64
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import GF
from pwn import *

# initial setup
z0 = GF(2)["z0"].gen()
F, z = GF(2**128, name="z", modulus=z0**128 + z0**7 + z0**2 + z0 + 1).objgen()
h, e0 = F["h", "e0"].gens()

# basic tools
def xor(a, b):
    return bytes([ai^bi for ai, bi in zip(a, b)])

def pad128(pt):
    return pt + b'\x00' * ((16 - len(pt))%16)

def len64(pt):
    return long_to_bytes(len(pt)*8, 8)

def b2gf(b):
    return F(list(bin(bytes_to_long(b))[2:].zfill(128)))

def gf2b(g):
    return long_to_bytes(int(''.join(map(str, g.list())), 2), 16)

def AUTH_CT(auth: bytes, ct: bytes):
    C = pad128(auth) + pad128(ct) + len64(auth) + len64(ct)
    return C


io = process(["python", "server.py"])
io.recvuntil(b"flag ciphertext:  ")
flag_enc = base64.b64decode(io.recvline().strip())
io.recvuntil(b"flag tag:  ")
flag_tag = base64.b64decode(io.recvline().strip())

t = 128
text1 = bytes([0]*(t-1) + [1])
io.sendlineafter(b"your_text1:", text1)
io.recvuntil(b"tag1: ")
tag1 = base64.b64decode(io.recvline().strip())

text2 = bytes([0]*t)
io.sendlineafter(b"your_text2:", text2)
io.recvuntil(b"tag2: ")
tag2 = base64.b64decode(io.recvline().strip())

C1 = AUTH_CT(auth=b"", ct=text1)
C2 = AUTH_CT(auth=b"", ct=text2)
C = xor(C1, C2)
ftag = 0
for i in range(0, len(C), 16):
    Ci = C[i: i+16]
    ftag += b2gf(Ci)
    ftag *= h
ftag -= b2gf(xor(tag1, tag2))
ans = ftag.univariate_polynomial().roots()
H = gf2b(ans[0][0])

C = AUTH_CT(auth=b"", ct=flag_enc)
ftag = 0
for i in range(0, len(C), 16):
    Ci = C[i: i+16]
    ftag += b2gf(Ci)
    ftag *= h
E0 = gf2b(ftag.univariate_polynomial()(b2gf(H)) - b2gf(flag_tag))
print(f"{H = }\n{E0 = }")

prefix = b""
for ind in range(t):
    for ch in range(256):
        C = AUTH_CT(auth=b"\x00"*16, ct=prefix + bytes([ch]))
        ftag = 0
        for i in range(0, len(C), 16):
            if i == 0:
                Ci = h
            else:
                Ci = b2gf(C[i: i+16])
            ftag += Ci
            ftag *= b2gf(H)
        ftag += b2gf(E0) + b2gf(tag2)
        ans = ftag.univariate_polynomial().roots()
        aad = gf2b(ans[0][0])
        io.sendlineafter(b"length:", str(ind+1).encode())
        io.sendlineafter(b"aad: ", base64.b64encode(aad))
        res = eval(io.recvline().strip().decode())
        if res:
            prefix += bytes([ch])
            print(f"{prefix = }")
            flag = xor(flag_enc, prefix)
            print(f"{flag = }")
            break
    else:
        print("no byte found!")
        break

flag = xor(flag_enc, prefix)
print(f"{flag = }")
io.close()
# BHFlagY{338524cd3bfa19a4fc775296945e880b}