from sage.all import *
import os
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Util.number import *


def derive_poly1305_key(key:bytes, nonce:bytes):
    from Crypto.Cipher.ChaCha20 import ChaCha20Cipher
    
    # assert len(key) == 32 and len(nonce) == 12, "The key should be 32 bytes and the nonce should be 12 bytes"
    chacha20_block = ChaCha20Cipher(key, nonce).encrypt(b'\x00'*64)
    return chacha20_block[:32]

def is_valid_r(r):
    # check if r is a valid Poly1305 key
    # from RFC specification: https://datatracker.ietf.org/doc/html/rfc7539#section-2.5
    return (r & 0x0ffffffc0ffffffc0ffffffc0fffffff) == r

key = os.urandom(32)
nonce = os.urandom(24)
aad = bytes(range(16))

def enc(pt):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return tag[-2:]

# keystream recovery
pt = os.urandom(16)
cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
cipher.update(aad)
ct, tag = cipher.encrypt_and_digest(pt)
keystream = bytes([pti ^ cti for pti, cti in zip(pt, ct)])
keystream = b'$' + keystream[1:]


p = 2**130 - 5 # the prime number used in Poly1305

t = 32 # more trials, more success rate
res = list()
for _ in range(t):
    pt = os.urandom(16 - 1)
    l = enc(b'#' + pt)
    res.append((b'#' + pt, l))

As, Bs = list(), list()
for pt, l in res:
    ct = bytes([pti ^ ksi for pti, ksi in zip(pt, keystream)])
    a = int.from_bytes(ct + b'\x01', 'little')
    b = int.from_bytes(l, 'little') * 2**((16-2)*8)
    As.append(a)
    Bs.append(b)
As = [As[i+1] - As[0] for i in range(t-1)]
Bs = [Bs[i+1] - Bs[0] for i in range(t-1)]

m = len(As)
A = matrix(ZZ, 1, m-1)
B = matrix(ZZ, 1, m-1)
C = matrix(ZZ, m-1, m-1)
D = matrix(ZZ, 1, m-1)
for i in range(m-1):
    A0, B0 = As[0], Bs[0]
    Ai, Bi = As[i+1], Bs[i+1]
    A[0, i] = ZZ(Ai*pow(2, 128, p)*inverse_mod(A0, p) % p)
    B[0, i] = ZZ(Ai*inverse_mod(A0, p) % p)
    C[i, i] = ZZ(-pow(2, 128, p))
    D[0, i] = ZZ((Ai*B0 - A0*Bi)*inverse_mod(A0, p) % p)
bounds = [8*2] + [2**112*2] + [8*2]*(m-1) + [2**112*2]*(m-1) + [1]
Q = diagonal_matrix(ZZ, [p**2 // b for b in bounds])
L = block_matrix(ZZ, [
    [1, 0, 0, A, 0],
    [0, 1, 0, B, 0],
    [0, 0, 1, C, 0],
    [0, 0, 0, p, 0],
    [0, 0, 0, D, 1]
])
L = (L*Q).LLL()
L = (L/Q).change_ring(ZZ)
for v in L:
    if abs(v[-1]) == 1:
        E0i = v[-1]*v[0]
        E1i = v[-1]*v[1]
        Ai, Bi = As[0], Bs[0]
        r2 = (Bi + E0i*2**128 + E1i) * inverse_mod(Ai, p) % p
        r = int(GF(p)(r2).sqrt())
        if is_valid_r(r):
            print(f"Found r: {r}")
            break
        r = p - r
        if is_valid_r(r):
            print(f"Found r: {r}")
            break
        


'''
a*r^2 + tt = bb mod p
b = bb - e0*2**128 - e1
a*r^2 + tt = b + e0*2**128 + e1 mod p
e0: 2bit
e1: (16-2)*8 = 112bit
ai*r^2 + tt = bi + ei0*2**128 + ei1 mod p
aj*r^2 + tt = bj + ej0*2**128 + ej1 mod p
->
(ai - aj)*r^2 = bi - bj + (ei0 - ej0)*2**128 + (ei1 - ej1) mod p

A = ai - aj, B = bi - bj
E0 = ei0 - ej0, E1 = ei1 - ej1
->
A*r^2 = B + E0*2**128 + E1 mod p
Ai*r^2 = Bi + E0i*2**128 + E1i mod p
Aj*r^2 = Bj + E0j*2**128 + E1j mod p
->
0 = (Aj*Bi - Ai*Bj) + (Aj*E0i - Ai*E0j)*2**128 + (Aj*E1i - Ai*E1j) mod p
0 = (Aj*Bi - Ai*Bj) + E0i*(Aj*2**128) + E0j*(-Ai*2**128) + E1i*Aj + E1j*(-Ai) mod p
E1j*Ai = (Aj*Bi - Ai*Bj) + E0i*(Aj*2**128) + E0j*(-Ai*2**128) + E1i*Aj mod p
E1j = (Aj*Bi - Ai*Bj)/Ai + E0i*(Aj*2**128/Ai) + E0j*(-2**128) + E1i*(Aj/Ai) mod p
E1j = 
    E0i*(Aj*2**128/Ai) + 
    E1i*(Aj/Ai) + 
    E0j*(-2**128) + 
    (Aj*Bi - Ai*Bj)/Ai 
'''