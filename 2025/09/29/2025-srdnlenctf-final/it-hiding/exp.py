from sage.all import *
from pwn import *
from Crypto.Util.number import *
from fastecdsa import point, curve
import hashlib, secrets

W25519 = curve.W25519
Point = point.Point

p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
K = GF(p)
A = K(0x76d06)
B = K(0x01)
E = EllipticCurve(K, ((3 - A**2)/(3 * B**2), (2 * A**3 - 9 * A)/(27 * B**3)))
def to_weierstrass(A, B, x, y):
    return (x/B + A/(3*B), y/B)
def to_montgomery(A, B, u, v):
    return (B * (u - A/(3*B)), B*v)
G = E(*to_weierstrass(A, B, K(0x09), K(0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)))
E.set_order(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed * 0x08)


challenge = lambda R, P: hashlib.sha256(str(R).encode() + str(P).encode()).digest()
B = E.gens()[0] * W25519.q * 4
B = point.Point(int(B.xy()[0]), int(B.xy()[1]), W25519)
G = W25519.G
for _ in range(100):
    z = secrets.randbelow(W25519.q - 1)
    R = z*G
    c = int(int.from_bytes(challenge(R, B), "big") % W25519.q)
    if c % 2 == 0:
        break

# io = remote("hiding.challs.srdnlen.it", "443", ssl=True)
io = process(["python3", "task.py"])
io.sendlineafter(b"Enter your base (x y): ", f"{B.x} {B.y}".encode())
io.sendlineafter(b"Enter your Schnorr proof (z c): ", f"{z} {c}".encode())


for _ in range(32):
    io.recvuntil(b"Randomized commitment: ")
    C = eval(io.recvline().decode().strip())
    C = E(C[0], C[1])

    guess = int(C.order() % 2 == 0)
    io.sendlineafter(b"Guess (0 or 1): ", str(guess).encode())
io.interactive()