from sage.all import *
from Crypto.Util.number import *
from os import urandom
from tqdm import trange
from Crypto.Util.strxor import strxor
from pwn import *

chunk_size = 5

def encrypt(message,priv):
    p,r,H = priv
    assert len(message) % 5 == 0

    message_chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

    ciphertext = b""
    mac = 0
    for chunk in message_chunks:
        temp = strxor(chunk, H)
        mac = (r*(mac + bytes_to_long(temp))) % p
        ciphertext += temp

    return ciphertext, long_to_bytes(mac)

io = process(['sage', '-python', 'server.py'])
# io = remote(*"hell-summon.int.seccon.games 8888".split())
io.recvuntil(b'p=')
p = int(io.recvline().strip().decode())
io.recvuntil(b'messages=')
ms = eval(io.recvline().strip().decode())
ms = [int(_, 16) for _ in ms]
io.recvuntil(b'truncated_macs=')
ys = eval(io.recvline().strip().decode())
ys = [int(_, 16)<<16 for _ in ys]

As, bs, cs = list(), list(), list()
for i in range(42):
    ci = ms[i]
    A = list()
    for j in range(40):
        cij = (ci >> j) & 1
        A.append((1-2*cij)*2**j)
    As.append(A)
    bs.append(ci)
    cs.append(ys[i])

B = matrix(GF(p), As).left_kernel().basis()
L = block_matrix(ZZ, [
    [1, matrix(B)[:,len(B):]],
    [0, p]
]).LLL()
vs = L[:len(B),:]

A = matrix(vs)*vector(bs)
b = -matrix(vs)*vector(cs)

a0, a1 = A
b0, b1 = b
# r*ai + bi = ei
# a1*b0-a0*b1 = a1*e0-a0*e1
U = matrix(GF(p), [a1, -a0]).T
u = vector(GF(p), [a1*b0-a0*b1])

K = 2**100
L = block_matrix(ZZ, [
    [1, K*matrix(ZZ, U), 0],
    [0, K*p, 0],
    [0, K*matrix(ZZ, u), p]
]).LLL()
for row in L:
    if abs(row[-1]) == p:
        v0 = -(row[-1]//p)*vector(row[:-2])
        break

L = block_matrix(ZZ, [
    [1, K*matrix(ZZ, U)],
    [0, K*p],
]).LLL()
vi = vector(L[0][:-1])

# e = k*vi + v0
for k in trange(-2**18, 2**19):
    try:
        e = k*vi + v0 % p
        r = matrix(GF(p), A).solve_left(e - b)
        r = ZZ(r.list()[0])
        k1 = 2**16
        k2 = 2**40

        L = matrix(ZZ, [
            [k1, k2*r, 0],
            [0, k2*p, 0],
            [0, k2*ys[0], k1*k2]
        ]).LLL()
        for row in L:
            if abs(row[-1]) == k1*k2:
                h0 = ms[0]^abs(row[0]//k1)
        L = matrix(ZZ, [
            [k1, k2*r, 0],
            [0, k2*p, 0],
            [0, k2*ys[1], k1*k2]
        ]).LLL()
        for row in L:
            if abs(row[-1]) == k1*k2:
                h1 = ms[1]^abs(row[0]//k1)
        assert h0 == h1
        priv = (p, r, long_to_bytes(h0, 5))
        break
    except KeyboardInterrupt:
        break
    except:
        continue
else:
    io.close()
    exit("not this time")

c, mac = encrypt(b"Kurenaif,gimme flag!", priv)
print(f"{priv = }\n{c = }\n{mac = }")
io.sendlineafter(b"ciphertext:", c.hex().encode())
io.sendlineafter(b"mac:", mac.hex().encode())
io.interactive()
# SECCON{UOoooO0oOoOo00ooO_RECKLESS_SUMOOOOOOOOON_ooooOOooOooOoo}