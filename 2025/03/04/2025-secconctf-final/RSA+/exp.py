from sage.all import *
from Crypto.Util.number import *
import tqdm
from pwn import *

p, q = 1, 1
ps = list()
pi = getPrime(14)
while True:
    if ZZ(p*pi).nbits() > 512:
        break
    ps.append(pi)
    p *= pi
    pi = next_prime(pi)
while True:
    if ZZ(q*pi).nbits() > 512:
        break
    ps.append(pi)
    q *= pi
    pi = next_prime(pi)
n = p * q
g = n // 2
h = n // 3

# io = process(['sage', '-python', 'server.py'])
io = remote(*"rsaplus.int.seccon.games 11337".split())

io.sendlineafter(b' > ', hex(p)[2:].encode())
io.sendlineafter(b' > ', hex(q)[2:].encode())
io.recvuntil(b'r = ')
r = int(io.recvline().strip().decode())

xs = list()
ys = list()
res = list()
for pi in tqdm.tqdm(ps):
    ans = list()
    for xi in range(pi):
        if (pow(xi, g, pi) + pow(xi, h, pi) - r) % pi == 0:
            ans.append(xi)
            if len(ans) > 2:
                break
    if len(ans) == 1:
        xs.append(ans[0])
        ys.append(pi)
    if len(ans) == 2:
        res.append((pi, ans))
    print(prod(ys).bit_length())
    if prod(ys).bit_length() > 515:break
x = crt(xs, ys)
print(x.nbits())
if ZZ(x).nbits() < 512:
    t = min(10, len(res))
    print(t)
    for tab in tqdm.trange(2**t):
        nowx = xs + [res[i][1][(tab>>i)&1] for i in range(t)]
        nowy = ys + [res[i][0] for i in range(t)]
        x = crt(nowx, nowy)
        if abs(ZZ(x).nbits() - 512) < 5:
            break
print(x.nbits())
print(f"{x = }")

# io.sendlineafter(b' > ', str(x).encode())
io.interactive()
# SECCON{R4d1c4lly_Sum_i5_Ab5urd}