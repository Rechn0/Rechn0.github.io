from sage.all import *
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

def func():
    # io = remote(*"tcp.flagyard.com:23619".split(":"))
    io = process(["python", "server.py"])
    io.recvuntil(b"e = ")
    e = int(io.recvline().strip().decode())
    io.recvuntil(b"n = ")
    n = int(io.recvline().strip().decode())

    sentences = list()
    for i in range(10):
        sentence = io.recvline().strip().decode()
        sentences.append(sentence)
    seeds = [15901, 17502, 4145, 15589]
    cts = list()
    for seed in seeds:
        io.sendlineafter(b"seed:", str(seed).encode())
        io.recvuntil(b"ct = ")
        ct = int(io.recvline().strip().decode())
        cts.append(ct)

    io.close()
    return e, n, cts, sentences

e, n, cts, sentences = func()

R, xs = Zmod(n)["x0", "x1"].objgens()
p0 = sentences[0]
p1 = " ".join([sentences[1], sentences[2], sentences[3], sentences[4]])


p0 = sentences[0]
p1 = " ".join([sentences[1], sentences[2], sentences[3], sentences[4]])
x0, x1 = bytes_to_long(p0.encode()), bytes_to_long(p1.encode())
f0 = (xs[0]*256 + ord(' '))*pow(256, len(p1)) + xs[1]
f0 = f0**e - cts[0]
f1 = (xs[1]*256 + ord(' '))*pow(256, len(p0)) + xs[0]
f1 = f1**e - cts[1]
g0 = f0.sylvester_matrix(f1, xs[1]).det()


p0 = sentences[0]
p1 = " ".join([sentences[2], sentences[3], sentences[4], sentences[5]])
x0, x1 = bytes_to_long(p0.encode()), bytes_to_long(p1.encode())
f0 = (xs[0]*256 + ord(' '))*pow(256, len(p1)) + xs[1]
f0 = f0**e - cts[2]
f1 = (xs[1]*256 + ord(' '))*pow(256, len(p0)) + xs[0]
f1 = f1**e - cts[3]
g1 = f0.sylvester_matrix(f1, xs[1]).det()


g0, g1 = g0.univariate_polynomial(), g1.univariate_polynomial()
while g1.degree() > 0:
    g0, g1 = g1, g0 % g1
    print(g0.degree(), g1.degree())
ans = ZZ(-g0.monic()(0))


p0 = sentences[0].split(".")[0]
p1 = ". Congratulations! The flag is BHFlagY{"
p2 = "00000000000000000000000000000000"
p3 = "}."
f = ((xs[0]*pow(256, len(p1)) + bytes_to_long(p1.encode()))*pow(256, len(p2)) + xs[1])*pow(256, len(p3)) + bytes_to_long(p3.encode())
f = f - ans
fs = [i for i, _ in f]
Q = diagonal_matrix([n // 256**len(p0), n // 256**len(p2), 1])
L = matrix(ZZ, [
    [1, fs[0]*inverse_mod(fs[1], n), 0],
    [0, n, 0],
    [0, fs[2]*inverse_mod(fs[1], n), n**2],
])
L = (L*Q).LLL()
L = (L/Q).change_ring(ZZ)
ans = abs(L[-1][1])
print(long_to_bytes(ans))