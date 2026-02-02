from sage.all import *
from pwn import *
import tqdm, random
from Crypto.Util.number import bytes_to_long

message = b"give me the flag!"
As = list()
for _ in tqdm.trange(20000//136 + 1):
    A = list()
    for _ in range(20000):
        now = random.randbytes(len(message))
        now = bytes_to_long(now)
        now = bin(now)[2:].zfill(len(message)*8)
        now = list(map(int, now))
        A.append(now)
    As.append(matrix(GF(2), A))
A = block_matrix(GF(2), [As])
v = A.left_kernel().basis()[0]

# io = remote(*"tcp.flagyard.com:32565".split(":"))
io = process(["python", "server.py"])
io.sendlineafter(b"msg> ", b"give me the flag!")
for i in tqdm.trange(20000):
    io.sendline(b"y" if v[i] else b"n")
io.interactive()