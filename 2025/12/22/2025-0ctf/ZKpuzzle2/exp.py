from sage.all import *
from pwn import *
import ast, tqdm

def attack(r, k, p, q):
    x = GF(q)["x"].gen()
    targ = int(r*pow(k, 3, q) % q)

    for t in range(1000):
        f = (x + t*p)**3 + (-x)**3 - targ
        ans = f.roots()
        if ans:
            u = int(ans[0][0])
            return [u+t*p, -u]

p   = 0b1100000000110000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000110000000000010000100000010000000000000000000000100000100000000000000000001000001000010000000000001100000000001000000000000000000000000001
q   = 0b1100000000110000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000110000000110010000101100010000000000000000000000100000100000000000000000000100000100010000000000001100000000000100000110000000000000000001

io = process(["python", "task.py"])
io.sendlineafter(b"Enter two primes: ", f"{p} {q}".encode())
io.recvuntil(b"You need to succese 940 times in ")
ROUND = ast.literal_eval(io.recvuntil(b" ").strip().decode())

for _ in tqdm.trange(ROUND):
    io.recvuntil(b"Prove for ")
    r = ast.literal_eval(io.recvuntil(b",").strip().decode()[:-1])
    io.recvuntil(b"this is your mask: ")
    k = ast.literal_eval(io.recvuntil(b",").strip().decode()[:-1])
    ws = attack(r, k, p, q) + attack(r, k, q, p)
    io.sendlineafter(b"witness: ", str(ws).encode())
io.interactive()
# 0ctf{A_g0Od_pUzZ1e_C0n5tra1ns_7he_WitNess_N0t_thE_proof!!~~~}