from sage.all import *
from pwn import *

n = 32
flat = lambda a: list(map(int, bin(a)[2:].zfill(n)))[::-1]

WORD = 0xFFFFFFFF
rol = lambda x, r: ((x << r) | (x >> (32 - r))) & WORD
ror = lambda x, r: ((x >> r) | (x << (32 - r))) & WORD
_ROUNDS = 24
_DELTA = [0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC]

def key_recover(T):
    for i in range(_ROUNDS)[::-1]:
        t0 = rol(_DELTA[i & 3], i & 31)
        t1 = rol(_DELTA[i & 3], (i + 1) & 31)
        t2 = rol(_DELTA[i & 3], (i + 2) & 31)
        t3 = rol(_DELTA[i & 3], (i + 3) & 31)
        T[0] = (ror(T[0], 1) - t0) & WORD
        T[1] = (ror(T[1], 3) - t1) & WORD
        T[2] = (ror(T[2], 6) - t2) & WORD
        T[3] = (ror(T[3], 11) - t3) & WORD
    key = b''.join([int.to_bytes(T[i], 4, "little") for i in range(4)])
    return key

def solve(C, res):
    R, xs = PolynomialRing(GF(2), 'x', 64).objgens()
    a, b = xs[:n], xs[n:]
    Fs = list()

    c = flat(C)
    for i in range(n):
        if i == 0:
            Fs.append(a[0]+b[0] - c[0])
        if i == 1:
            Fs.append(a[1]+b[1] + a[0]*b[0] - c[1])
        if i >= 2:
            Fs.append(a[i]+b[i] + a[i-1]*b[i-1] + (a[i-1]+b[i-1])*(a[i-1]+b[i-1]+c[i-1]) - c[i])
    for dBi, Ci in res:
        db = flat(dBi)
        c = flat(Ci)
        for i in range(n):
            if i == 0:
                Fs.append(a[0]+b[0]+db[0] - c[0])
            if i == 1:
                Fs.append(a[1]+b[1]+db[1] + a[0]*(b[0]+db[0]) - c[1])
            if i >= 2:
                Fs.append(a[i]+b[i]+db[i] + a[i-1]*(b[i-1]+db[i-1]) + (a[i-1]+b[i-1]+db[i-1])*(a[i-1]+b[i-1]+db[i-1]+c[i-1]) - c[i])

    dica, dicb = dict({i: None for i in range(n)}), dict({i: None for i in range(n)})
    Fs = Ideal(Fs).groebner_basis()
    for f in Fs:
        vars = f.variables()
        if len(vars) == 1:
            ans = int(f.univariate_polynomial()(0))
            for i in range(n):
                if vars[0] == a[i]:
                    dica[i] = ans
                    break
                if vars[0] == b[i]:
                    dicb[i] = ans
                    break
    return dica, dicb

def func1(C0, Cs):
    def func(C):
        x23_0 = C[3] & WORD
        return x23_0
    
    res = list()
    for Ci in Cs:
        dBi = func(Ci)^func(C0)
        res.append((dBi, ror(Ci[0], 9)))
    dica, dicb = solve(
        C=ror(C0[0], 9),
        res=res
    )
    return dica, dicb

def func2(C0, Cs, rk23_0):
    def func(C):
        x23_0_rk23_0 = C[3] ^ rk23_0
        x23_1_rk23_1 = (ror(C[0], 9) - x23_0_rk23_0) & WORD
        return x23_1_rk23_1

    res = list()
    for Ci in Cs:
        dBi = func(Ci)^func(C0)
        res.append((dBi, rol(Ci[1], 5)))
    dica, dicb = solve(
        C=rol(C0[1], 5),
        res=res
    )
    return dica, dicb

def func3(C0, Cs, rk23_0, rk23_1_rk23_2):
    def func(C):
        x23_0_rk23_0 = C[3] ^ rk23_0
        x23_1_rk23_1 = (ror(C[0], 9) - x23_0_rk23_0) & WORD
        x23_1_rk23_2 = (x23_1_rk23_1^rk23_1_rk23_2) & WORD
        x23_2_rk23_3 = (rol(C[1], 5) - x23_1_rk23_2) & WORD
        return x23_2_rk23_3

    res = list()
    for Ci in Cs:
        dBi = func(Ci)^func(C0)
        res.append((dBi, rol(Ci[2], 3)))
    dica, dicb = solve(
        C=rol(C0[2], 3),
        res=res
    )
    return dica, dicb

def func4(C0, Cs, rk23_0, rk23_1_rk23_2, rk23_3_rk23_4):
    def func(C):
        x23_0_rk23_0 = C[3] ^ rk23_0
        x23_1_rk23_1 = (ror(C[0], 9) - x23_0_rk23_0) & WORD
        x23_1_rk23_2 = x23_1_rk23_1 ^ rk23_1_rk23_2
        x23_2_rk23_3 = (rol(C[1], 5) - x23_1_rk23_2) & WORD
        x23_2_rk23_4 = x23_2_rk23_3 ^ rk23_3_rk23_4
        x23_3_rk23_5 = (rol(C[2], 3) - x23_2_rk23_4) & WORD
        return x23_3_rk23_5

    res = list()
    for Ci in Cs:
        dBi = func(Ci)^func(C0)
        res.append((dBi, ror(Ci[3], 9)))
    dica, dicb = solve(
        C=ror(C0[3], 9),
        res=res
    )
    return dica, dicb

def proof():
    from subprocess import run

    io.recvuntil(b'    python3 ')
    command = f"sage -python {io.recvline().strip().decode()}"
    res = run(
        command, 
        shell=True,
        text=True,
        capture_output=True,
        executable='/bin/bash',
    )
    io.sendlineafter(b'Solution? ', res.stdout.encode())
    io.recvlines(14)

def oracle_normal():
    io.sendline(b'0')
    io.sendline(b'00'*16)
    io.recvuntil(b'> ')
    ct = bytes.fromhex(io.recvline().strip().decode())
    return [int.from_bytes(ct[i * 4 : (i + 1) * 4], "little") for i in range(4)]

def oracle_fault(round, index):
    io.sendline(b'1')
    io.sendline(b'00'*16)
    io.sendline(' '.join(map(str, [round, index])).encode())
    io.recvuntil(b'> ')
    ct = bytes.fromhex(io.recvline().strip().decode())
    return [int.from_bytes(ct[i * 4 : (i + 1) * 4], "little") for i in range(4)]


def attack():
    C0 = oracle_normal()

    Cs1 = [oracle_fault(round=22, index=0) for _ in range(5)]
    dica, dicb = func1(C0, Cs1)
    x23_0 = C0[3] & WORD
    # x23_0_rk23_0 = x23_0 ^ rk23_0 # 
    # print([dicb[i] == flat(x23_0_rk23_0)[i] if dicb[i] is not None else "?" for i in range(n)])
    rk23_0 = int(''.join([str(dicb[i]) for i in range(n-1)])[::-1], 2) ^ x23_0
    # rk23_0 = rk23_0

    Cs2 = [oracle_fault(round=23, index=1) for _ in range(5)]
    dica, dicb = func2(C0, Cs2, rk23_0)
    x23_0_rk23_0 = C0[3] ^ rk23_0
    x23_1_rk23_1 = (ror(C0[0], 9) - x23_0_rk23_0) & WORD
    # x23_1_rk23_2 = x23_1_rk23_1 ^ rk23_1^rk23_2 #
    # print([dicb[i] == flat(x23_1_rk23_2)[i] if dicb[i] is not None else "?" for i in range(n)])
    # x23_2_rk23_3 = (rol(C0[1], 5) - x23_1_rk23_2) & WORD
    # print([dica[i] == flat(x23_2_rk23_3)[i] if dica[i] is not None else "?" for i in range(n)])
    rk23_1_rk23_2 = int(''.join([str(dicb[i]) for i in range(n-1)])[::-1], 2) ^ x23_1_rk23_1
    # rk23_1_rk23_2 = rk23_1^rk23_2

    Cs3 = [oracle_fault(round=23, index=2) for _ in range(5)]
    dica, dicb = func3(C0, Cs3, rk23_0, rk23_1_rk23_2)
    x23_0_rk23_0 = C0[3] ^ rk23_0
    x23_1_rk23_1 = (ror(C0[0], 9) - x23_0_rk23_0) & WORD
    x23_1_rk23_2 = x23_1_rk23_1 ^ rk23_1_rk23_2
    x23_2_rk23_3 = (rol(C0[1], 5) - x23_1_rk23_2) & WORD
    # x23_2_rk23_4 = x23_2_rk23_3 ^ rk23_3^rk23_4 #
    # print([dicb[i] == flat(x23_2_rk23_4)[i] if dicb[i] is not None else "?" for i in range(n)])
    # x23_3_rk23_5 = (rol(C0[2], 3) - x23_2_rk23_4) & WORD
    # print([dica[i] == flat(x23_3_rk23_5)[i] if dica[i] is not None else "?" for i in range(n)])
    rk23_3_rk23_4 = int(''.join([str(dicb[i]) for i in range(n-1)])[::-1], 2) ^ x23_2_rk23_3
    # rk23_3_rk23_4 = rk23_3^rk23_4

    dica, dicb = func4(C0, Cs1, rk23_0, rk23_1_rk23_2, rk23_3_rk23_4)
    x23_0_rk23_0 = C0[3] ^ rk23_0
    x23_1_rk23_1 = (ror(C0[0], 9) - x23_0_rk23_0) & WORD
    x23_1_rk23_2 = x23_1_rk23_1 ^ rk23_1_rk23_2
    x23_2_rk23_3 = (rol(C0[1], 5) - x23_1_rk23_2) & WORD
    x23_2_rk23_4 = x23_2_rk23_3 ^ rk23_3_rk23_4
    x23_3_rk23_5 = (rol(C0[2], 3) - x23_2_rk23_4) & WORD
    # x22_0_rk22_0 = x23_3_rk23_5 ^ rk23_5^rk22_0 #
    # print([dicb[i] == flat(x22_0_rk22_0)[i] if dicb[i] is not None else "?" for i in range(n)])
    rk23_5_rk22_0 = int(''.join([str(dicb[i]) for i in range(n-1)])[::-1], 2) ^ x23_3_rk23_5
    # rk23_5_rk22_0 = rk23_5^rk22_0

    rk22_0 = (ror(rk23_0, 1) - rol(_DELTA[23 & 3], 23 & 31)) & WORD
    rk23_5 = rk23_5_rk22_0 ^ rk22_0

    from LEAk import encrypt

    for i0 in range(2):
        for i1 in range(4):
            for i2 in range(2):
                for i3 in range(2):
                    T0 = rk23_0 + (i0 << 31)
                    T1 = rk23_5 + (i1 << 30)
                    T2 = (rk23_1_rk23_2 + (i2 << 31)) ^ T1
                    T3 = (rk23_3_rk23_4 + (i3 << 31)) ^ T1
                    KEY = key_recover([T0, T1, T2, T3])
                    ct = encrypt(b'\x00'*16, KEY)
                    if [int.from_bytes(ct[i * 4 : (i + 1) * 4], "little") for i in range(4)] == C0:
                        return KEY
    raise Exception("Failed to recover key")
while True:
    # io = process(["sage", "-python", "LEAk.py"])
    io = remote(*"43.201.153.112 10955".split())
    proof()

    try:
        KEY = attack()
        io.sendline(KEY.hex().encode())
        io.interactive()
    except KeyboardInterrupt:
        io.close()
        print("interrupted")
        break
    except Exception as e:
        io.close()
        print("not this time", e)
# codegate2025{6db857825fcc5d7b59d950d5896d0e2f}