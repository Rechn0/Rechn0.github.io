from sage.all import *
from pwn import *
from Crypto.Util.number import long_to_bytes

def fuzz():
    p = 7
    x = 233
    for g in range(100):
        io = remote(*"1.95.137.123 9999".split())
        io.sendlineafter(b'What do you do? ', b'4')
        io.sendlineafter(b"I don't think the boss's lucky number is lucky enough: ", str(p).encode())
        io.sendlineafter(b"with my own: ", str(x).encode())
        io.sendlineafter(b"own lucky number: ", str(g).encode())
        io.sendlineafter(b'your bet size: ', b'1')
        print(g, 'Oops' not in io.recvline().decode())
        io.close()
    exit()
# fuzz()

p = 1502305675703953507826564356364207463785905265358954425050832597353379827611347779894929874274487297076504174110953417469304402049079223143080164648064147459
q = (p - 1) // 2
qs = [(2, 12), (2449952539, 1), (2580715139, 1), (2792523953, 1), (2945474351, 1), (2996317717, 1), (3172879987, 1), (3229817321, 1), (3272969519, 1), (3435471803, 1), (3606091481, 1), (3613773421, 1), (3696075863, 1), (3706535681, 1), (3729911617, 1), (3912962413, 1), (3919762169, 1)]
assert q == prod(qi**i for qi, i in qs) + 1
qs = [_[0] for _ in qs[1:]]

def bsgs(g, h, p, q, qi):
    from tqdm import trange

    t = sqrt(qi).round() + 1
    dic = dict()
    for a in trange(t + 1):
        dic[pow(g, 2*pow(g, a*t, q), p)] = a
    for b in trange(t + 1):
        k = pow(h, 2*pow(g, -b, q), p)
        if k in dic:
            return dic[k]*a + b
    return None

xs = list()
for qi in qs:
    times = 2
    gi = pow(2, (q-1)//qi, q)

    while True:
        io = remote(*"1.95.137.123 9999".split())

        io.sendlineafter(b'What do you do? ', b'1')
        io.recvuntil(b"Today's lucky number is ")
        P = int(io.recvuntil(b'.')[:-1].decode())
        if P == p:
            break
        io.close()

    while True:
        gi = pow(gi, randint(1, qi-1), q)
        if is_prime(gi):
            io.sendlineafter(b'What do you do? ', b'2')
            io.sendlineafter(b"You decide to pick your own lucky number: ", str(gi).encode())
            if 'successfully' in io.recvline().decode():
                break

    io.sendlineafter(b'What do you do? ', b'3')
    io.sendlineafter(b"You decide to pick your bet size: ", str(times).encode())
    io.recvuntil(b'You take the ticket with the number ')
    hi = int((io.recvuntil(b'.')[:-1].split(b" from the machine")[0]).decode())
    xs.append(bsgs(gi, hi, p, q, qi))
    io.close()

x, q = crt(xs, qs), lcm(qs)
while True:
    flag = long_to_bytes(int(x))
    if b'ACTF' in flag:
        print(flag)
        break
    x += q
# Lucky won't help you but wisdom can! ACTF{0oooooh_My_T3tr@ti0n!}