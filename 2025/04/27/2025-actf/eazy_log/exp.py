from sage.all import *
from collections import namedtuple
from Crypto.Util.number import *

Point = namedtuple("Point", "x y")
O = "Origin"

def ph_attack(p, order, P, Q):
    def point_addition(P, Q, n):
        if P == O:
            return Q
        if Q == O:
            return P
        x = (P.x * Q.y + P.y * Q.x - P.x * Q.x) % n
        y = (P.x * Q.x + P.y * Q.y) % n
        return Point(x, y)
        
    def double_and_add(k, P, n):
        Q = P
        R = O
        while(k > 0):
            if k & 1:
                R = point_addition(R, Q, n)
            k >>= 1
            Q = point_addition(Q, Q, n)
        return R
    
    def bsgs(P, Q, sub_order):
        from tqdm import trange

        t = sqrt(sub_order).round() + 1
        dic = dict()

        atP, tP = Point(0, 1), double_and_add(t, P, p)
        for a in trange(t+1):
            dic[atP] = a
            atP = point_addition(atP, tP, p)
        
        bP, _P = Q, double_and_add(sub_order-1, P, p)
        for b in trange(t+1):
            if bP in dic.keys():
                return dic[bP]*t + b
            bP = point_addition(bP, _P, p)
        return None

    xs, qs = list(), list()
    for q, i in factor(order):
        sub_order = q**i
        Pi, Qi = double_and_add(order//sub_order, P, p), double_and_add(order//sub_order, Q, p)
        xs.append(bsgs(Pi, Qi, sub_order))
        qs.append(sub_order)
    return int(crt(xs, qs))

def padic_attack(p, i, order, P, Q):
    def point_addition(P, Q):
        if P == O:
            return Q
        if Q == O:
            return P
        x = P.x * Q.y + P.y * Q.x - P.x * Q.x
        y = P.x * Q.x + P.y * Q.y
        return Point(x, y)
        
    def double_and_add(k, P):
        Q = P
        R = O
        while(k > 0):
            if k & 1:
                R = point_addition(R, Q)
            k >>= 1
            Q = point_addition(Q, Q)
        return R
    
    F = Qp(p, i)
    P, Q = Point(F(P.x), F(P.y)), Point(F(Q.x), F(Q.y))
    Pi, Qi = double_and_add(order, P), double_and_add(order, Q)
    x = ZZ((Qi.x/Qi.y) / (Pi.x/Pi.y))
    return x

def find_p():
    while True:
        q = getPrime(16)
        qs = 1
        while True:
            qs *= q
            q = next_prime(q)
            p = 2*qs + 1
            if isPrime(p) and p.bit_length() == 400 and p % 4 == 3:
                print(f"{p = }")
                return p
            if p.bit_length() > 400:
                break

n = 0x231d5fa471913e79facfd95e9b874e2d499def420e0914fab5c9f87e71c2418d1194066bd8376aa8f02ef35c1926f73a46477cd4a88beae89ba575bb3e1b04271426c6706356dd8cd9aa742d7ad0343f8939bfd2110d45122929d29dc022da26551e1ed7000
G1 = Point(0xf22b9343408c5857048a19150c8fb9fd44c25d7f6decabc10bf46a2250a128f0df15adc7b82c70c0acaf855c0e898b141c9c94ba8aef8b67ea298c6d9fd870ea70e1c4f8a1b595d15373dc6db25a4ecddf626a64f47beba5538b7f733e4aa0c4f1fd4c291d, 0x8d3264514b7fdbce97fbaedb33120c7889a1af59691a1947c2c7061347c091b0950ca36efaa704514004a988b9b87b24f5cebf2d1c7bef44ff172519e1a62eb62cde234c94bd0ab39375d7ddb42e044090c8db46d3f965ef7e4753bc41dac3b8b3ae0cdb57)
G2 = Point(0x81919777837d3e5065c6f7f6801fe29544180be9db2137f075f53ebb3307f917183c6fc9cdfc5d75977f7, 0xd1a586d6848caa3a5436a86d903516d83808ce2fa49c5fb3f183ecb855e961c7e816a7ba8f588ef947f19)
ps = [
    (2, 12),
    (5, 4),
    (15271784978279, 1),
    (10714146599832792643, 1), 
    (222696442740376752383, 3), 
    (899889935029682511225429150065010811552017719005924136271659168643090431, 1),
    (899889935029682511225429150065010811552017719005924136271659166808024139, 1)
]
assert n == prod([p**i for p, i in ps])

def point_addition(P, Q, n):
    if P == O:
        return Q
    if Q == O:
        return P
    x = (P.x * Q.y + P.y * Q.x - P.x * Q.x) % n
    y = (P.x * Q.x + P.y * Q.y) % n
    return Point(x, y)
    
def double_and_add(k, P, n):
    Q = P
    R = O
    while(k > 0):
        if k & 1:
            R = point_addition(R, Q, n)
        k >>= 1
        Q = point_addition(Q, Q, n)
    return R

# pp = find_p()
pp = 1550220515754193660669276602604749780922806971659171151122821870024426003839071691617885362931292961519877746876566255999

from pwn import *
io = process(['sage', '-python', 'easy_log.py'])
kG1 = eval(io.recvline().strip().decode())

xs, qs = list(), list()
for p, i in [
    (15271784978279, 1),
    (899889935029682511225429150065010811552017719005924136271659168643090431, 1),
]:
    xs.append(ph_attack(p, p-1, G1, kG1))
    qs.append(p-1)

for p, i in [
    (10714146599832792643, 1), 
]:
    xs.append(ph_attack(p, p**2-1, G1, kG1))
    qs.append(p**2-1)

for p, i in [
    (222696442740376752383, 3), 
]:
    xs.append(ph_attack(p, p**2-1, G1, kG1))
    qs.append(p**2-1)
    xs.append(padic_attack(p, i-1, p**2-1, G1, kG1))
    qs.append(p**(i-2))

x = crt(xs, qs)
flag = long_to_bytes(x)

io.sendline(str(x).encode())
io.sendline(str(pp).encode())
kG2 = eval(io.recvline().strip().decode())
io.close()

x = ph_attack(pp, pp-1, G2, kG2)
flag += long_to_bytes(x)
print(flag)