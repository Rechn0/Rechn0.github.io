from sage.all import *
from Crypto.Cipher import AES

k = 16
e = 65537
C = 
ct = b"\xab\r\xc7m\xc7\xab\xff\x837\x94\xd1Al\x95\xf1\x90\x9d>v\xb1?\x903'\x97e\xfb\xfa\xc1L\xf1\xed\xeaJFi0\xccs\xf5"

C = matrix(ZZ, k, k, C)

def func(i0, i1, j0, j1):
    u = C[i0].list() + C[i1].list() + (-C.T)[j1].list()
    L = block_matrix(ZZ, [
        [1, matrix(u).T]
    ]).LLL()

    for v in L:
        try:
            v = list(map(abs, L[2]))
            v0, v1 = v[:k], v[k:2*k]
            s0, s1 = gcd(v1[:j0] + v1[j0+1:]), gcd(v0[:j1] + v0[j1+1:])
            MTj0 = [i//s1 for i in v0]
            MTj1 = [i//s0 for i in v1]
            MTj0[j0], MTj1[j1] = 0, 0
            if MTj0.count(0) > 10:
                continue
            if bytes(MTj0) == bytes(MTj1):
                print(bytes(MTj0))
                print(bytes(MTj1))
                return MTj0
        except:
            continue

import random
M = list()
for ind in range(k):
    tab = list(range(k))
    tab.pop(ind)
    while True:
        i0, i1 = random.choices(tab, k=2)
        ans = func(i0, i1, ind, ind)
        if ans:
            M.append(ans)
            print(ind)
            break
M = matrix(ZZ, k, k, M).T
M = [M[i] for i in range(k)]
print(M)

# and the bruteforce part