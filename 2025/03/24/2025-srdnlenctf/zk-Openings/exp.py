from sage.all import *
from Crypto.Cipher import AES
from field import p, n, H
import json
from flatter import flatter

k = 20
with open("opening.json", "r") as f:
    res = json.loads(f.read())
    claim = res['claim']
    proof = res['proof']
with open('flag.enc', 'rb') as f:
    enc = f.read()
xs, ys = claim

# f = vector(GF(p), poly)
# key = vector(GF(p), list(key))
# g = vector(GF(p), hiding_poly)

H = matrix(GF(p), [[pow(h, i, p) for i in range(n)] for h in H]).T
# print(f"{key-f*H = }")
A = matrix(GF(p), [[pow(x, i, p) for i in range(n)] for x in xs]).T
B = matrix(GF(p), [[pow(x, i, p)*(pow(x, n, p)-1) for i in range(k)] for x in xs]).T
y = vector(GF(p), ys)
# print(f"{y-f*A-g*B = }")

P = matrix(ZZ, k, k-1)
for i in range(k-1):
    P[i,i] = -1
    P[i+1,i] = 1
z = y*B**-1*P
C = H**-1*A*B**-1*P
# print(f"{z-key*C-h = }")
# print(f"{h-h[0]*vector(GF(p), [pow(a, i, p) for i in range(k-1)]) = }")

R = PolynomialRing(GF(p), 'k', n)
ks = R.gens()
h = z - vector(R, ks)*C
D = Sequence([], R)
for i in range(k-2):
    hi, hi1 = h[i], h[i+1]
    for j in range(i):
        hj, hj1 = h[j], h[j+1]
        D.append(hi1*hj-hj1*hi)
D, monomials = D.coefficient_matrix()
D, v = D.T[:-1,:], D.T[-1:,:]
# print(f"{vector(GF(p), [monomial(*list(key))[0] for monomial in monomials[:-1]])*D + vector(v) = }")

D0, D1 = D[:D.ncols(),:], D[D.ncols():,:]
D, v = D1*D0**-1, v*D0**-1
L = block_matrix(ZZ, [
    [D, 1, 0],
    [p, 0, 0],
    [v, 0, 1]
])
L = flatter(L)
for row in L:
    if abs(row[-1]) == 1:
        ans = row[:-1]
        key = bytes(map(abs, ans[-n:]))
        flag = AES.new(key, AES.MODE_ECB).decrypt(enc)
        print(flag)
# srdnlen{what?...how?...discrete_logarithm_assumption_doesn't_hold?...should_be_k_degree_hiding_polynomial?...well...you_deserve_this_flag!}