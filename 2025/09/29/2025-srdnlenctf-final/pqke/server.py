from ring import Ring
import os, numpy as np, hashlib

# https://eprint.iacr.org/2018/1155 section 2.2 RLWE KE adapted to MLWE

q = 0x10001
n = 128
s = 2
k = 2
R = Ring(q=q, n=n, s=s)

# Generate random matrix m
m = np.array([R.uniform() for _ in range(k**2)]).reshape((k, k))
for i in range(k):
    for j in range(k):
        print(f"m[{i}, {j}] = {m[i, j]}")

# Alice's secret key and public key computation
sA = np.array([R.binomial() for _ in range(k)])
eA = np.array([R.binomial() for _ in range(k)])
pA = sA @ m + 2 * eA
for i in range(k):
    print(f"pA[{i}] = {pA[i]}")

# Bob's secret key and public key computation
sB = np.array([R.binomial() for _ in range(k)])
eB = np.array([R.binomial() for _ in range(k)])
pB = m @ sB + 2 * eB
for i in range(k):
    print(f"pB[{i}] = {pB[i]}")

# Shared secret computation
kB = pA @ sB
kA = sA @ pB
assert np.array_equal(kA.centered_coeffs() % 2, kB.centered_coeffs() % 2), \
    "Shared secrets do not match! Hint sharing is not implemented, so this may happen. Please rerun."

shared_secret = int("".join(map(str, kA.centered_coeffs() % 2)), 2).to_bytes(n // 8, 'big')
xor = lambda x, y: bytes(a ^ b for a, b in zip(x, y))
flag = os.getenv("FLAG", "srdnlen{this_is_a_fake_flag}").encode()
flag_enc = xor(flag, hashlib.shake_256(shared_secret).digest(len(flag)))
print(f"flag_enc = {flag_enc.hex()}")
