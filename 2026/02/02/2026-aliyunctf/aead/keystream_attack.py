from sage.all import *
import os
from collections import Counter
import tqdm
from Crypto.Cipher import ChaCha20_Poly1305

key = os.urandom(32)
nonce = os.urandom(24)
aad = bytes(range(16))

def enc(pt):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return tag[-2:]

cnt = Counter()
dic = dict()
for ind in tqdm.trange(1, 16): # cannot recover the first byte of each block
    dic[ind] = dict()
    for ch in range(256):
        ss = set()
        for _ in range(32): # more trials, more success rate
            pt0 = os.urandom(ind)
            t0 = enc(pt0)
            t1 = enc(pt0 + bytes([ch]))

            l0, l1 = int.from_bytes(t0, 'little'), int.from_bytes(t1, 'little')
            ss.add((l1 - l0) % 2**16)
        ss = tuple(sorted(list(ss)))
        cnt.update([ss])
        dic[ind][ss] = ch
print(f"{cnt.most_common(5) = }")
ss = cnt.most_common(1)[0][0]
keystream = bytes([dic[ind][ss] for ind in range(1,16)])
print('??' + keystream.hex())

# check real keystream
pt = os.urandom(16)
cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
cipher.update(aad)
ct, tag = cipher.encrypt_and_digest(pt)
keystream = bytes([pti ^ cti for pti, cti in zip(pt, ct)])
print(keystream.hex())