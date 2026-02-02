from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
import base64

def B64Encode(x: bytes) -> str:
    """ Encodes a bytestring into url-safe base64. """
    return base64.urlsafe_b64encode(x).decode().strip('=')

def B64Decode(x: str) -> bytes:
    """ Decodes a url-safe base64 string into bytes. """
    return base64.urlsafe_b64decode(x.encode() + b'===')

def Pour(cup: bytes, tap: int):
    io.sendlineafter(b"|  > ", b"P")
    io.sendlineafter(b"|  > (B64.B64) ", B64Encode(cup).encode() + b"." + B64Encode(tap.to_bytes(32, 'big')).encode())
    io.recvuntil(b"cupFull = ")
    cup = B64Decode(io.recvline().strip().decode())
    return cup

def Depour(cup: bytes, tap: int):
    io.sendlineafter(b"|  > ", b"D")
    io.sendlineafter(b"|  > (B64.B64) ", B64Encode(cup).encode() + b"." + B64Encode(tap.to_bytes(32, 'big')).encode())
    io.recvuntil(b"cupEmpty = ")
    cup = B64Decode(io.recvline().strip().decode())
    return cup

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

from limeade import Lime
volume = 256
sugars = 2
iceCubes = 16

io = process(["python", "limeade.py"])
# io = remote(*"tcp.flagyard.com:32525".split(":"))

io.recvuntil(b"|  [~] Flag = ")
flag_enc = B64Decode(io.recvline().strip().decode())

io.recvuntil(b"|    limes = ")
res = io.recvline().strip().decode().split(".")
res = [list(B64Decode(lime)) for lime in res]
limes = [Lime(volume) for _ in range(3 * sugars + 1)]
for i in range(len(limes)):
    limes[i].suco = res[i]

ans = list()
for i in range(255):
    pt = bytes([0]*32)
    ct0 = Pour(pt, 0)

    error = long_to_bytes(1 << i, 32)
    error = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(error, 'big'), n=volume)]
    error = limes[0].Roll(error)
    error = int(''.join(str(i) for i in error), 2).to_bytes(volume // 8, 'big').lstrip(b'\x00')
    error = error.rjust(32, b'\x00')
    pt = xor(pt, error)
    ct = Pour(pt, 1<<i)

    error = long_to_bytes(1 << i, 32)
    error = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(error, 'big'), n=volume)]
    error = limes[-1].Roll(error)
    error = int(''.join(str(i) for i in error), 2).to_bytes(volume // 8, 'big').lstrip(b'\x00')
    error = error.rjust(32, b'\x00')
    ct = xor(ct, error)
    pt = Depour(ct, 0)

    error = long_to_bytes(1 << i, 32)
    error = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(error, 'big'), n=volume)]
    error = limes[0].Roll(error)
    error = int(''.join(str(i) for i in error), 2).to_bytes(volume // 8, 'big').lstrip(b'\x00')
    error = error.rjust(32, b'\x00')
    pt = xor(pt, error)
    ct1 = Pour(pt, 1<<i)

    res = int(xor(ct0, ct1).hex(), 16)
    print(i, int(res.bit_count() != 1), xor(ct0, ct1).hex())
    ans.append(int(res.bit_count() != 1))
io.close()

secretIngredient = int(''.join(str(i) for i in ans + [0])[::-1], 2)
secret = secretIngredient.to_bytes(volume // 8, 'big')
flag = AES.new(sha256(secret).digest(), AES.MODE_ECB).decrypt(flag_enc)
print(flag)

secretIngredient = int(''.join(str(i) for i in ans + [1])[::-1], 2)
secret = secretIngredient.to_bytes(volume // 8, 'big')
flag = AES.new(sha256(secret).digest(), AES.MODE_ECB).decrypt(flag_enc)
print(flag)