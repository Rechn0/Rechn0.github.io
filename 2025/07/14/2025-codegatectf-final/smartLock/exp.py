from sage.all import *
from pwn import *
from Crypto.Util.number import *

io = remote(*"3.36.14.139 5333".split())
lockers = list()
for i in range(10):
    io.recvuntil(b'Device ID:')
    id = io.recvline().strip().decode()[:-1]
    io.recvuntil(b'Public Key (N): ')
    n = int(io.recvline().strip().decode(), 16)
    lockers.append([i, n])

for id, n in lockers[-1:]:
    io.sendlineafter(b'> ', f'unlock {id}'.encode())
    io.recvuntil(b'OTP: ')
    otp = int(io.recvline().strip().decode(), 16)
    pt = pow(otp, 0x10001, n)
    io.sendlineafter(b'Plain: ', hex(pt)[2:].zfill(512).encode())
# io.sendlineafter(b'> ', b'AccessVault')
io.interactive()
'''
Hi Admin. You can access the secure vault
Here is the data: codegate2025{fa8d7f158dfe94262069b0ce8fff670b513a855e15038e16ca994c790a417f39eb4de3d9353d1622b00d2a0302b3e8b46d79835a8ed245ce8c7ff197a349ae8ebc28abed0551e859}
'''