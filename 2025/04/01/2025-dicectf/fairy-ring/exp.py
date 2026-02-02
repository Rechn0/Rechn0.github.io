from sage.all import *
from pwn import *
from uov import uov_1p_pkc as uov

def unpack_pub(pub):
    def unpack_mat(mat):
        Ms = list()
        for i in range(uov.m):
            Ms.append(matrix(F, len(mat), len(mat[0])))
            for a in range(len(mat)):
                for b in range(len(mat[0])):
                    Ms[-1][a, b] = F.from_integer((mat[a][b]>>(i*8) & 0xff))
        return Ms
    m1  = uov.unpack_mtri(pub, uov.v)
    m2  = uov.unpack_mrect(pub[uov.p1_sz:], uov.v, uov.m)
    m3  = uov.unpack_mtri(pub[uov.p1_sz + uov.p2_sz:], uov.m)
    Mvs, Mvms, Mms = unpack_mat(m1), unpack_mat(m2), unpack_mat(m3)
    return Mvs, Mvms, Mms

_, z0 = GF(2)["z"].objgen()
F, z = GF(
    2**8, 
    name='z', 
    modulus=z0**8 + z0**4 + z0**3 + z0 + 1).objgen()

NAMES = ['oberon', 'titania', 'puck', 'gloriana', 'aibell', 'sebile']
MESSAGE = b'shrooms'
dict = {}
for name in NAMES:
    with open(f'keys/{name}.pub', 'rb') as f:
        dict[name] = uov.expand_pk(f.read())

pub = dict['oberon']
Mvs, Mvms, Mms = unpack_pub(pub)
y = vector(map(F.from_integer, uov.shake256(MESSAGE, uov.m_sz)))

xv = vector(map(F.from_integer, range(uov.v)))
U = matrix([xv*Mvms[i] for i in range(uov.m)][::-1])
v = vector([xv*Mvs[i]*xv for i in range(uov.m)][::-1])
xm = U.solve_right(y-v)

sigs = [[F.from_integer(0)]*uov.v + xm.list(), xv.list() + xm.list()]
sigs = b''.join(bytes([i.to_integer() for i in s]) for s in sigs)

io = process(['sage', '-python', 'server.py'])
io.sendlineafter(b'ring size: ', b'2')
for i in range(2):
    io.sendlineafter(f'name {i + 1}: '.encode(), b'oberon')
io.sendlineafter(b'ring signature (hex): ', sigs.hex().encode())
io.interactive()