from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from pwn import *
import ast, tqdm, multiprocessing as mp


def _factor_worker(n, q):
    try:
        q.put(sum([[p]*i for p, i in factor(n)], []))
    except Exception as e:
        q.put(e)


def factor_with_timeout(n, timeout):
    """Run Sage factor in a child process to enforce wall-clock timeout."""
    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    q = ctx.Queue()
    proc = ctx.Process(target=_factor_worker, args=(n, q))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        raise TimeoutError("factor timeout")
    if q.empty():
        raise RuntimeError("factor failed without result")
    res = q.get()
    if isinstance(res, Exception):
        raise res
    return res

# u, v, w = ZZ["u", "v", "w"].gens()
# xs = [
#     u+v, 
#     u-v,
#     -u+w,
#     -u-w
# ]
# y = 6*u*(v - w)*(v + w)
# print(y - sum(xi**3 for xi in xs))

def attack(r, k, p):
    t = ZZ(r*pow(k, 3, p) % p)
    for _ in tqdm.trange(10000):
        if t % 6 == 0:
            try:
                facs = factor_with_timeout(t // 6, 1)

                xs = [facs[-1], facs[-2], facs[-3]]
                ind = 0
                for i in range(len(facs)-3):
                    if ZZ(xs[ind]).nbits() >= 200:
                        ind += 1
                    if ind == 3:
                        raise Exception("try again")
                    xs[ind] *= facs[i]
                u = xs[0]
                v = (xs[1] + xs[2]) // 2
                w = (xs[2] - xs[1]) // 2

                ws = [u+v, u-v, -u+w, -u-w]
                assert max(wi.bit_length() for wi in ws) < 200, "too big"
                assert sum(wi**3 for wi in ws)*inverse_mod(k**2, p) % p == (r*k) % p, "not match"
                return ws
            except TimeoutError as e:
                print(e)
            except Exception as e:
                print(e)
        t += p

# context.log_level = "debug"
# io = process(["python", "task.py"])
io = remote(*"instance.penguin.0ops.sjtu.cn 18570".split())
p = 81784117026246473991822428317352569153660970715929901941320622388580720911061
io.sendlineafter(b"Enter two primes: ", f"{p} {p}".encode())
for _ in range(1000):
    print(f"Round {_}")
    io.recvuntil(b"Prove for ")
    r = ast.literal_eval(io.recvuntil(b",").strip().decode()[:-1])
    io.recvuntil(b"this is your mask: ")
    k = ast.literal_eval(io.recvuntil(b",").strip().decode()[:-1])
    ws = attack(r, k, p)
    io.sendlineafter(b"witness: ", str(ws).encode())
    print(io.recvline())
io.interactive()
# 0ctf{NOt_A_zk_Bu7_a_1nteR3st1ng_PuzZle!!!o12bjk41dsapd;}