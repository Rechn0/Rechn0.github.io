import os, hashlib, numpy as np, galois


int_to_bytes = lambda x: x.to_bytes((x.bit_length() - 1) // 8 + 1, 'big')


class UOV:
    def __init__(self, m: int, n: int, q: int) -> None:
        assert n > m > 0, "n must be greater than m, and m must be positive"
        assert 2 <= q <= 256 and q & (q - 1) == 0, "q must be a power of 2 between 2 and 256"
        self.m = m
        self.n = n
        self.q = q
        self.F = galois.GF(q)
        self.keygen()

    def expand_from_seed(self, seed: bytes, shape: tuple) -> np.ndarray:
        a = np.frombuffer(hashlib.shake_256(seed).digest(np.prod(shape)), dtype=np.uint8)
        return self.F(a % self.q).reshape(shape)

    def keygen(self) -> None:
        m, n = self.m, self.n
        self.pi = os.urandom(16)  # public randomness
        self.rho = os.urandom(16)  # private randomness
        self.sigma = os.urandom(16)  # signature randomness

        # sample the oil subspace
        O = self.expand_from_seed(self.rho, (n - m, m))

        # generate public key
        pub, pk = [], []
        for i in range(m):
            P1 = self.expand_from_seed(self.pi + int_to_bytes(i), (n - m, n - m))
            P2 = self.expand_from_seed(self.pi + int_to_bytes(i + m), (n - m, m))
            P3 = (-O.T @ P1 @ O - O.T @ P2)
            P = self.F(np.block([[P1, P2], [np.zeros((m, n - m), dtype=np.uint8), P3]]))
            pub.append(P)
            pk.append(P3.tobytes().hex())
        self.pub = pub
        self.pk = (self.pi.hex(), pk)

        # generate private key (precomputation for signing)
        self.O = self.F(np.block([[O], [np.eye(m, dtype=np.uint8)]]))
        self.priv = [(self.pub[i] + self.pub[i].T) @ self.O for i in range(m)]

    def sign(self, msg: bytes) -> bytes:
        h = self.expand_from_seed(msg, (self.m,))

        # deterministic signature thanks to Fiat-Shamir With Aborts
        k = 0
        while True:
            v = self.expand_from_seed(self.sigma + msg + int_to_bytes(k), (self.n,))
            M = self.F([v @ self.priv[i] for i in range(self.m)])
            u = h - self.F([v @ self.pub[i] @ v for i in range(self.m)])
            try:
                o = self.O @ np.linalg.solve(M, u)
                return (o + v).tobytes()
            except np.linalg.LinAlgError:
                k += 1

    def verify(self, msg: bytes, token: bytes) -> bool:
        h = self.expand_from_seed(msg, (self.m,))
        t = self.F(np.frombuffer(token, dtype=np.uint8))

        for i in range(self.m):
            if t @ self.pub[i] @ t != h[i]:
                return False
        return True


if __name__ == "__main__":
    n = 128
    m = 44
    q = 16
    uov = UOV(m, n, q)
    print(f"Public key: {uov.pk}")
    
    for _ in range(256):
        msg = bytes.fromhex(input("Enter a message to sign (hex): "))
        if not msg:
            break
        token = uov.sign(msg)
        print(f"Signature: {token.hex()}")
    
    for _ in range(16):
        msg = os.urandom(16)
        token = bytes.fromhex(input(f"Enter a signature for {msg.hex()} (hex): "))
        if not uov.verify(msg, token):
            print("Signature verification failed! Bye!")
            break
    else:
        print("All signatures verified successfully!")
        flag = os.getenv("FLAG", "srdnlen{this_is_a_fake_flag}")
        print(flag)
