from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from secret import flag

class proofSystem:
    def __init__(self, p1, p2):
        assert is_prime(p1) and is_prime(p2)
        assert p1.bit_length() == p2.bit_length() == 256
        self.E1 = EllipticCurve(Zmod(p1), [0, 137])
        self.E2 = EllipticCurve(Zmod(p2), [0, 137])

    def myrand(self, E1, E2):
        F = Zmod(E1.order())
        r = F.random_element()
        P = r * E2.gens()[0]
        x = P.x()
        return int(r * x) & (2**128 - 1)

    def verify(self, E, r, k, w):
        G = E.gens()[0]
        P = (r*k) * G
        Q = (w[0]**3 + w[1]**3 + w[2]**3 + w[3]**3) * inverse_mod(k**2, G.order()) * G
        return P.x() == Q.x()


def task():
    ROUND = 1000
    threshold = 999
    print("hello hello")
    p1, p2 = map(int, input("Enter two primes: ").split())

    proofsystem = proofSystem(p1, p2)
    print(f"You need to succese {threshold} times in {ROUND} rounds.")
    r = proofsystem.myrand(proofsystem.E1, proofsystem.E2)
    success = 0
    for _ in range(ROUND):
        k = proofsystem.myrand(proofsystem.E2, proofsystem.E1)
        w = literal_eval(input(f"Prove for {r}, this is your mask: {k}, now give me your witness: "))
        assert len(w) == 4
        assert max(wi.bit_length() for wi in w) < 200
        print("pass the bit check")
        if proofsystem.verify(proofsystem.E1, r, k, w) and proofsystem.verify(proofsystem.E2, r, k, w):
            print(f"Good!")
            success += 1
        r += 1


    if success > threshold:
        print("You are master of math!")
        print(flag)


if __name__ == "__main__":
    try:
        task()
    except Exception:
        exit()