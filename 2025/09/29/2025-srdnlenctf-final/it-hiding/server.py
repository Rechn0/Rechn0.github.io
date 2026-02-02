from fastecdsa import point, curve
import os, secrets, hashlib

# Weierstrass curve isomorphic to Ed25519
# be careful it is not the same as the Weierstrass form in https://neuromancer.sk/std/other/Curve25519
W25519 = curve.W25519
Point = point.Point

# Pedersen commitment scheme is information-theoretically hiding
# i.e. it is impossible to infer any information about the committed value from the commitment
# or from a rerandomization of the commitment (assumed to be secure)
class Pedersen:
    G = W25519.G
    H = secrets.randbelow(W25519.q) * W25519.G

    @classmethod
    def commit(cls, m: int, r: int) -> Point:
        return m * cls.G + r * cls.H

    @classmethod
    def randomize(cls, C: Point, r: int) -> Point:
        return C + r * cls.H

# Schnorr protocol to prove knowledge of discrete log (assumed to be secure)
class Schnorr:
    G = W25519.G
    n = W25519.q
    challenge = lambda R, P: hashlib.sha256(str(R).encode() + str(P).encode()).digest()

    @classmethod
    def prove(cls, d: int) -> tuple[int, int]:
        k = secrets.randbelow(cls.n)
        P = d * cls.G
        R = k * cls.G
        c = int.from_bytes(cls.challenge(R, P), "big") % cls.n
        z = (k + c * d) % cls.n
        return z, c

    @classmethod
    def verify(cls, P: Point, proof: tuple[int, int]) -> bool:
        z, c = proof
        R = z * cls.G - c * P
        return c == int.from_bytes(cls.challenge(R, P), "big") % cls.n


if __name__ == "__main__":
    x, y = map(int, input("Enter your base (x y): ").split(" "))
    B = point.Point(x, y, W25519)
    # make sure B is a multiple of G
    z, c = map(int, input("Enter your Schnorr proof (z c): ").split(" "))
    assert Schnorr.verify(B, (z, c))

    for _ in range(32):
        b = secrets.randbits(1)
        if b:
            r = secrets.randbelow(W25519.q)
            C = Pedersen.randomize(B, r)
        else:
            m = secrets.randbelow(W25519.q)
            r = secrets.randbelow(W25519.q)
            C = Pedersen.commit(m, r)
        print(f"Randomized commitment: ({C.x}, {C.y})")

        guess = int(input("Guess (0 or 1): "))
        assert guess in (0, 1)
        if guess != b:
            print("Wrong guess!")
            break
    else:
        print(os.getenv("FLAG", "srdnlen{this_is_a_fake_flag}"))
