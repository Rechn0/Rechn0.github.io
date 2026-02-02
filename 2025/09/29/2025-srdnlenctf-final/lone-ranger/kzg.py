# The following code is not intended to be vulnerable

from ecc import r, G1, G2
from field import Polynomial
import os, secrets, json

__all__ = ["KZG"]


class KZG:
    def __init__(self, d: int, filename: str = "srs.json", *, save: bool = True, new: bool = False) -> None:
        assert d > 0, "SRS degree must be positive"
        if new or not os.path.exists(filename):
            srs = self.setup(d)
            if save:
                json.dump(srs, open(filename, "w"), indent=4)
        else:
            srs = json.load(open(filename, "r"))
            assert srs["d"] == d, "SRS degree mismatch"
            assert len(srs["G1"]) == d + 1, "SRS G1 length mismatch"
            assert len(srs["G2"]) == 2, "SRS G2 length mismatch"
        self.srs = srs
        self.srs["G1"] = [G1.from_repr(g) for g in self.srs["G1"]]
        self.srs["G2"] = [G2.from_repr(g) for g in self.srs["G2"]]

    def setup(self, d: int) -> dict:
        srs = dict()
        srs["d"] = d
        x = secrets.randbelow(r)
        g1 = G1.one()
        srs["G1"] = [repr(g1 * pow(x, i, r)) for i in range(d + 1)]
        g2 = G2.one()
        srs["G2"] = [repr(g2), repr(g2 * x)]
        return srs

    def commit(self, f: list[int]) -> G1:
        if not isinstance(f, list):
            f = list(f)
        assert len(f) <= self.srs["d"] + 1, "Polynomial degree exceeds SRS degree"
        return sum((f[i] * self.srs["G1"][i] for i in range(len(f))), start=G1.zero())

    def open(self, f: list[int], x: int) -> tuple[int, G1]:
        if not isinstance(f, Polynomial):
            f = Polynomial(list(f))
        assert f.degree <= self.srs["d"], "Polynomial degree exceeds SRS degree"
        x %= r
        y = f(x)
        g = Polynomial([-x, 1])
        q = (f - y) // g
        assert f - y == q * g, "Polynomial division mismatch"
        return y, self.commit(q)

    def verify(self, f_cm: G1, x: int, y: int, q_cm: G1) -> bool:
        x %= r
        g1, (g2, g2_x) = G1.one(), self.srs["G2"]
        lhs1 = f_cm - g1 * y
        lhs2 = g2
        rhs1 = q_cm
        rhs2 = g2_x - g2 * x
        return lhs1.pairing(lhs2) == rhs1.pairing(rhs2)


if __name__ == "__main__":
    kzg = KZG(10, save=False, new=True)
    f = [secrets.randbelow(r) for _ in range(11)]
    x = secrets.randbelow(r)
    f_cm = kzg.commit(f)
    y, q_cm = kzg.open(f, x)
    assert Polynomial(f)(x) == y, "Polynomial evaluation mismatch"
    assert kzg.verify(f_cm, x, y, q_cm), "Verification failed"
