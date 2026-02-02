import dataclasses
import functools

import secrets
import numpy as np
import galois


__all__ = ["Ring", "RingElem"]


@dataclasses.dataclass(frozen=True)
class Ring:
    q: int
    n: int
    s: int

    @functools.cached_property
    def Zq(self):
        return galois.GF(
            self.q, 
            verify=False, 
            compile="python-calculate"  # slower operations, but has less compile overhead
        )

    def __post_init__(self):
        if not galois.is_prime(self.q):
            raise ValueError(f"q must be prime, got {self.q}")
        if self.n & (self.n - 1) != 0 or self.n < 2:
            raise ValueError(f"n must be a power of two, got {self.n}")
        if (self.q - 1) % (2 * self.n) != 0:
            raise ValueError(f"q - 1 must be divisible by 2*n")
        if self.s < 1:
            raise ValueError(f"s must be positive, got {self.s}")
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Ring):
            return False
        return self.q == other.q and self.n == other.n and self.s == other.s
    
    def __ne__(self, other) -> bool:
        return not (self == other)
    
    def __call__(self, value) -> "RingElem":
        if isinstance(value, RingElem):
            if value.ring != self:
                raise ValueError("cannot coerce RingElem from different ring")
            return RingElem(self, coeffs=value.coeffs, evals=value.evals)
        if isinstance(value, int):
            return RingElem(self, evals=self.Zq(np.array([value % self.q] * self.n)))
        raise TypeError(f"conversion from {type(value).__name__} to RingElem not supported")
    
    def __repr__(self) -> str:
        return f"Ring(q={self.q}, n={self.n}, s={self.s})"
    
    def __str__(self) -> str:
        return repr(self)
    
    def binomial(self, f: callable = None) -> "RingElem":
        if f is None:
            f = lambda: secrets.randbits(self.s).bit_count() - secrets.randbits(self.s).bit_count()
        return RingElem(self, coeffs=self.Zq(np.array([f() % self.q for _ in range(self.n)])))
    
    def uniform(self) -> "RingElem":
        elem = self.binomial()
        return RingElem(self, evals=elem.coeffs)

    @functools.lru_cache(maxsize=None)
    def zero(self) -> "RingElem":
        return RingElem(self, evals=self.Zq(np.zeros(self.n)))
    
    @functools.lru_cache(maxsize=None)
    def one(self) -> "RingElem":
        return RingElem(self, evals=self.Zq(np.ones(self.n)))
    
    @functools.lru_cache(maxsize=None)
    def gen(self) -> "RingElem":
        return RingElem(self, coeffs=self.Zq(np.array([0] + [1] + [0] * (self.n - 2))))
    
    @functools.lru_cache(maxsize=None)
    def primitive_root(self) -> int:
        omega = self.Zq.primitive_root_of_unity(2 * self.n)
        return min(omega**i for i in range(1, 2 * self.n, 2))

    @functools.lru_cache(maxsize=None)
    def roots(self) -> np.ndarray:
        zeta = self.primitive_root()
        bitrev = lambda x: int(f"{x:0{self.n.bit_length() - 1}b}"[::-1], 2)
        return self.Zq(np.array([zeta**bitrev(i) for i in range(self.n)]))

    def ntt(self, w: np.ndarray) -> np.ndarray:
        assert len(w) == self.n, f"expected w of length {self.n}, got {len(w)}"
        w = self.Zq(w)
        zetas = self.roots()
        m, ell = 0, self.n // 2
        while ell > 0:
            for start in range(0, self.n, 2 * ell):
                z = zetas[m := m + 1]
                t = z * w[start + ell:start + 2 * ell]
                w[start + ell:start + 2 * ell] = w[start:start + ell] - t
                w[start:start + ell] = w[start:start + ell] + t
            ell >>= 1
        return w

    def intt(self, w: np.ndarray) -> np.ndarray:
        assert len(w) == self.n, f"expected w of length {self.n}, got {len(w)}"
        w = self.Zq(w)
        zetas = self.roots()
        m, ell = self.n, 1
        while ell < self.n:
            for start in range(0, self.n, 2 * ell):
                z = -zetas[m := m - 1]
                t = w[start:start + ell].copy()
                w[start:start + ell] = t + w[start + ell:start + 2 * ell]
                w[start + ell:start + 2 * ell] = z * (t - w[start + ell:start + 2 * ell])
            ell <<= 1
        return w / self.Zq(self.n)


class RingElem:
    def __init__(self, ring: Ring, coeffs: np.ndarray = None, *, evals: np.ndarray = None) -> None:
        if coeffs is None and evals is None:
            raise ValueError("must specify either coeffs or evals")
        self.ring = ring
        self.coeffs = self.ring.Zq(coeffs) if coeffs is not None else None
        self.evals = self.ring.Zq(evals) if evals is not None else ring.ntt(coeffs)

    def __add__(self, other) -> "RingElem":
        if not isinstance(other, RingElem):
            return self + self.ring(other)
        if self.ring != other.ring:
            raise ValueError("cannot add RingElem from different rings")
        if self.coeffs is None or other.coeffs is None:
            return RingElem(self.ring, evals=self.evals + other.evals)
        return RingElem(self.ring, coeffs=self.coeffs + other.coeffs, evals=self.evals + other.evals)

    def __radd__(self, other) -> "RingElem":
        return self + other
    
    def __sub__(self, other) -> "RingElem":
        if not isinstance(other, RingElem):
            return self - self.ring(other)
        if self.ring != other.ring:
            raise ValueError("cannot subtract RingElem from different rings")
        if self.coeffs is None or other.coeffs is None:
            return RingElem(self.ring, evals=self.evals - other.evals)
        return RingElem(self.ring, coeffs=self.coeffs - other.coeffs, evals=self.evals - other.evals)

    def __rsub__(self, other) -> "RingElem":
        return self.ring(other) - self
    
    def __mul__(self, other) -> "RingElem":
        if not isinstance(other, RingElem):
            return self * self.ring(other)
        if self.ring != other.ring:
            raise ValueError("cannot multiply RingElem from different rings")
        return RingElem(self.ring, evals=self.evals * other.evals)
    
    def __rmul__(self, other) -> "RingElem":
        return self * other
    
    def __neg__(self) -> "RingElem":
        return RingElem(self.ring, evals=-self.evals)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, RingElem):
            return np.array_equal(self.evals, self.ring(other).evals)
        return self.ring == other.ring and np.array_equal(self.evals, other.evals)
    
    def __ne__(self, other) -> bool:
        return not (self == other)
    
    def poly(self) -> galois.Poly:
        if self.coeffs is None:
            self.coeffs = self.ring.intt(self.evals)
        return galois.Poly(self.coeffs, field=self.ring.Zq, order="asc")
    
    def centered_coeffs(self) -> np.ndarray:
        if self.coeffs is None:
            self.coeffs = self.ring.intt(self.evals)
        coeffs = np.array(self.coeffs, dtype=int)
        return coeffs - self.ring.q * (coeffs > self.ring.q // 2)
    
    def __repr__(self) -> str:
        return f"RingElem(ring={self.ring}, elem={self.poly()})"
    
    def __str__(self) -> str:
        return str(self.poly())


if __name__ == "__main__":
    import time

    q = 8380417  # Dilithium prime
    n = 256
    s = 2
    R = Ring(q=q, n=n, s=s)

    # test the ring element addition, subtraction, multiplication
    g1, g2 = R.uniform(), R.uniform()
    p1, p2 = g1.poly(), g2.poly()
    mod = galois.Poly(  # x^n + 1  ->  x^n = -1
        [1] + [0] * (R.n - 1) + [1], 
        field=R.Zq, 
        order="asc"
    )
    assert p1 + p2 == (g1 + g2).poly()
    assert p1 - p2 == (g1 - g2).poly()
    # this is the slowest operation since it involves the modulus, ntt makes it so much faster
    tick = time.time()
    p3 = p1 * p2 % mod
    tock = time.time()
    print(f"poly mod mul time {tock - tick}")
    tick = time.time()
    g3 = g1 * g2  # this performs only the element-wise eval multiplication
    g3_poly = g3.poly()  # this performs the intt to recover the coefficients
    tock = time.time()
    print(f"elem ntt mul time {tock - tick}")
    assert p3 == g3_poly
