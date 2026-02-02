# The following code is not intended to be vulnerable

from ecc import r
from collections.abc import Iterable
import secrets

__all__ = ["Fr", "Polynomial"]


class Fr:
    def __init__(self, value: int):
        if isinstance(value, Fr):
            self.value = value.value
        elif isinstance(value, int):
            self.value = value % r
        else:
            raise TypeError(f"expected int or Fr, got {type(value).__name__}")

    @classmethod
    def random_element(cls):
        return cls(secrets.randbelow(r))
    
    @classmethod
    def multiplicative_generator(cls):
        return cls(5)  # in the field of BN254, not necessarily the same for other fields

    def __add__(self, other):
        if isinstance(other, int):
            return Fr(self.value + other)
        if isinstance(other, Fr):
            return Fr(self.value + other.value)
        return NotImplemented

    def __radd__(self, other):
        return self.__add__(other)
    
    def __neg__(self):
        return Fr(-self.value)
    
    def __sub__(self, other):
        if isinstance(other, int):
            return Fr(self.value - other)
        if isinstance(other, Fr):
            return Fr(self.value - other.value)
        return NotImplemented
    
    def __rsub__(self, other):
        return self.__neg__().__add__(other)
    
    def __mul__(self, other):
        if isinstance(other, int):
            return Fr(self.value * other)
        if isinstance(other, Fr):
            return Fr(self.value * other.value)
        return NotImplemented
    
    def __rmul__(self, other):
        return self.__mul__(other)
    
    def __pow__(self, exponent: int):
        if not isinstance(exponent, int):
            raise TypeError(f"exponent must be an integer, not {type(exponent).__name__}")
        return Fr(pow(self.value, exponent, r))
    
    def __truediv__(self, other):
        if isinstance(other, int):
            return Fr(self.value * pow(other, -1, r))
        if isinstance(other, Fr):
            return Fr(self.value * pow(other.value, -1, r))
        raise TypeError(f"unsupported operand type(s) for /: 'Fr' and '{type(other).__name__}'")
    
    def __rtruediv__(self, other):
        if isinstance(other, int):
            return Fr(other * pow(self.value, -1, r))
        assert not isinstance(other, Fr), "this should never happen"
        raise TypeError(f"unsupported operand type(s) for /: '{type(other).__name__}' and 'Fr'")
    
    def __floordiv__(self, other):
        return self.__truediv__(other)
    
    def __rfloordiv__(self, other):
        return self.__rtruediv__(other)
    
    def __div__(self, other):
        return self.__truediv__(other)
    
    def __rdiv__(self, other):
        return self.__rtruediv__(other)
    
    def __mod__(self, other):
        if not isinstance(other, int):
            raise TypeError(f"modulus must be an integer, not {type(other).__name__}")
        if other != r:
            raise ValueError(f"reduction modulus {other} must be equal to the field characteristic {r}")
        return Fr(self.value % r)
    
    def __eq__(self, other):
        if isinstance(other, int):
            return self.value == other % r
        if isinstance(other, Fr):
            return self.value == other.value
        return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __repr__(self):
        return f"Fr({self.value})"
    
    def __str__(self):
        return str(self.value)

    def __int__(self):
        return self.value

    def __bool__(self):
        return self.value != 0
    
    def __hash__(self):
        return hash(self.value)


class Polynomial(Iterable):
    def __init__(self, coeffs: list[int]):
        if not isinstance(coeffs, (list, tuple)):
            raise TypeError("coeffs must be a list or tuple")
        if not all(isinstance(c, (int, Fr)) for c in coeffs):
            raise TypeError("coeffs must be a list of integers or Fr elements")
        self.coeffs = [Fr(c) if isinstance(c, int) else c for c in coeffs]
        while self.coeffs and self.coeffs[-1] == 0:
            self.coeffs.pop()
    
    @classmethod
    def random_element(cls, degree: int):
        if degree < 0:
            raise ValueError("degree must be non-negative")
        coeffs = [Fr.random_element() for _ in range(degree)]
        while not (coeff := Fr.random_element()):
            pass
        coeffs.append(coeff)
        return cls(coeffs)
    
    @property
    def degree(self):
        while self.coeffs and self.coeffs[-1] == 0:
            self.coeffs.pop()
        return len(self.coeffs) - 1

    def __call__(self, x):
        if not isinstance(x, (int, Fr)):
            raise TypeError("x must be an integer or Fr element")
        result = Fr(0)
        for c in reversed(self.coeffs):
            result = result * x + c
        return result
    
    def __add__(self, other):
        if isinstance(other, Polynomial):
            coeffs = []
            for a, b in zip(self.coeffs, other.coeffs):
                coeffs.append(a + b)
            if len(self.coeffs) > len(other.coeffs):
                coeffs.extend(self.coeffs[len(other.coeffs):])
            elif len(other.coeffs) > len(self.coeffs):
                coeffs.extend(other.coeffs[len(self.coeffs):])
            return Polynomial(coeffs)
        if isinstance(other, (int, Fr)):
            return Polynomial([self.coeffs[0] + other] + self.coeffs[1:])
        raise TypeError(f"unsupported operand type(s) for +: 'Polynomial' and '{type(other).__name__}'")
    
    def __radd__(self, other):
        return self.__add__(other)
    
    def __neg__(self):
        return Polynomial([-c for c in self.coeffs])
    
    def __sub__(self, other):
        return self.__add__(-other)
    
    def __rsub__(self, other):
        return (-self).__add__(other)

    def __mul__(self, other):
        if isinstance(other, Polynomial):
            coeffs = [Fr(0)] * (self.degree + other.degree + 1)
            for i, a in enumerate(self.coeffs):
                if a == 0:
                    continue
                for j, b in enumerate(other.coeffs):
                    if b == 0:
                        continue
                    coeffs[i + j] += a * b
            return Polynomial(coeffs)
        if isinstance(other, (int, Fr)):
            return Polynomial([c * other for c in self.coeffs])
        raise TypeError(f"unsupported operand type(s) for *: 'Polynomial' and '{type(other).__name__}'")
    
    def __rmul__(self, other):
        return self.__mul__(other)
    
    def __truediv__(self, other):
        if isinstance(other, Polynomial):
            if not other.coeffs:
                raise ZeroDivisionError("division by zero polynomial")
            if self.degree < other.degree:
                return Polynomial([0]), Polynomial(self.coeffs)
            if self.degree == other.degree:
                coeff = self.coeffs[0] // other.coeffs[0]
                return Polynomial([coeff]), Polynomial([0])
            quotient_coeffs = []
            remainder = self
            while remainder != 0 and remainder.degree >= other.degree:
                coeff = remainder.coeffs[-1] // other.coeffs[-1]
                quotient_coeffs.append(coeff)
                remainder -= Polynomial([Fr(0)] * (remainder.degree - other.degree) + (coeff * other).coeffs)
            quotient_coeffs.reverse()
            return Polynomial(quotient_coeffs), remainder
        if isinstance(other, (int, Fr)):
            return Polynomial([c // other for c in self.coeffs]), Polynomial([0])
        raise TypeError(f"unsupported operand type(s) for //: 'Polynomial' and '{type(other).__name__}'")
    
    def __floordiv__(self, other):
        quotient, _ = self.__truediv__(other)
        return quotient
    
    def __mod__(self, other):
        _, remainder = self.__truediv__(other)
        return remainder
    
    def __eq__(self, other):
        if isinstance(other, Polynomial):
            return self.degree == other.degree and self.coeffs == other.coeffs
        if isinstance(other, (int, Fr)):
            if self.degree > 0:
                return False
            if not self.coeffs:
                return other == 0
            return self.coeffs[0] == other
        return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __repr__(self):
        if not self.coeffs:
            return "Polynomial(0)"
        if self.degree == 0:
            return "Polynomial(" + str(self.coeffs[0]) + ")"
        terms = []
        for i, coeff in enumerate(self.coeffs):
            if coeff != 0:
                terms.append(str(coeff) + ("" if i == 0 else "*x" if i == 1 else f"*x^{i}"))
        return "Polynomial(" + " + ".join(terms) + ")"
    
    def __str__(self):
        if not self.coeffs:
            return "0"
        if self.degree == 0:
            return str(self.coeffs[0])
        terms = []
        for i, coeff in enumerate(self.coeffs):
            if coeff != 0:
                terms.append(str(coeff) + ("" if i == 0 else "*x" if i == 1 else f"*x^{i}"))
        return " + ".join(terms)
    
    def __int__(self):
        if self.degree > 0:
            raise ValueError("cannot convert polynomial of degree > 0 to int")
        if not self.coeffs:
            return 0
        return int(self.coeffs[0])
    
    def __bool__(self):
        return any(c != 0 for c in self.coeffs)
    
    def __iter__(self):
        if not self.coeffs:
            return iter([Fr(0)])
        return iter(self.coeffs)
    
    def __hash__(self):
        return hash(tuple(self.coeffs))
    
    @classmethod
    def ntt(cls, omega: int, points: list):
        """ DFT as of Cooley-Tukey algorithm """
        n = len(points)
        assert n > 0 and n & (n - 1) == 0, "length of points must be a power of 2"
        omega = Fr(omega)
        H = [omega**i for i in range(n)]
        assert len(set(H)) == n and 1 in H, "omega must be a n-th root of unity"
        points = [Fr(point) if isinstance(point, int) else point for point in points]


        def bit_reverse(x: int, n: int) -> int:
            """ Reverse the bits of x, assuming it is represented with n bits """
            y = 0
            for _ in range(n):
                y = (y << 1) | (x & 1)
                x >>= 1
            return y


        for i in range(n):
            j = bit_reverse(i, n.bit_length() - 1)
            if j <= i:
                continue
            points[i], points[j] = points[j], points[i]
        
        m = 1
        for _ in range(n.bit_length() - 1):
            w_m = H[(n // (2 * m)) % n]
            for k in range(0, n, 2 * m):
                w = Fr(1)
                for j in range(m):
                    t = w * points[k + j + m]
                    points[k + j + m] = points[k + j] - t
                    points[k + j] += t
                    w *= w_m
            m *= 2
        return points

    @classmethod
    def intt(cls, omega: int, points: list):
        """ INV-DFT as of Cooley-Tukey algorithm """
        n = len(points)
        assert n > 0 and n & (n - 1) == 0, "length of points must be a power of 2"
        omega = Fr(omega)
        points = cls.ntt(omega, points)
        n_inv = Fr(n)**-1
        return [n_inv * points[0]] + [n_inv * point for point in reversed(points[1:])]

    def to_ntt(self, n: int = None):
        if n is None:
            n = 1 << (self.degree + 1).bit_length()
        elif not isinstance(n, int) or n < 1 or n & (n - 1) != 0:
            raise ValueError("n must be a positive power of 2")
        if n < self.degree + 1:
            raise ValueError("n must be at least degree + 1")
        omega = Fr.multiplicative_generator()**((r - 1) // n)
        points = [self.coeffs[i] if i < len(self.coeffs) else Fr(0) for i in range(n)]
        return self.ntt(omega, points)
    
    @classmethod
    def from_ntt(cls, points: list):
        n = len(points)
        if n < 1 and n & (n - 1) == 0:
            raise ValueError("points must be a power of 2")
        omega = Fr.multiplicative_generator()**((r - 1) // n)
        return cls(cls.intt(omega, points))


if __name__ == "__main__":
    to_list = lambda x: list(map(int, list(x)))

    from sage.all import GF, PolynomialRing

    F = GF(r)
    R = PolynomialRing(F, 'x')

    f1 = R.random_element(5)
    g1 = R.random_element(3)

    f2 = Polynomial(to_list(f1))
    g2 = Polynomial(to_list(g1))

    h1 = f1 + g1
    h2 = f2 + g2
    assert to_list(h1) == to_list(h2)

    h1 = f1 - g1
    h2 = f2 - g2
    assert to_list(h1) == to_list(h2)

    h1 = f1 * g1
    h2 = f2 * g2
    assert to_list(h1) == to_list(h2)

    h1 = f1 // g1
    h2 = f2 // g2
    assert to_list(h1) == to_list(h2)

    h1 = f1 % g1
    h2 = f2 % g2
    assert to_list(h1) == to_list(h2)
