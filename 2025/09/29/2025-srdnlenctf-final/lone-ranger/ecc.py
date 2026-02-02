# The following code is not intended to be vulnerable

import py_ecc.optimized_bn128 as ecc

__all__ = ["r", "G1", "G2"]

r = ecc.curve_order


class GenericPoint:
    def __init__(self, point: tuple):
        self.point = point

    def __call__(self, point: tuple, is_on_curve: bool = False):
        raise NotImplementedError("this method should be implemented in subclasses")

    def __add__(self, other):
        if not isinstance(other, GenericPoint):
            raise TypeError("can only add another GenericPoint")
        return self(ecc.add(self.point, other.point), is_on_curve=True)

    def __neg__(self):
        return self(ecc.neg(self.point), is_on_curve=True)

    def __sub__(self, other):
        if not isinstance(other, GenericPoint):
            raise TypeError("can only subtract another GenericPoint")
        return self(ecc.add(self.point, ecc.neg(other.point)), is_on_curve=True)

    def __mul__(self, scalar: int):
        return self(ecc.multiply(self.point, int(scalar)), is_on_curve=True)
    
    def __rmul__(self, scalar: int):
        return self(ecc.multiply(self.point, int(scalar)), is_on_curve=True)

    def __eq__(self, other):
        if isinstance(other, int) and other == 0:
            return ecc.is_inf(self.point)
        if not isinstance(other, GenericPoint):
            return False
        return ecc.eq(self.point, other.point)

    def __ne__(self, other):
        return not (self == other)


class G1(GenericPoint):
    def __init__(self, point: tuple, is_on_curve: bool = False):
        if not isinstance(point, (tuple, list)):
            raise TypeError("point must be a tuple or list")
        if len(point) == 2:
            x, y = point
            z = ecc.FQ.one()
        elif len(point) == 3:
            x, y, z = point
        elif len(point) != 3:
            raise ValueError("point must be a tuple of length 2 or 3")
        
        x = x if isinstance(x, ecc.FQ) else ecc.FQ(x)
        y = y if isinstance(y, ecc.FQ) else ecc.FQ(y)
        z = z if isinstance(z, ecc.FQ) else ecc.FQ(z)
        point = (x, y, z)
        if not (is_on_curve or ecc.is_on_curve(point, ecc.b)):
            raise ValueError("point is not on curve")
        super().__init__(point)

    def __call__(self, point: tuple, is_on_curve: bool = False):
        return G1(point, is_on_curve=is_on_curve)

    def __repr__(self):
        if ecc.is_inf(self.point):
            return "G1(infinity)"
        x, y = map(int, self.normalize())
        return f"G1({x=}, {y=})"
    
    def __str__(self):
        if ecc.is_inf(self.point):
            return "(infinity)"
        x, y = map(int, self.normalize())
        return f"({x}, {y})"
    
    @classmethod
    def from_repr(cls, s: str, can_be_zero: bool = False):
        if not isinstance(s, str):
            raise TypeError("input must be a string")
        s = s.strip()
        if can_be_zero and s == "G1(infinity)":
            return cls.zero()
        assert s.startswith("G1(") and s.endswith(")")
        x, y = s.strip("G1").strip("()").split(",")
        x = int(x.split("=").pop())
        y = int(y.split("=").pop())
        return cls((x, y))
    
    @classmethod
    def zero(cls):
        return cls(ecc.Z1)

    @classmethod
    def one(cls):
        return cls(ecc.G1)

    def pairing(self, other):
        if not isinstance(other, G2):
            raise TypeError("can only pair with a G2 point")
        return ecc.pairing(other.point, self.point)
    
    def normalize(self):
        if ecc.is_inf(self.point):
            raise ValueError("point at infinity cannot be normalized")
        x, y = ecc.normalize(self.point)
        self.point = (x, y, ecc.FQ.one())
        return (x, y)


class G2(GenericPoint):
    def __init__(self, point: tuple, is_on_curve: bool = False):
        if not isinstance(point, (tuple, list)):
            raise TypeError("point must be a tuple")
        if len(point) == 2:
            x, y = point
            z = ecc.FQ2.one()
        elif len(point) == 3:
            x, y, z = point
        elif len(point) != 3:
            raise ValueError("point must be a tuple of length 2 or 3")
        
        x = x if isinstance(x, ecc.FQ2) else ecc.FQ2(x)
        y = y if isinstance(y, ecc.FQ2) else ecc.FQ2(y)
        z = z if isinstance(z, ecc.FQ2) else ecc.FQ2(z)
        point = (x, y, z)
        if not (is_on_curve or ecc.is_on_curve(point, ecc.b2)):
            raise ValueError("point is not on curve")
        super().__init__(point)

    def __call__(self, point: tuple, is_on_curve: bool = False):
        return G2(point, is_on_curve=is_on_curve)

    def __repr__(self):
        if ecc.is_inf(self.point):
            return "G2(infinity)"
        x, y = self.normalize()
        x0, x1 = map(int, x.coeffs)
        y0, y1 = map(int, y.coeffs)
        return f"G2(x={x0} + {x1} * i, y={y0} + {y1} * i)"
    
    def __str__(self):
        if ecc.is_inf(self.point):
            return "(infinity)"
        x, y = self.normalize()
        x0, x1 = map(int, x.coeffs)
        y0, y1 = map(int, y.coeffs)
        return f"({x0} + {x1} * i, {y0} + {y1} * i)"
    
    @classmethod
    def from_repr(cls, s: str, can_be_zero: bool = False):
        if not isinstance(s, str):
            raise TypeError("input must be a string")
        s = s.strip()
        if can_be_zero and s == "G2(infinity)":
            return cls.zero()
        assert s.startswith("G2(") and s.endswith(")")
        x, y = s.strip("G2").strip("()").split(",")
        x0, x1 = x.split("=").pop().split(" + ")
        y0, y1 = y.split("=").pop().split(" + ")
        x0, x1 = int(x0), int(x1.split(" * i").pop(0))
        y0, y1 = int(y0), int(y1.split(" * i").pop(0))
        return cls(((x0, x1), (y0, y1)))
    
    @classmethod
    def zero(cls):
        return cls(ecc.Z2)
    
    @classmethod
    def one(cls):
        return cls(ecc.G2)
    
    def pairing(self, other):
        if not isinstance(other, G1):
            raise TypeError("can only pair with a G1 point")
        return ecc.pairing(self.point, other.point)

    def normalize(self):
        if ecc.is_inf(self.point):
            raise ValueError("point at infinity cannot be normalized")
        x, y = ecc.normalize(self.point)
        self.point = (x, y, ecc.FQ2.one())
        return (x, y)


if __name__ == "__main__":
    import secrets
    
    g1 = G1(ecc.G1)
    g2 = G2(ecc.G2)

    assert g1 == G1.one()
    assert g2 == G2.one()
    
    x, y = tuple(map(int, ecc.normalize(ecc.G1)))
    assert g1 == G1((x, y))
    (x0, x1), (y0, y1) = tuple(map(lambda c: c.coeffs, ecc.normalize(ecc.G2)))
    assert g2 == G2(((x0, x1), (y0, y1)))

    assert g1 == G1.from_repr(repr(g1))
    assert g2 == G2.from_repr(repr(g2))

    a = secrets.randbelow(r)
    b = secrets.randbelow(r)
    assert g1 * a + g1 * b == g1 * (a + b)
    assert g2 * a + g2 * b == g2 * (a + b)
    assert a * G1.zero() == G1.zero()
    assert b * G2.zero() == G2.zero()

    p1 = (g1 * a).pairing(g2 * b)
    p2 = (g1 * b).pairing(g2 * a)
    p3 = g1.pairing(g2)**(a * b)
    assert p1 == p2
    assert p1 == p3
