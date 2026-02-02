#!/usr/bin/env python3
#
# BlackHat MEA 2025 Finals :: LCC LLC
#
# By Polymero
#

#------------------------------------------------------------------------------------------------------------------------------#
#   IMPORTS                                                                                                                    #
#------------------------------------------------------------------------------------------------------------------------------#
# Documentation imports
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union

# Native imports
from secrets import randbelow

# Sage imports (sage --python3)
from sage.all import GF, Matrix, vector

#------------------------------------------------------------------------------------------------------------------------------#
#   UTILITY FUNCTIONS                                                                                                          #
#------------------------------------------------------------------------------------------------------------------------------#
BitVec = NewType('BitVec', object)
Polynomial = NewType('Polynomial', object)

def Bytes2BitVec(x: bytes, k: int = None) -> BitVec:
    """ Converts byte-string into bit vector of length k. """
    if k is None:
        k = 8 * len(x)
    xInt = int.from_bytes(x, 'big')
    xBit = []
    for _ in range(k):
        xBit.append(xInt & 1)
        xInt >>= 1
    return Matrix(GF(2), xBit)

def BitVec2Bytes(x: BitVec) -> bytes:
    """ Converts bit vector into byte-string. """
    xInt = int(0)
    for i in x.list()[::-1]:
        xInt <<= 1
        xInt |= int(i)
    return xInt.to_bytes(-(-len(x.list()) // 8), 'big')

def DiagonalMatrix(entries: list) -> Matrix:
    """ Returns matrix with given entries on its diagonal. """
    R = entries[0].parent()
    n = len(entries)
    return Matrix(R, [[0]*i + [entries[i]] + [0]*(n - i - 1) for i in range(n)])

def IdentityMatrix(size: int) -> Matrix:
    """ Returns identity matrix of given size. """
    return Matrix([[0]*i + [1] + [0]*(size - i - 1) for i in range(size)])

def CheckSystematicForm(matrix: Matrix) -> Matrix:
    """ Return reduced echelon form of given matrix if it can be put in systematic form. """
    red = matrix.echelon_form()
    lhs = red[:,:red.nrows()]
    if lhs == IdentityMatrix(red.nrows()):
        return red
    else:
        return None

#------------------------------------------------------------------------------------------------------------------------------#
#   UTILITY CLASSES                                                                                                            #
#------------------------------------------------------------------------------------------------------------------------------#
class InverseFreeBerlekampMasseyDecoder:
    """
    Binary Goppa code decoding algorithm based on the inverse-free Berlekamp-Massey algorithm.
    """
    def __init__(self, g: Polynomial, L: list) -> None:
        assert 0 not in L
        self.L = L
        self.g = g
        self.pc = self._RunPreComputation()
        
    # Private methods
        
    def _RunPreComputation(self) -> dict:
        """ Pre-computes double-size parity check matrix to save time during decoding. """
        g2 = self.g ** 2
        return {
            'H2' : Matrix([[j ** i / g2(j) for j in self.L] for i in range(g2.degree())])
        }
    
    def _SyndromePolynomial(self, codeword: BitVec) -> Polynomial:
        """ Derives syndrome polynomial using pre-computed double-size parity check matrix. """
        return sum([j * self.g.parent().gen() ** i for i,j in enumerate((codeword * self.pc['H2'].T).list()[::-1])])
    
    # Public methods
    
    def ErrorLocatorPolynomial(self, codeword: BitVec) -> Polynomial:
        """ Derives ELP from syndrome polynomial using inverse-free Berlekamp-Massey algorithm. """
        syndrome = self._SyndromePolynomial(codeword)
        elp = self.g.parent()(1)
        sup = self.g.parent().gen()
        b, l = 1, 0
        for i in range(2 * self.g.degree()):
            d = sum([elp[j] * syndrome[i - j] for j in range(i + 1)])
            if (d == 0) or (2 * l > i):
                elp = b * elp - d * sup
                sup *= sup.parent().gen()
            else:
                tmp = elp
                elp = b * elp - d * sup
                l = i + 1 - l
                sup = sup.parent().gen() * tmp
                b = d
        return elp

class BinaryGoppaCode:
    """ 
    Class for constructing binary Goppa codes.
    m : field degree, i.e. F(q) = F(2 ** m)
    n : codeword bitlength, default n = 2 ** m
    t : error-correcting capability (in bits)
    k : plaintext blocksize (in bits)
    d : minimum (Hamming) distance of the code
    L : code locators, sequence of n distinct elements in F(q)
    g : Goppa polynomial, irreducible monic polynomial in F(q)[x] of degree t with g(L[i]) != 0
    """
    def __init__(self, g: Polynomial, L: list) -> None:
        # Code defining elements
        self.L = L
        self.g = g
        # Get code parameters
        assert self.L[0].parent().characteristic() == 2
        self.m = self.L[0].parent().degree()
        self.n = len(self.L)
        self.t = self.g.degree()
        self.k = self.n - self.m * self.t
        self.d = 2 * self.t + 1
        assert self.t > 1
        assert self.k > 0
        # Parity check and generator matrices
        print('  Deriving H...')
        Hrs = self._GenerateReedSolomonParityCheckMatrix()
        print('  Expanding H...')
        self.H = CheckSystematicForm(self._ChangeMatrixToBinaryField(Hrs))
        if not self.H:
            print('    Not systematic, retrying...')
            raise ValueError()
        print('  Deriving G...')
        self.G = self.H.right_kernel().basis_matrix()
        # Set decoder algorithm
        print('  Building decoder...')
        self.decoder = InverseFreeBerlekampMasseyDecoder(self.g, self.L)
        print('Done.')

    @classmethod
    def Generate(cls, m: int, t: int, n: int = None) -> object:
        """ Generates a binary Goppa code from given code parameters. """
        if n is None:
            n = 2 ** m
        assert (n > m * t) and (n <= 2 ** m)
        F = GF(2 ** m, 'x')
        R = F['y']
        print('Generating BinaryGoppaCode:')
        while True:
            try:
                print('  Generating (g,L)...')
                Lm = [F.gen() ** i for i in range(2 ** m - 1)]
                if n == 2 ** m:
                    Lm.append(F(0))
                Ln = []
                while len(Ln) < n:
                    Ln.append(Lm.pop(randbelow(len(Lm))))
                while True:
                    g = R.random_element(degree=int(t)).monic()
                    if g.is_irreducible() and all(g(i) != 0 for i in Ln):
                        break
                return cls(g, Ln)
            except ValueError:
                continue

    # Private methods
    
    def _GenerateReedSolomonParityCheckMatrix(self) -> object:
        """ Generates parity check matrix over F(2 ** m). """
        X = Matrix([[self.L[j] ** i for j in range(self.n)] for i in range(self.t)])
        Y = DiagonalMatrix([1 / self.g(self.L[i]) for i in range(self.n)])
        return X * Y

    def _ChangeMatrixToBinaryField(self, matrix: object) -> object:
        """ Converts matrix over F(2 ** m) to matrix over F(2). """
        B = Matrix(GF(2), self.m * matrix.nrows(), matrix.ncols())
        for i in range(matrix.nrows()):
            for j in range(matrix.ncols()):
                be = [int(k) for k in '{:0{m}b}'.format(matrix[i,j].to_integer(), m=self.m)]
                B[i*self.m:(i+1)*self.m,j] = vector(be)
        return B
    
    def _RandomMaxWeight(self) -> BitVec:
        """ Returns a random vector of max weight. """
        i = list(range(self.n))
        b = [0 for _ in range(self.n)]
        for _ in range(self.t):
            b[i.pop(randbelow(len(i)))] = 1
        return Matrix(GF(2), b)

    # Public methods

    def EncodeWord(self, word: BitVec) -> BitVec:
        """ Encodes a k-bit word into an n-bit codeword. """
        return word * self.G

    def DecodeCodeWord(self, codeword: BitVec) -> Tuple[BitVec]:
        """ Decodes an n-bit codeword into a k-bit word. """
        errorLocator = self.decoder.ErrorLocatorPolynomial(codeword)
        errorLocations = [int(errorLocator(self.L[i]) == 0) for i in range(self.n)]
        errorBitVec = Matrix(GF(2), errorLocations)
        return self.G.solve_left(codeword + errorBitVec), errorBitVec

#------------------------------------------------------------------------------------------------------------------------------#
#   CRYPTO CLASS                                                                                                               #
#------------------------------------------------------------------------------------------------------------------------------#
class McEliece(BinaryGoppaCode):
    """
    McEliece encryption system based on binary Goppa codes.
    """
    def __init__(self, g: Polynomial, L: list) -> None:
        super().__init__(g, L)
        self.S, self.P = self._GenerateBinaryMask()
        self.maskedG = self.S * self.G * self.P
        self.Sinv = self.S.inverse()
        self.Pinv = self.P.inverse()
        
    # Private methods
    
    def _GenerateBinaryMask(self) -> tuple:
        """ Generates binary scrambler and permutation matrix to hide matrix structure. """
        nrows, ncols = self.G.dimensions()
        Mkk = GF(2)**(nrows, nrows)
        while True:
            S = Mkk.random_element()
            if S.det():
                break
        i = list(range(ncols))
        p = []
        while i:
            p.append(i.pop(randbelow(len(i))))
        P = Matrix(GF(2), [[0]*i + [1] + [0]*(ncols - (i + 1)) for i in p])
        return S, P
    
    # Public methods
    
    def Encrypt(self, msg: bytes, eloc: List[int] = None) -> bytes:
        """ Encrypts a message. """
        assert 8 * len(msg) <= self.k
        mvec = Bytes2BitVec(msg, self.k)
        if eloc is None:
            evec = self._RandomMaxWeight()
        else:
            evec = Matrix(GF(2), [1 if i in eloc else 0 for i in range(self.n)])
        cvec = mvec * self.maskedG + evec
        return BitVec2Bytes(cvec)
    
    def Decrypt(self, cip: bytes) -> Tuple[bytes, set]:
        """ Decrypts a ciphertext. """
        assert len(cip) <= -(-self.n // 8)
        cvec = Bytes2BitVec(cip, self.n)
        mvec, evec = self.DecodeCodeWord(cvec * self.Pinv)
        eloc = set([i for i,j in enumerate((evec * self.P).list()) if j])
        return BitVec2Bytes(mvec * self.Sinv), eloc
    
    # def Update(self, msg: bytes, cip: bytes) -> bytes:
    #     """ Updates a ciphertext with a new message. """
    #     assert (8 * len(msg) <= self.k) and (len(cip) <= -(-self.n // 8))
    #     mvecNew = Bytes2BitVec(msg, self.k)
    #     cvecOld = Bytes2BitVec(cip, self.n)
    #     mvecOld = self.DecodeCodeWord(cvecOld * self.Pinv) * self.Sinv
    #     cvecNew = cvecOld + (mvecNew + mvecOld) * self.maskedG
    #     return BitVec2Bytes(cvecNew)
