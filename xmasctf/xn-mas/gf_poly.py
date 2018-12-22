# https://stackoverflow.com/a/48067397/1106415
# (C) user6655984, CC-BY-SA 3.0

import itertools
from functools import reduce
from sympy import symbols, Dummy
from sympy.polys.domains import ZZ
from sympy.polys.galoistools import (gf_irreducible_p, gf_add, \
                                     gf_sub, gf_mul, gf_rem, gf_gcdex)
from sympy.ntheory.primetest import isprime

class GF():
    def __init__(self, p, n=1):
        p, n = int(p), int(n)
        if not isprime(p):
            raise ValueError("p must be a prime number, not %s" % p)
        if n <= 0:
            raise ValueError("n must be a positive integer, not %s" % n)
        self.p = p
        self.n = n
        if n == 1:
            self.reducing = [1, 0]
        else:
            for c in itertools.product(range(p), repeat=n):
              poly = (1, *c)
              if gf_irreducible_p(poly, p, ZZ):
                  self.reducing = poly
                  break

    def add(self, x, y):
        return gf_add(x, y, self.p, ZZ)

    def sub(self, x, y):
        return gf_sub(x, y, self.p, ZZ)

    def mul(self, x, y):
        return gf_rem(gf_mul(x, y, self.p, ZZ), self.reducing, self.p, ZZ)

    def inv(self, x):
        s, t, h = gf_gcdex(x, self.reducing, self.p, ZZ)
        return s

    def eval_poly(self, poly, point):
        val = []
        for c in poly:
            val = self.mul(val, point)
            val = self.add(val, c)
        return val

class PolyRing():
    def __init__(self, field):
        self.K = field

    def add(self, p, q):
        s = [self.K.add(x, y) for x, y in \
             itertools.zip_longest(p[::-1], q[::-1], fillvalue=[])]
        return s[::-1]       

    def sub(self, p, q):
        s = [self.K.sub(x, y) for x, y in \
             itertools.zip_longest(p[::-1], q[::-1], fillvalue=[])]
        return s[::-1]     

    def mul(self, p, q):
        if len(p) < len(q):
            p, q = q, p
        s = [[]]
        for j, c in enumerate(q):
            s = self.add(s, [self.K.mul(b, c) for b in p] + \
                         [[]] * (len(q) - j - 1))
        return s

def interp_poly(X, Y, K):
    R = PolyRing(K)
    poly = [[]]
    for j, y in enumerate(Y):
        Xe = X[:j] + X[j+1:]
        numer = reduce(lambda p, q: R.mul(p, q), ([[1], K.sub([], x)] for x in Xe))
        denom = reduce(lambda x, y: K.mul(x, y), (K.sub(X[j], x) for x in Xe))
        poly = R.add(poly, R.mul(numer, [K.mul(y, K.inv(denom))]))
    return poly
