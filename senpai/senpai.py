import numpy
import sympy
import hashlib


def mod_inverse(a, n):
    t = 0
    newt = 1
    r = n
    newr = a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt 
        r, newr = newr, r - quotient * newr
    if r > 1:
        raise RuntimeError("A is not invertible")
    if t < 0:
        t = t + n
    return t


def commitment(s):
    return int(hashlib.sha256(bytes(s)).hexdigest(), 16)


class Alice():
    def __init__(self):
        self.padding = numpy.random.randint(10000000, 99999999) * 1000
        #self.p = sympy.randprime(10000,100000)
        #self.q = sympy.randprime(10000,100000)
        self.p = sympy.randprime(100,1000)
        self.q = sympy.randprime(100,1000)
        self.N = self.p * self.q
        self.l = sympy.lcm(self.p-1, self.q-1)
        self.e = 1
        while self.l % self.e == 0:
            self.e = sympy.randprime(1, self.l)
        self.d = mod_inverse(self.e, self.l)

    def get_public_information(self):
        return {'public_key': self.e, 'rsa_modulus': self.N, 'padding': self.padding}
    
    def encrypt_answer(self, answer_alice):
        self.s = numpy.random.randint(10, 999) % self.N
        self.c = commitment(self.s)
        self.x = self.padding + self.s
        if answer_alice:
            self.y = self.padding + 1
        else:
            self.y = self.padding + self.s
        self.cx = self.x**self.e % self.N
        self.cy = self.y**self.e % self.N
        return (self.cx, self.cy, self.c)
    
    def decrypt_answer(self, message_from_bob):
        return message_from_bob**self.d % self.N
    
    def post_checks(self, message_from_bob):
        self.final_answer = message_from_bob
        return self.x

    
class Bob():
    def __init__(self, public_information):
        self.N = public_information['rsa_modulus']
        self.padding = public_information['padding']
        self.e = public_information['public_key']

    def encrypt_answer(self, answer_bob, message_from_alice):
        self.cx, self.cy, self.c = message_from_alice
        self.r = numpy.random.randint(10000000, 99999999) % self.N
        self.cr = self.r**self.e % self.N
        if answer_bob:
            self.cz = self.cy*self.cr % self.N
        else:
            self.cz = self.cx*self.cr % self.N
        return self.cz
    
    def decrypt_answer(self, message_from_alice):
        r = (message_from_alice * mod_inverse(self.r, self.N) - self.padding) % self.N
        self.final_answer = False
        if r == 1:
            self.final_answer = True
        else:
            if commitment(r) != self.c:
                raise RuntimeError("Commitment was violated")
        return self.final_answer
    
    def post_checks(self, message_from_alice):
        x = message_from_alice
        if commitment((x - self.padding) % self.N) != self.c:
            raise RuntimeError("Commitment was violated")
        if x**self.e % self.N != self.cx:
            raise RuntimeError("Keys don't match. Commitment was violated")
