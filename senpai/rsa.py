#! /usr/bin/env python3
# Simple RSA implementation
# Not suitable for real cryptographic purposes

import numpy
import sympy
import random


def mod_inverse(a, n):
    """
    Calculates the modular multiplicative inverse using the extended euclidean algorithm
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Simple_algebraic_field_extensions
    Determines t such that it fulfills
    a * t = 1 mod n 
    @param a integer to be inverted
    @param n modulus
    """
    t = 0
    newt = 1
    r = n
    newr = a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt 
        r, newr = newr, r - quotient * newr
    if r > 1:
        raise RuntimeError("a is not invertible")
    if t < 0:
        t = t + n
    return t


class RSA(object):
    """
    Simple implementation of RSA
    Not suitable for real crypotographic purposes for many reasons
    - the primes I choose are way too small
    - the padding is badly broken, I should implement https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding instead
    - probably not time constant
    - probably the RNG is not secure
    """
    def __init__(self):
        """
        Create an empty RSA object
        """
        self.e = None
        self.d = None
        self.N = None
        self.padding = None

    @classmethod
    def create_new_keypair(cls, seed=None):
        """ 
        Create new RSA public/private key pair
        @param seed the seed for the random number generation
        """
        self = cls()
        if seed is not None:
            random.seed(seed)
        # Choose random primes p, q
        self.p = int(sympy.randprime(100,1000))
        self.q = int(sympy.randprime(100,1000))
        # RSA modulus
        self.N = self.p * self.q
        # Create a padding, just a number we add to the clear-text, probably not secure at all
        self.padding = numpy.random.randint(10000000, 99999999)
        # Find least common denominator
        self.l = int(sympy.lcm(self.p-1, self.q-1))
        # Find coprime e, which is our public key
        self.e = 1
        while self.l % self.e == 0:
            self.e = int(sympy.randprime(1, self.l))
        # Find d, which is our private key
        self.d = mod_inverse(self.e, self.l)
        return self
       
    @classmethod
    def create_from_keypair(cls, public_key=None, private_key=None):
        """
        Creates fills RSA object from existing given keys.
        @param public_key required for encryption
        @param private_key required for decryption
        """
        self = cls()
        if public_key is not None and private_key is not None:
            if public_key['rsa_modulus'] != private_key['rsa_modulus']:
                raise RuntimeError('RSA Modulus of public and private key do not match!')
            if public_key['padding'] != private_key['padding']:
                raise RuntimeError('Padding of public and private key do not match!')

        if public_key is not None: 
            self.e = public_key['public_key']
            self.N = public_key['rsa_modulus']
            self.padding = public_key['padding']

        if private_key is not None: 
            self.d = private_key['private_key']
            self.N = private_key['rsa_modulus']
            self.padding = private_key['padding']

        return self

    def get_public_key(self):
        """
        Returns public key
        """
        return {'public_key': self.e, 'rsa_modulus': self.N, 'padding': self.padding}
    
    def get_private_key(self):
        """
        Returns private key
        """
        return {'private_key': self.d, 'rsa_modulus': self.N, 'padding': self.padding}

    def encrypt(self, x, use_padding=True):
        """
        Encrypts a given number using the public key
        @param x the number to encrypt
        @param use_padding if true
        """
        if self.e is None:
            raise RuntimeError('Cannot encrypt due to missing public key.')
        return pow((self.padding if use_padding else 0) + x, self.e, self.N)

    def decrypt(self, x, use_padding=True):
        """
        Decrypts a given number using the private key
        @param x the number to decrypt
        @param use_padding if true
        """
        if self.d is None:
            raise RuntimeError('Cannot decrypt due to missing private key.')
        return (pow(x, self.d, self.N) - (self.padding if use_padding else 0)) % self.N
