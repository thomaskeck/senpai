#! /usr/bin/env python3

from senpai import rsa

import random
import unittest
import sympy


class TestModInverse(unittest.TestCase):

    def test_mod_inverse(self):
        for a in range(2, 20):
            for n in range(2, 20):
                if sympy.gcd(a, n) != 1:
                    with self.assertRaises(RuntimeError):
                        inverse = rsa.mod_inverse(a, n)
                else:
                    inverse = rsa.mod_inverse(a, n)
                    self.assertEqual(inverse * a % n, 1)


class TestRSA(unittest.TestCase):

    def setUp(self):
        self.x = rsa.RSA.create_new_keypair(seed=1)

    def test_create_new_keypair(self):
        self.assertTrue(sympy.isprime(self.x.q))
        self.assertTrue(sympy.isprime(self.x.p))
        self.assertEqual(self.x.q*self.x.p, self.x.N)
        self.assertTrue(1 < self.x.e < self.x.l)
        self.assertEqual(sympy.gcd(self.x.e, self.x.l), 1)
        self.assertEqual(self.x.e * self.x.d % self.x.l, 1)

    def test_init(self):
        x = rsa.RSA()
        self.assertIsNone(x.e)
        self.assertIsNone(x.d)
        self.assertIsNone(x.N)
        self.assertIsNone(x.padding)

    def test_get_public_key(self):
        public_key = self.x.get_public_key()
        self.assertIn('public_key', public_key)
        self.assertIn('rsa_modulus', public_key)
        self.assertIn('padding', public_key)
    
    def test_get_private_key(self):
        private_key = self.x.get_public_key()
        self.assertIn('private_key', public_key)
        self.assertIn('rsa_modulus', private_key)
        self.assertIn('padding', private_key)

    def test_create_from_keypair(self):
        public_key = self.x.get_public_key()
        private_key = self.x.get_private_key()
        x = rsa.RSA.create_from_keypair(public_key=public_key, private_key=private_key)
        self.assertDictEqual(x.get_public_key(), public_key)
        self.assertDictEqual(x.get_private_key(), private_key)
        
        with self.assertRaises(RuntimeError):
            public_key['rsa_modulus'] = 5
            x = rsa.RSA.create_from_keypair(public_key=public_key, private_key=private_key)
        
        with self.assertRaises(RuntimeError):
            public_key['rsa_modulus'] = private_key['rsa_modulus']
            public_key['padding'] = 5
            x = rsa.RSA.create_from_keypair(public_key=public_key, private_key=private_key)

    def test_encrypt(self):
        for n in range(1000):
            self.assertNotEqual(self.x.encrypt(n), n)
        
        # Without padding, 0 and 1 are actually not encrypted
        self.assertEqual(self.x.encrypt(0, use_padding=False), 0)
        self.assertEqual(self.x.encrypt(1, use_padding=False), 1)
        for n in range(2, 1000):
            self.assertNotEqual(self.x.encrypt(n, use_padding=False), n)

        self.x.e = None
        with self.assertRaises(RuntimeError):
            self.x.encrypt(10)
    
    def test_decrypt(self):
        for n in range(1000):
            self.assertNotEqual(self.x.decrypt(n), n)
        
        # Without padding, 0 and 1 are actually not encrypted
        self.assertEqual(self.x.decrypt(0, use_padding=False), 0)
        self.assertEqual(self.x.decrypt(1, use_padding=False), 1)
        for n in range(2, 1000):
            self.assertNotEqual(self.x.decrypt(n, use_padding=False), n)
        
        self.x.d = None
        with self.assertRaises(RuntimeError):
            self.x.decrypt(10)

    def test_encrypt_and_decrypt(self):
        for n in range(1000):
            self.assertEqual(self.x.decrypt(self.x.encrypt(n)), n)

    def test_homomorphic(self):
        for x in range(10):
            for y in range(10):
                self.assertEqual(self.x.decrypt(self.x.encrypt(x, use_padding=False)*self.x.encrypt(y, use_padding=False), use_padding=False), x*y % self.x.N)
        

    def test_get_public_key(self):
        self.assertDictEqual(self.x.get_public_key(), {'public_key': self.x.e, 'rsa_modulus': self.x.N, 'padding': self.x.padding})
    
    def test_get_private_key(self):
        self.assertDictEqual(self.x.get_private_key(), {'private_key': self.x.d, 'rsa_modulus': self.x.N, 'padding': self.x.padding})

if __name__ == '__main__':
    unittest.main()
