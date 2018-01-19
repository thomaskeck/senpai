#! /usr/bin/env python3
# Implements the SENPAI protocoll
# http://sigtbd.csail.mit.edu/pubs/veryconference-paper10.pdf

import numpy

from senpai import rsa
from senpai import commitment


class Alice(object):
    """
    Alice wants to check if she agrees with Bob on a certain question,
    without leaking information about her own position in case Bob does not agree.
    """
    
    def __init__(self):
        """
        Creates a rsa keypair for alice
        """
        self.rsa = rsa.RSA.create_new_keypair()

    def encrypt_answer(self, answer):
        """
        Encrypts the answer using RSA
        @param answer either True or False
        """
        self.x = numpy.random.randint(2, 999)
        self.y = 1 if answer else self.x
        # Encrypt messages and commit to secret x
        self.cx = self.rsa.encrypt(self.x)
        self.cy = self.rsa.encrypt(self.y)
        self.c = commitment.create(self.x)
        print(self.cx, self.cy)
        return (self.cx, self.cy, self.c)
    
    def decrypt_message(self, message):
        """
        Decrypts the message received from bob
        @param message received from bob
        """
        # We do not remove the padding here, bob does this himself
        return self.rsa.decrypt(message, use_padding=False)
    
    def check_final_answer(self, final_answer):
        """
        We receive the final answer from bob. We return our initially used s, so bob an check that we sticked to the commited secret
        @param final_answer either true (if both parties agreed on true) or false otherwise
        """
        self.final_answer = final_answer
        return self.x

    
class Bob(object):
    """
    Bob wants to check if he agrees with Alice on a certain question,
    without leaking information about his own position in case Alice does not agree.
    """

    def __init__(self, public_key):
        """
        Creates a rsa object using the public key of Alice
        @param public_key of alice
        """
        self.rsa = rsa.RSA.create_from_keypair(public_key=public_key)

    def encrypt_answer(self, answer, message):
        """
        Encrypts the answer using RSA and append it to the message received from alice
        @param answer either True or False
        @param message from alice
        """
        self.cx, self.cy, self.c = message
        self.r = numpy.random.randint(10000000, 99999999)
        # We cannot use padding, otherwise we break the homomorphism
        self.cr = self.rsa.encrypt(self.r, use_padding=False)
        self.cz = self.cy*self.cr if answer else self.cx*self.cr
        return self.cz
    
    def decrypt_message(self, message):
        """
        Decrypts the message received from alice
        @param message received from alice
        """
        r = (message * rsa.mod_inverse(self.r, self.rsa.N) - self.rsa.padding) % self.rsa.N
        self.final_answer = False
        if r == 1:
            self.final_answer = True
        else:
            commitment.check(r, self.c)
        return self.final_answer
    
    def check_final_answer(self, message):
        """
        We receive the secret alice commited to earlier and check if she cheated
        @param message containing the secret she commited to earlier
        """
        commitment.check(message, self.c)
        if self.rsa.encrypt(message) != self.cx:
            raise RuntimeError("Keys don't match. Commitment was violated")

