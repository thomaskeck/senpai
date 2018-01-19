#! /usr/bin/env python3

from senpai import senpai
from senpai import commitment
import unittest


class TestCommunication(unittest.TestCase):

    def test_communication(self):
        alice = senpai.Alice()
        bob = senpai.Bob(alice.rsa.get_public_key())

        for answer_alice in [True, False]:
            for answer_bob in [True, False]:
                message = alice.encrypt_answer(answer_alice)
                cx, cy, c = message
                self.assertEqual(alice.rsa.decrypt(cx), alice.x)
                self.assertEqual(alice.rsa.decrypt(cy), alice.y)
                self.assertEqual(commitment.create(alice.x), c)

                message = bob.encrypt_answer(answer_bob, message)
                if answer_bob: 
                    self.assertEqual(alice.rsa.decrypt(message, use_padding=False), bob.r * (alice.y + alice.rsa.padding) % alice.rsa.N)
                else:
                    self.assertEqual(alice.rsa.decrypt(message, use_padding=False), bob.r * (alice.x + alice.rsa.padding) % alice.rsa.N)

                message = alice.decrypt_message(message)
                if answer_bob: 
                    self.assertEqual(message, bob.r * (alice.y + alice.rsa.padding) % alice.rsa.N)
                else:
                    self.assertEqual(message, bob.r * (alice.x + alice.rsa.padding) % alice.rsa.N)

                message = bob.decrypt_message(message)
                message = alice.check_final_answer(message)
                message = bob.check_final_answer(message)

                self.assertEqual(bob.final_answer, alice.final_answer)
                self.assertEqual(bob.final_answer, answer_alice & answer_bob)


if __name__ == '__main__':
    unittest.main()
