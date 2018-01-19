#! /usr/bin/env python3

from senpai import commitment

import unittest


class TestCommitment(unittest.TestCase):

    def test_create(self):
        self.assertEqual(len(set(commitment.create(x) for x in range(100))), 100)

    def test_check(self):
        for x in range(2, 20):
            c = commitment.create(x)
            commitment.check(x, c)

        for x in range(2, 20):
            c = commitment.create(x)
            with self.assertRaises(RuntimeError):
                commitment.check(x, 21)
        
        for x in range(2, 20):
            c = commitment.create(x)
            with self.assertRaises(RuntimeError):
                commitment.check(21, c)


if __name__ == '__main__':
    unittest.main()
