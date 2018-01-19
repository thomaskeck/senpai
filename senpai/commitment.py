#! /usr/bin/env python3
# Simple Commitment implementation
# Allows to commit to a certain value without disclosing the value at first.
# The commitment is send to a third-party, and later we can proof that we used the corresponding input.
# https://en.wikipedia.org/wiki/Commitment_scheme
# Not suitable for real cryptographic purposes

import hashlib


def create(s):
    """
    Hash function used to implement the commitment.
    We use sha256 here, this is save as far as I know
    @param s the input to which we want to commit using for a specific purpose
    """
    return int(hashlib.sha256(bytes(str(s), 'utf8')).hexdigest(), 16)

def check(s, c):
    """
    Check if the commitment is actuall fulfilled.
    @param s the input to which the third-party claimed to be commited to
    @param c the commitment send by a third-party
    """
    if create(s) != c:
        raise RuntimeError("Commitment was violated")

