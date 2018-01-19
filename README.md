# senpai
This project provides a simple implementation of the SENPAI algorithm.
Based on this paper
http://sigtbd.csail.mit.edu/pubs/veryconference-paper10.pdf

I used this project to learn more about RSA, cryptography and the mathematical tools behind it.
WARNING: Do not use this code in production, I am not a cryptographer and the implementation is not secure.

## Possible design flaw in the protocoll

The paper states 
> x consists of 0 (with some suitable padding scheme applied), and y consists of Alice’s response (0 if her response is No, 1 if her response is Yes).
> ...
> before generating x and y, Alice chooses a random bitstring s, long enough that it can’t be reasonably guessed.
> Then, x consists of 0 and s (with some padding scheme), and if y is 0, then y likewise consists of 0 and s.''
Both x and y are encrypted and send to Bob. However, Bob can trivially extract the answer of Alice at this point,
because if x == y (meaning Alice choose No), the encrypted messages will be equal as well.

