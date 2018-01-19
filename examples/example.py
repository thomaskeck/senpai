from senpai import *

alice = Alice()
bob = Bob(alice.get_public_information())

for answer_alice in [True, False]:
    for answer_bob in [True, False]:
        bob.post_checks(alice.post_checks(bob.decrypt_answer(alice.decrypt_answer(bob.encrypt_answer(answer_bob, alice.encrypt_answer(answer_alice))))))
        if bob.final_answer != alice.final_answer:
            raise RuntimeError("Final answers don't match")
        print("Answers", answer_alice, answer_bob)
        print("Final Answer", bob.final_answer)
