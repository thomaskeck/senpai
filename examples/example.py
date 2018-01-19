from senpai import *

alice = Alice()
bob = Bob(alice.rsa.get_public_key())

for answer_alice in [True, False]:
    for answer_bob in [True, False]:
        message = alice.encrypt_answer(answer_alice)
        message = bob.encrypt_answer(answer_bob, message)
        message = alice.decrypt_message(message)
        message = bob.decrypt_message(message)
        message = alice.check_final_answer(message)
        message = bob.check_final_answer(message)
        if bob.final_answer != alice.final_answer:
            raise RuntimeError("Final answers don't match")
        print("Answers", answer_alice, answer_bob)
        print("Final Answer", bob.final_answer)
