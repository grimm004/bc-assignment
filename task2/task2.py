from hashlib import sha256
import itertools

target = bytes.fromhex("987dcca6ea151951c963ce256e3a035b044ee0c597836759e30ca11d08bf74ed")

words = [
    "blockchain", "Blockchain", "BLOCKCHAIN",
    "and", "And", "AND",
    "cryptocurrency", "Cryptocurrency", "CRYPTOCURRENCY",
    "cryptocurrencies", "Cryptocurrencies", "CRYPTOCURRENCIES",
    "crypto", "Crypto", "CRYPTO",
    "COMP4137", "comp4137", "4137", "comp",
    "module", "Module", "MODULE"
]

words_encoded = [word.encode("utf-8") for word in words]

for i in range(1, 6):
    for permutation in itertools.permutations(words_encoded, i):
        guess = b" ".join(permutation)
        if sha256(guess).digest() == target:
            print(repr(guess.decode("utf-8")))

        guess = b"".join(permutation)
        if sha256(guess).digest() == target:
            print(repr(guess.decode("utf-8")))
