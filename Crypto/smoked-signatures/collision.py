import itertools

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

def H(m):
    h = 0
    for i, b in enumerate(m):
        h = (h + (b << (i % 8))) % 2**32
        h ^= h >> (i % 5)
    return h % n

hash_map = {}

for length in range(30, 40):
    for msg in itertools.product(range(33, 128), repeat=length):
        b = bytes(msg)
        h = H(b)
        if h in hash_map:
            print("Collision found!")
            print("Message 1:", hash_map[h])
            print("Message 2:", b)
            print("Hash:", h)
            exit(0)
        else:
            hash_map[h] = b
