from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long
from random import randint

FLAG = open("flag.txt", "r").read().strip()

class Alice:
    def __init__(self):
        self.g = 17
        self.p = 0x4a4f081ae8f22f2fa161b31a5dedf95f7909ceaaf7415e213ccd3e060ca2573d6944b0fbb30d36c68d438942b906190c4cdb6f7df5032bff2bd2f204cd30a06548f62973e4c96824286cf26c7604e95283fa1b00d5b662261ef07f0b888931d915af973c73add4a523fc12bcfa394a8bdbd2ab32651690fb3f68b4a5a5494819
        self.x = randint(2, self.p)
        self.y = pow(self.g, self.x, self.p)

    def haesh(self, m):
        m = pad(m, 16)
        blocks = [m[i:i + 16] for i in range(0, len(m), 16)]
        current = blocks[0]
        cipher = AES.new(current, AES.MODE_ECB)
        for block in blocks[1:]:
            current = cipher.encrypt(block)
            cipher = AES.new(current, AES.MODE_ECB)
        return current

    def commit(self):
        v = randint(2, self.p)
        t = pow(self.g, v, self.p)

        m = f"{self.g},{self.y},{t}"
        c = bytes_to_long(self.haesh(m.encode()))

        r = (v - c * self.x) % (self.p - 1)
        assert t == pow(self.g, r, self.p) * pow(self.y, c, self.p) % self.p
        return (t, r)

    def verify(self, challenge, commitment, t, r):
        parts = commitment.split(b",")
        g, y, t_ = int(parts[0]), int(parts[1]), int(parts[2])
        
        if g != self.g or y != challenge or t_ != t:
            return False
        
        c = bytes_to_long(self.haesh(commitment))
        return t == pow(self.g, r, self.p) * pow(y, c, self.p) % self.p


if __name__ == "__main__":
    alice = Alice()
    print(f"Alice says: g = {alice.g}, p = {alice.p}, y = {alice.y}")
    t, r = alice.commit()
    print(f"Alice's committment: t = {t}, r = {r}")
    assert alice.verify(alice.y, f"{alice.g},{alice.y},{t}".encode(), t, r), "Uh oh! Alice didn't do something right!"

    x = randint(2, alice.p)
    challenge = pow(alice.g, x, alice.p)
    print(f"Your turn! Prove you know the x such that g^x = {challenge}")

    print("Commitment hash: ")
    h = bytes.fromhex(input())
    
    print("t: ")
    t = int(input())
    
    print("r: ")
    r = int(input())

    if alice.verify(challenge, h, t, r):
        print(FLAG)
    else:
        print("Verification failed!")
