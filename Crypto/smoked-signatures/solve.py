from hashlib import sha256
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey.ECC import _curves
from Crypto.Util.number import bytes_to_long, long_to_bytes

curve = _curves["P-256"]
n = int(curve.order)

# Collision:
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!&
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!1!

def H(m):
    h = 0
    for i, b in enumerate(m):
        h = (h + (b << (i % 8))) % 2**32
        h ^= h >> (i % 5)
    return h % n

io = process("./challenge/chall.py")
flag_enc = bytes.fromhex(io.recvline().decode().strip().split(": ")[1])
io.sendlineafter(b": ", b"m")
io.sendlineafter(b": ", b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!&")
s1 = int(io.recvline().decode().split("s = ")[1].strip())
io.sendlineafter(b": ", b"m")
io.sendlineafter(b": ", b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!1!")
s2 = int(io.recvline().decode().split("s = ")[1].strip())
io.close()

h1_1 = H(b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!&")
h1_2 = H(b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!1!")
h2_1 = bytes_to_long(sha256(b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!&").digest())
h2_2 = bytes_to_long(sha256(b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!1!").digest())
numerator = s1 - s2
denominator = (h1_1 * h2_1 - h1_2 * h2_2) % n
x = numerator * pow(denominator, -1, n) % n

key = sha256(long_to_bytes(x)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(flag_enc), AES.block_size)
print(flag.decode())
