# A B C
# c = ??
# Our blocks: A' B' C'
# Want to control them as much as possible and also have hash(A' || B' || C') = c
# Enc_(Enc_A'(B')) (C')
# Full control over A' and B', no control over C'

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long

from pwn import remote, process

LOCAL = True  # Change to False for remote connection
if LOCAL:
    io = process(["python3", "proofing.py"])
else:
    io = remote("IP", "PORT")

g = 17
p = 0x4a4f081ae8f22f2fa161b31a5dedf95f7909ceaaf7415e213ccd3e060ca2573d6944b0fbb30d36c68d438942b906190c4cdb6f7df5032bff2bd2f204cd30a06548f62973e4c96824286cf26c7604e95283fa1b00d5b662261ef07f0b888931d915af973c73add4a523fc12bcfa394a8bdbd2ab32651690fb3f68b4a5a5494819
io.recvuntil(b"g^x = ")
challenge = int(io.recvline().strip())
print(f"Challenge: {challenge}")

m = f"{g},{challenge},1,"
m += ((-len(m) % 16) - 1) * "0" + ","
m = m.encode()

from random import randbytes
FOUND = False
while not FOUND:
    m_ = m + randbytes(8) + b"\xaa" * 8
    blocks = [m_[i:i + 16] for i in range(0, len(m_), 16)]
    current = blocks[0]
    cipher = AES.new(current, AES.MODE_ECB)
    for block in blocks[1:]:
        current = cipher.encrypt(block)
        cipher = AES.new(current, AES.MODE_ECB)
    target = b"\x00" * 16
    last_block = cipher.decrypt(target)
    # Need to account for the padding
    if last_block[-1] == 1:
        FOUND = True

commitment = m_.hex() + last_block[:-1].hex()

io.sendline(commitment.encode()) # Commitment hash
io.sendline(b"1") # t
io.sendline(b"0") # r
print(io.recvall().decode())