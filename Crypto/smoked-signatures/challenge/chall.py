#!/usr/bin/env python3

import os
from random import randrange
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey.ECC import _curves, EccPoint
from Crypto.Util.number import bytes_to_long, long_to_bytes

FLAG = os.getenv("FLAG", "ZeroDays{fake_flag}").encode()

curve = _curves["P-256"]
p = curve.p
G = curve.G
n = int(curve.order)

x = randrange(1, n-1)
Y = x * G

magic_number = randrange(1, n-1)

def encrypt_flag():
    key = sha256(long_to_bytes(x)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    flag_enc = cipher.encrypt(pad(FLAG, AES.block_size))
    return flag_enc.hex()

def H(m):
    h = 0
    for i, b in enumerate(m):
        h = (h + (b << (i % 8))) % 2**32
        h ^= h >> (i % 5)
    return h % n

def sign(m):
    h1 = H(m)
    h2 = bytes_to_long(sha256(m).digest())
    k = magic_number * (h1 + 1000) % n
    R = k * G
    s = (k + h1 * h2 * x) % n
    return (R, s)

def verify(m, R, s, Y):
    h1 = H(m)
    h2 = bytes_to_long(sha256(m).digest())
    return s * G == R + h1 * h2 * Y

if __name__ == "__main__":
    print("Encrypted flag:", encrypt_flag())

    messages_signed = []
    while True:
        option = input("Sign a message (m) or verify a signature (v): ").strip().lower()
        if option == "m":
            message = input("Enter message to sign: ").encode()
            if len(message) < 30:
                print("Message too short, must be at least 30 characters.")
                continue
            if message in messages_signed:
                print("Message already signed.")
                continue
            messages_signed.append(message)
            R, s = sign(message)
            print(f"Signature: R = {R.xy}, s = {s}")
        elif option == "v":
            message = input("Enter message to verify: ").encode()
            x = int(input("Enter x coordinate of R: "))
            y = int(input("Enter y coordinate of R: "))
            s = int(input("Enter s: "))
            is_valid = verify(message, EccPoint(x, y, curve='P-256'), s, Y)
            if is_valid:
                print("Signature is valid.")
            else:
                print("Signature is invalid.")
        else:
            break
