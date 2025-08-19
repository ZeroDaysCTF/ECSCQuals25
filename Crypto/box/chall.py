#! /usr/bin/env python3

import random
import hashlib
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

with open('flag.txt', 'rb') as f:
    flag = f.read()

r = 5
e = getPrime(512)
s = random.randrange(2, e - 1)
A = pow(r, s, e)

print("Flag Exchange Services!!!!!\n")
print(f'r: {r}', f'e: {e}', sep='\n')

pk = int(input("\nWhat is your flag recovery key?\n"))


if not 1 < pk < (e - 1):
    print('Ah ah ah, you didnt say the magic word')
    exit()
else:
    ss = pow(pk, s, e)
    key = hashlib.md5(long_to_bytes(ss)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.encrypt(pad(flag, 16))
    print(f'\nencrypted flag: {enc.hex()}')