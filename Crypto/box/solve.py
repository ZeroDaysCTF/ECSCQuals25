#!/usr/bin/env python3

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Util.number import long_to_bytes
import primefac
import hashlib
import random

def main():
    conn = remote('localhost', 2500)

    # Read until we get the parameters r and e
    conn.recvuntil(b'r: ')
    r = int(conn.recvline().strip())
    conn.recvuntil(b'e: ')
    e = int(conn.recvline().strip())

    log.info(f"Received r: {r}")
    log.info(f"Received e: {e}")

    # Factorize e-1 to find subgroups
    factors = primefac.primefac(e - 1)
    seen_factors = set()

    for factor in factors:
        if factor in seen_factors:
            continue
        seen_factors.add(factor)
        log.info(f'Testing subgroup size {factor}, if this is too big, please restart.')

        for _ in range(1000):
            candidate = random.randrange(2, e - 1)
            candidate = pow(candidate, (e - 1) // factor, e)
            if candidate != (e - 1) and candidate != 1:
                log.info(f'Found candidate subgroup generator: {candidate}')

                # Generate all elements of the subgroup
                possible_shared = set()
                ctr = 1
                while len(possible_shared) != factor:
                    possible_shared.add(pow(candidate, ctr, e))
                    ctr += 1
                log.info(f'Candidate subgroup size: {len(possible_shared)}')

                # This candidate is our public key B to send
                B = candidate
                conn.recvuntil(b'flag recovery key?\n')
                conn.sendline(str(B).encode())

                # Receive encrypted flag line
                line = conn.recvline_contains(b'encrypted flag:')
                enc_hex = line.strip().split(b': ')[1].decode()
                log.info(f'Received encrypted flag: {enc_hex}')

                # Try to decrypt with all possible shared secrets
                for shared in possible_shared:
                    key = hashlib.md5(long_to_bytes(shared)).digest()
                    cipher = AES.new(key, AES.MODE_ECB)
                    try:
                        decrypted = unpad(cipher.decrypt(bytes.fromhex(enc_hex)), 16)
                        if b'ZeroDays{' in decrypted:
                            log.success(f'Flag: {decrypted.decode()}')
                            return
                    except:
                        pass

                log.warning('Failed to decrypt flag with this subgroup.')
                return

    conn.close()

if __name__ == '__main__':
    main()
