from pwn import remote, process
LOCAL = True
if LOCAL:
    io = process(["python", "hades.py"])
else:
    io = remote("IP", "PORT")

from Crypto.Cipher import AES

aes = AES.new(b"\x00"*32, AES.MODE_ECB)
for _ in range(50):
    io.sendline(b"3")
    io.sendline(b"00"*32)
    io.recvuntil(b"left soul screams: ")
    left = bytes.fromhex(io.recvline(False).decode())
    io.recvuntil(b"right soul screams: ")
    right = bytes.fromhex(io.recvline(False).decode())
    
    if aes.decrypt(aes.decrypt(left[:16])) == left[16:]:
        io.sendline(b"2")
    else:
        io.sendline(b"1")

print(io.recvall().decode())