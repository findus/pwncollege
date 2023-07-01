#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh = ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               mov al, dil
               mov bx, si
               ''',arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall(), end='\\n' )
