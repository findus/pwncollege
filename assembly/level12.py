#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               mov rax, 0xdeadbeef00001337
               mov rbx, 0xc0ffee0000
               mov [rdi], rax
               mov [rsi], rbx
               ''',arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#MSB                                    LSB
#+----------------------------------------+
#|                   rax                  |
#+--------------------+-------------------+
#                     |        eax        |
#                     +---------+---------+
#                               |   ax    |
#                               +----+----+
#                               | ah | al |
#                               +----+----+


#It is worth noting, as you may have noticed, that values are stored in reverse order of how we
#represent them. As an example, say:
#[0x1330] = 0x00000000deadc0de
#If you examined how it actually looked in memory, you would see:
#[0x1330] = 0xde 0xc0 0xad 0xde 0x00 0x00 0x00 0x00
#This format of storing things in 'reverse' is intentional in x86, and its called Little Endian.
#
#For this challenge we will give you two addresses created dynamically each run. The first address
#will be placed in rdi. The second will be placed in rsi.
#Using the earlier mentioned info, perform the following:
#1. set [rdi] = 0xdeadbeef00001337
#2. set [rsi] = 0xc0ffee0000
#Hint: it may require some tricks to assign a big constant to a dereferenced register. Try setting
#a register to the constant then assigning that register to the derefed register.