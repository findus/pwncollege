#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               mov rax, [rdi]
               mov rbx, [rdi+8]
               add rbx, rax
               add [rsi], rbx
               ''',arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#Recall that memory is stored linearly. What does that mean? Say we access the quad word at 0x1337:
#[0x1337] = 0x00000000deadbeef
#The real way memory is layed out is byte by byte, little endian:
#[0x1337] = 0xef
#[0x1337 + 1] = 0xbe
#[0x1337 + 2] = 0xad
#...
#[0x1337 + 7] = 0x00
#What does this do for us? Well, it means that we can access things next to each other using offsets,
#like what was shown above. Say you want the 5th *byte* from an address, you can access it like:
#mov al, [address+4]
#Remember, offsets start at 0.
#
#Perform the following:
#1. load two consecutive quad words from the address stored in rdi
#2. calculate the sum of the previous steps quad words.
#3. store the sum at the address in rsi
#
#We will now set the following in preparation for your code:
#[0x404228] = 0xe3335
#[0x404230] = 0xde6ca
#rdi = 0x404228
#rsi = 0x404718
#
#Please give me your assembly in bytes (up to 0x1000 bytes): 