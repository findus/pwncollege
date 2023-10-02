#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               push rdi
               push rsi
               pop rdi
               pop rsi
               ''',arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#We will now set some values in memory dynamically before each run. On each run
#the values will change. This means you will need to do some type of formulaic
#operation with registers_use. We will tell you which registers_use are set beforehand
#and where you should put the result. In most cases, its rax.
#
#In this level you will be working with the Stack, the memory region that dynamically expands
#and shrinks. You will be required to read and write to the Stack, which may require you to use
#the pop & push instructions. You may also need to utilize rsp to know where the stack is pointing.
#
#
#
#In this level we are going to explore the last in first out (LIFO) property of the stack.
#
#Using only following instructions:
#push, pop
#Swap values in rdi and rsi.
#i.e.
#If to start rdi = 2 and rsi = 5
#Then to end rdi = 5 and rsi = 2