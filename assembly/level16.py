#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               mov rax, [rsp+24]
               add rax, [rsp+16]
               add rax, [rsp+8]
               add rax, [rsp]
               mov rcx, 0x4
               div rcx
               push rax
               ''',arch='amd64')


# div mit Werten in rbx geht irgendwie nicht
# Warum geht "div 0x4 nicht? Weiss dann kompiler nicht breite des registers?"

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
#In the previous levels you used push and pop to store and load data from the stack
#however you can also access the stack directly using the stack pointer.
#The stack pointer is stored in the special register rsp.
#rsp always stores the memory address to the top of the stack,
#i.e. the memory address of the last value pushed.
#Similar to the memory levels we can use [rsp] to access the value at the memory address in rsp.
#
#Without using pop please calculate the average of 4 consecutive quad words stored on the stack.
#Push the average on the stack. Hint:
#RSP+0x?? Quad Word A
#RSP+0x?? Quad Word B
#RSP+0x?? Quad Word C
#RSP      Quad Word D
#
#We will now set the following in preparation for your code:
#(stack) [0x7fffff200000:0x7fffff1fffe0]
#= ['0x2959c7c9', '0x210bc9c3', '0x26040bae', '0x3214f1a5'] (list of things)
#
#Please give me your assembly in bytes (up to 0x1000 bytes): 
#
#WARNING: It looks like your input might not be assembled binary
#code, but actual assembly source. This challenge needs the
#raw binary assembled code as input.