#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               pop rax
               sub rax, rdi
               push rax
               ''',arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#In these levels we are going to introduce the stack.
#The stack is a region of memory, that can store values for later.
#To store a value a on the stack we use the push instruction, and to retrieve a value we use pop.
#The stack is a last in first out (LIFO) memory structure this means
#the last value pushed in the first value popped.
#Imagine unloading plates from the dishwasher let's say there are 1 red, 1 green, and 1 blue.
#First we place the red one in the cabinet, then the green on top of the red, then the blue.
#Out stack of plates would look like:
#Top ----> Blue
#          Green
#Bottom -> Red
#Now if we wanted a plate to make a sandwich we would retrieve the top plate from the stack
#which would be the blue one that was last into the cabinet, ergo the first one out.
#
#Replace the top value of the stack with (top value of the stack - rdi).
#
#We will now set the following in preparation for your code:
#rdi = 0x103cc
#(stack) [0x7fffff1ffff8] = 0x398fc142