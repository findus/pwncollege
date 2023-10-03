#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix        
                mov rbx, rsi
                mov rcx, 0x0
                mov rdx, 0x0
                loopstart:
                sub rbx,1
                mov ecx,[rdi+rbx*8]
                add rax, rcx
                cmp rbx, 0
                jne loopstart
                div rsi
               ''', arch='amd64')


# JE/JZ, ZF set if AND == 0
# and rax,0xfffffffffffffffc <- check if greater 2

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#In this level you will be working with control flow manipulation. This involves using instructions
#to both indirectly and directly control the special register `rip`, the instruction pointer.
#You will use instructions like: jmp, call, cmp, and the like to implement requests behavior.
#
#
#
#In  a previous level you computed the average of 4 integer quad words, which
#was a fixed amount of things to compute, but how do you work with sizes you get when
#the program is running? In most programming languages a structure exists called the
#for-loop, which allows you to do a set of instructions for a bounded amount of times.
#The bounded amount can be either known before or during the programs run, during meaning
#the value is given to you dynamically. As an example, a for-loop can be used to compute
#the sum of the numbers 1 to n:
#sum = 0
#i = 1
#for i <= n:
#    sum += i
#    i += 1
#
#Please compute the average of n consecutive quad words, where:
#rdi = memory address of the 1st quad word
#rsi = n (amount to loop for)
#rax = average computed
#
#We will now set the following in preparation for your code:
#- [0x404220:0x4043b0] = {n qwords]}
#- rdi = 0x404220
#- rsi = 50