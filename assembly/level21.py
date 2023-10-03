#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               xor rax, rax
               xor rcx, rcx
               cmp rdi,0x0
               je end
               loop:        
               mov rbx, [rdi+rcx]
               cmp rbx, 0x00
               je end
               add rcx, 0x1
               jmp loop
               nop
               end:
               mov rax, rcx               
               ''', arch='amd64')


##Additionally, if rdi = 0, then set rax = 0 (we will check)! <- F M L
 

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))


#In previous levels you discovered the for-loop to iterate for a *number* of times, both dynamically and
#statically known, but what happens when you want to iterate until you meet a condition? A second loop
#structure exists called the while-loop to fill this demand. In the while-loop you iterate until a
#condition is met. As an example, say we had a location in memory with adjacent numbers and we wanted
#to get the average of all the numbers until we find one bigger or equal to 0xff:
#average = 0
#i = 0
#while x[i] < 0xff:
#    average += x[i]
#    i += 1
#average /= i
#
#Using the above knowledge, please perform the following:
#Count the consecutive non-zero bytes in a contiguous region of memory, where:
#rdi = memory address of the 1st byte
#rax = number of consecutive non-zero bytes
#Additionally, if rdi = 0, then set rax = 0 (we will check)!
#An example test-case, let:
#rdi = 0x1000
#[0x1000] = 0x41
#[0x1001] = 0x42
#[0x1002] = 0x43
#[0x1003] = 0x00
#then: rax = 3 should be set
#
#We will now run multiple tests on your code, here is an example run:
#- (data) [0x404000] = {10 random bytes},
#- rdi = 0x404000