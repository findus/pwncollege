#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
                mov rax, [0x404000]
                mov rdi, [0x404000]
                add rdi, 0x1337
                mov rbx, 0x404000
                mov [rbx], rdi
               ''',arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#Welcome to ASMLevel10
#==================================================
#...
#Up until now you have worked with registers as the only way for storing things, essentially
#variables like 'x' in math. Recall that memory can be addressed. Each address contains something
#at that location, like real addresses! As an example: the address '699 S Mill Ave, Tempe, AZ 85281'
#maps to the 'ASU Campus'. We would also say it points to 'ASU Campus'.  We can represent this like:
#['699 S Mill Ave, Tempe, AZ 85281'] = 'ASU Campus'
#The address is special because it is unique. But that also does not mean other address cant point to
#the same thing (as someone can have multiple houses). Memory is exactly the same! For instance,
#the address in memory that your code is stored (when we take it from you) is 0x400000.
#In x86 we can access the thing at a memory location, called dereferencing, like so:
#mov rax, [some_address]        <=>     Moves the thing at 'some_address' into rax
#This also works with things in registers:
#mov rax, [rdi]         <=>     Moves the thing stored at the address of what rdi holds to rax
#This works the same for writing:
#mov [rax], rdi         <=>     Moves rdi to the address of what rax holds.
#So if rax was 0xdeadbeef, then rdi would get stored at the address 0xdeadbeef:
#[0xdeadbeef] = rdi
#Note: memory is linear, and in x86_64, it goes from 0 - 0xffffffffffffffff (yes, huge).
#
#Please perform the following:
#1. Place the value stored at 0x404000 into rax
#2. Increment the value stored at the address 0x404000 by 0x1337
#Make sure the value in rax is the original value stored at 0x404000 and make sure
#that [0x404000] now has the incremented value.
#
#We will now set the following in preparation for your code:
#[0x404000] = 0xf5c2e
#
#Please give me your assembly in bytes (up to 0x1000 bytes): 
#Executing your code...
#---------------- CODE ----------------
#0x400000:    and       rdi, 0xe
#0x400004:    xor       rax, rdi
#0x400007:    and       rax, 1
#--------------------------------------
#Failed in the following way: rax was expected to be 0xf5c2e, but instead was 0x0
#Sorry, no flag :(.