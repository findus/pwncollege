#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix
               jmp next
               .rep 0x51
                nop
               .endr
               next:
               pop rdi
               push 0x403000
               ret
               ''', vma=0x40080, arch='amd64')

#   _start:
#   jmp next
#   .rep 0x51
#       nop
#   .endr
#    next:
#   mov rdi,[rsp]
#   mov r12,0x403000
#   jmp r12

# ich musste vma benutzen
# https://github.com/Gallopsled/pwntools/issues/1287




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
#Earlier, you learned how to manipulate data in a pseudo-control way, but x86 gives us actual
#instructions to manipulate control flow directly. There are two major ways to manipulate control
#flow: 1. through a jump; 2. through a call. In this level, you will work with jumps. There are
#two types of jumps:
#1. Unconditional jumps
#2. Conditional jumps
#Unconditional jumps always trigger and are not based on the results of earlier instructions.
#As you know, memory locations can store data and instructions. You code will be stored
#at 0x400076 (this will change each run).
#For all jumps, there are three types:
#1. Relative jumps
#2. Absolute jumps
#3. Indirect jumps
#In this level we will ask you to do both a relative jump and an absolute jump. You will do a relative
#jump first, then an absolute one. You will need to fill space in your code with something to make this
#relative jump possible. We suggest using the `nop` instruction. It's 1 byte and very predictable.
#
#In fact, the as assembler that we're using has a handy .rept directive that you can use to repeat assembly instructions some number of times:
#https://ftp.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_7.html
#
#Useful instructions for this level is:
#jmp (reg1 | addr | offset) ; nop
#Hint: for the relative jump, lookup how to use `labels` in x86.
#
#Using the above knowledge, perform the following:
#Create a two jump trampoline:
#1. Make the first instruction in your code a jmp
#2. Make that jmp a relative jump to 0x51 bytes from its current position
#3. At 0x51 write the following code:
#4. Place the top value on the stack into register rdi
#5. jmp to the absolute address 0x403000
#
#We will now set the following in preparation for your code:
#- Loading your given code at: 0x400076
#- (stack) [0x7fffff1ffff8] = 0x46