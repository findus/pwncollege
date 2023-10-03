#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

shellcode= asm('''
               .intel_syntax noprefix        
                mov rax,rdi
                and rax,0xfffffffffffffffc
                je normal
                nop
                jmp [rsi+32]
                nop
                normal:
                jmp [rsi+rdi*8]
                nop
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

#The last set of jump types is the indirect jump, which is often used for switch statements in the
#real world. Switch statements are a special case of if-statements that use only numbers to
#determine where the control flow will go. Here is an example:
#switch(number):
#    0: jmp do_thing_0
#    1: jmp do_thing_1
#    2: jmp do_thing_2
#    default: jmp do_default_thing
#The switch in this example is working on `number`, which can either be 0, 1, or 2. In the case that
#`number` is not one of those numbers, default triggers. You can consider this a reduced else-if
#type structure.
#In x86, you are already used to using numbers, so it should be no suprise that you can make if
#statements based on something being an exact number. In addition, if you know the range of the numbers,
#a switch statement works very well. Take for instance the existence of a jump table. A jump table
#is a contiguous section of memory that holds addresses of places to jump. In the above example, the
#jump table could look like:
#[0x1337] = address of do_thing_0
#[0x1337+0x8] = address of do_thing_1
#[0x1337+0x10] = address of do_thing_2
#[0x1337+0x18] = address of do_default_thing
#Using the jump table, we can greatly reduce the amount of cmps we use. Now all we need to check
#is if `number` is greater than 2. If it is, always do:
#jmp [0x1337+0x18]
#Otherwise:
#jmp [jump_table_address + number * 8]
#Using the above knowledge, implement the following logic:
#if rdi is 0:
#    jmp 0x403006
#else if rdi is 1:
#    jmp 0x403119
#else if rdi is 2:
#    jmp 0x4031f3
#else if rdi is 3:
#    jmp 0x4032a7
#else:
#    jmp 0x403373
#Please do the above with the following constraints:
#- assume rdi will NOT be negative
#- use no more than 1 cmp instruction
#- use no more than 3 jumps (of any variant)
#- we will provide you with the number to 'switch' on in rdi.
#- we will provide you with a jump table base address in rsi.

#Here is an example table:
#    [0x4041b9] = 0x403006 (addrs will change)
#    [0x4041c1] = 0x403119
#    [0x4041c9] = 0x4031f3
#    [0x4041d1] = 0x4032a7
#    [0x4041d9] = 0x403373