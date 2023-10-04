#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'
#context.endian = 'little'

ssh=ssh(host='pwn')
p=ssh.process('/challenge/run')

#rsi is size of list

code=   '''
               .intel_syntax noprefix
               push 0
               mov rbp, rsp
               sub rsp, rsi

               sub rsi, 1
               mov rax, -1

               loop1:
                add rax, 1
                cmp rax, rsi
                jg next
                
                mov rcx, 0 
                mov cl,[rdi+rax] ; untere 8 bit von rcx setzen
                
                mov r11, rbp ; base stack pointer in r11 schreiben
                sub r11, rcx ; stack pointer in position für bit bringen
                mov dl, [r11] ; inhalt von stack in dl schreiben
                add dl, 1 ; inhalt um 1 incrementen
                mov [r11], dl ; inhalt wieder zurück schreiben
                jmp loop1

               next:
                mov rax, 0
                mov rbx, rax
                mov rcx, rax
                mov ax, -1
               
                loop2:
                    add ax,1
                    cmp ax,0xff
                    jg return ; wenn b > 0xff return
                    
                    mov r11, rbp
                    sub r11, rax
                    mov dl,[r11]
                    cmp dl,bl ; check if wert aus stack grösser
                    jle loop2

                    mov bl,dl
                    mov cl,al 
                    jmp loop2
            
            return:
                mov rax, rcx
                mov rsp, rbp
                pop rbx
                ret
     
               '''
code=re.sub(';.*\\n','\\n',code)
shellcode= asm(code, arch='amd64')

print(disasm(shellcode, arch = 'amd64'))
#print(bytes(shellcode))
print('1', shellcode)
shellcode=bytes(shellcode)
#print('1', shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))

#You can even run all that together as one command:
#as -o asm.o asm.S && objcopy -O binary --only-section=.text ./asm.o ./asm.bin && cat ./asm.bin | /challenge/run
#
#We will be testing your code multiple times in this level with dynamic values! This means we will
#be running your code in a variety of random ways to verify that the logic is robust enough to
#survive normal use. You can consider this as normal dynamic value se
#
#In this level you will be working with functions! This will involve manipulating both ip control
#as well as doing harder tasks than normal. You may be asked to utilize the stack to save things
#and call other functions that we provide you.
#
#
#
#In the previous level, you learned how to make your first function and how to call other functions. Now
#we will work with functions that have a function stack frame. A function stack frame is a set of
#pointers and values pushed onto the stack to save things for later use and allocate space on the stack
#for function variables.
#First, let's talk about the special register rbp, the Stack Base Pointer. The rbp register is used to tell
#where our stack frame first started. As an example, say we want to construct some list (a contigous space
#of memory) that is only used in our function. The list is 5 elements long, each element is a dword.
#A list of 5 elements would already take 5 registers, so instead, we can make space on the stack! The
#assembly would look like:
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#; setup the base of the stack as the current top
#mov rbp, rsp
#; move the stack 0x14 bytes (5 * 4) down
#; acts as an allocation
#sub rsp, 0x14
#; assign list[2] = 1337
#mov eax, 1337
#mov [rbp-0x8], eax
#; do more operations on the list ...
#; restore the allocated space
#mov rsp, rbp
#ret
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Notice how rbp is always used to restore the stack to where it originally was. If we don't restore
#the stack after use, we will eventually run out TM. In addition, notice how we subtracted from rsp
#since the stack grows down. To make it have more space, we subtract the space we need. The ret
#and call still works the same. It is assumed that you will never pass a stack address across functions,
#since, as you can see from the above use, the stack can be overwritten by anyone at any time.
#Once, again, please make function(s) that implements the following:
#most_common_byte(src_addr, size):
#    i = 0
#    for i <= size-1:
#        curr_byte = [src_addr + i]
#        [stack_base - curr_byte] += 1
#
#    b = 0
#    max_freq = 0
#    max_freq_byte = 0
#    for b <= 0xff:
#        if [stack_base - b] > max_freq:
#            max_freq = [stack_base - b]
#            max_freq_byte = b
#        b += 1
#
#    return max_freq_byte
#
#Assumptions:
#- There will never be more than 0xffff of any byte
#- The size will never be longer than 0xffff
#- The list will have at least one element
#Constraints:
#- You must put the "counting list" on the stack
#- You must restore the stack like in a normal function
#- You cannot modify the data at src_addr